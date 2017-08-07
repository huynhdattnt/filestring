'''
Created on dec 12 2016

@author: dat.huynh
'''
from fscore.helper import redis_store
import logging
from datetime import datetime
from fscore.helper import notification_utils
from fscore.service import get_database_manager, file_retrieval
import requests
from fscore.app import app, is_timeout_event
from appconfig import constants
from fscore.helper import geotools
import ujson
from fscore.helper.smtp import send_email_to_recipient_on_file_shared
from fscore.helper.datetime_utils import to_iso8601
from itertools import groupby
from operator import itemgetter


def _get_activities_by_file(self, sharer_id, file_id, from_time, to_time, is_owner, connection):
        '''
        Get all activities of user
        :param pdf_file:
            - sharer_id: identity of a person sharing a file
            - file_id: identity of file
        :return:
            list of activities of user
        '''
        query = '''
            SELECT
                u.email as email,
                u.first_name as first_name,
                u.last_name as last_name,
                u.user_id as uid,
                al_fm.action,
                al_fm.client_city,
                al_fm.client_country,
                al_fm.client_platform,
                al_fm.created_time,
                al_fm.started_time,
                al_fm.timespan,
                al_fm.platform,
                al_fm.city,
                al_fm.country
            FROM
                (SELECT
                    al_l.action as action,
                    al_l.city as client_city,
                    al_l.country as client_country,
                    al_l.client_platform as client_platform,
                    al_l.created_time as created_time,
                    fm.user_id as user_id,
                    fm.started_time as started_time,
                    fm.timespan as timespan,
                    fm.platform as platform,
                    fm.city as city,
                    fm.country as country
                FROM
                    (
                        SELECT
                            al.file_id as file_id,
                            al.actor_uid as actor_uid,
                            al.action as action,
                            loc.city as city,
                            loc.country as country,
                            al.client_platform as client_platform,
                            al.created_time as created_time
                        FROM
                            %(additional_sharer_from_clause)s
                        WHERE
                            al.action in ('download', 'Print')
                            AND al.file_id = %(file_id)s
                            %(additional_sharer_where_clause)s
                    ) al_l
                    RIGHT JOIN
                    (
                        SELECT
                            COALESCE (lead(f.started_time) over (order by f.started_time), NOW()) as next_created_time,
                            f.file_id as file_id,
                            f.started_time,
                            f.user_id,
                            f.completed_time,
                            f.timespan,
                            d.platform as platform,
                            loc.city as city,
                            loc.country as country
                        FROM file_metrics f
                            INNER JOIN device_metrics d ON d.tracking_id = f.tracking_id
                            LEFT JOIN locations loc ON loc.location_id = f.location_id
                        WHERE f.file_id = %(file_id)s
                        %(additional_time_clause)s
                        ORDER BY f.started_time ASC) fm
                    ON
                        al_l.created_time >= fm.started_time
                        AND al_l.created_time < fm.next_created_time
                        AND al_l.file_id = fm.file_id
                ORDER BY al_l.created_time ASC) al_fm,
            users u
            WHERE u.user_id = al_fm.user_id
            '''
        if not from_time:
            query = query.replace('%(additional_time_clause)s', '')
            if is_owner == 1:
                query = query.replace('%(additional_sharer_from_clause)s',
                                      ' activity_logs al LEFT JOIN locations loc ON loc.location_id = al.location_id ')
                query = query.replace('%(additional_sharer_where_clause)s', '')
            else:
                query = query.replace('%(additional_sharer_from_clause)s',
                                      ' activity_logs al LEFT JOIN locations loc ON loc.location_id = al.location_id, shared_files fs ')
                query = query.replace('%(additional_sharer_where_clause)s',
                                      ' AND al.actor_uid = fs.receiver_uid AND al.file_id = fs.file_id AND fs.sender_uid = %(uid)s ')

            rs = connection.fetch_all(
                query,
                {
                    'file_id': file_id,
                    'uid': sharer_id,
                }
            )
        else:
            query = query.replace('%(additional_time_clause)s', ' AND f.started_time BETWEEN %(from_time)s AND %(to_time)s ')
            if is_owner == 1:
                query = query.replace('%(additional_sharer_from_clause)s',
                                      ' activity_logs al LEFT JOIN locations loc ON loc.location_id = al.location_id ')
                query = query.replace('%(additional_sharer_where_clause)s', '')
            else:
                query = query.replace('%(additional_sharer_from_clause)s',
                                      ' activity_logs al LEFT JOIN locations loc ON loc.location_id = al.location_id, shared_files fs ')
                query = query.replace('%(additional_sharer_where_clause)s',
                                      ' AND al.actor_uid = fs.receiver_uid AND al.file_id = fs.file_id AND fs.sender_uid = %(uid)s ')

            rs = connection.fetch_all(
                query,
                {
                    'file_id'   : file_id,
                    'from_time' : from_time,
                    'to_time'   : to_time,
                    'uid': sharer_id,
                }
            )
        activity_makeup = []
        # Mapping column before make result data
        numbermap = {'email': 1, 'first_name': 2, 'last_name': 3, 'uid': 4, 'action': 5, 'client_city': 6, 'client_country': 7,
                     'client_platform': 8, 'created_time': 9, 'started_time': 10, 'timespan': 11, 'platform': 12,
                     'city': 13, 'country': 14
                     }
        # Make up result to [(value1 of session 1, value2 of session 1 ...), (value1 of session 2, value of session 2) ....]
        for item in rs:
            item_cv = [tuple(item[i] for i in sorted(item, key=numbermap.__getitem__))]
            activity_makeup = activity_makeup + item_cv

        activity_makeup = sorted(activity_makeup, key=lambda activity: activity[4])

        activities = []
        for infos, data in groupby(activity_makeup, key=itemgetter(0, 1, 2, 3)):
            activities_belong_user = [d for d in data]
            logger.info('activities_belong_user is: {}'.format(activities_belong_user))
            for open, session_data in groupby(activities_belong_user, key=itemgetter(9, 12, 13, 10, 11)):
                activity = {}
                # Get infos of receiver about: first name, last name, email, uid
                activity['recipient'] = {}
                activity['recipient']['email'] = infos[0]
                activity['recipient']['first_name'] = infos[1]
                activity['recipient']['last_name'] = infos[2]
                activity['recipient']['uid'] = infos[3]
                # Get infos about time, location, duration when a session has been opened.
                activity['open'] = {}
                activity['open']['started_time'] = to_iso8601(open[0])
                activity['open']['location'] = open[1] + ', ' + open[2] if open[1] and open[2] else ''
                activity['open']['duration'] = open[3]
                activity['open']['device_name'] = open[4]
                # Group action print and download that belongs to this session.
                _print = []
                _download = []
                for s in session_data:
                    act = {}
                    act['started_time'] = to_iso8601(s[8])
                    act['location'] = s[5] + ', ' + s[6] if s[5] else ''
                    act['device_name'] = s[7]

                    if s[4] == 'Print':
                        _print.append(act)
                    else:
                        _download.append(act)
                activity['print'] = _print
                activity['download'] = _download
                activities.append(activity)
        res = {}
        res['body'] = {}
        res['body']['activities'] = activities
        return res, 1
