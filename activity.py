'''
Created on Apr 22, 2014

@author: dinh.pham
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


logger = logging.getLogger("fscore.app")


NOTIFICATION_MESSAGES = {
    constants.ACTION_CHANGE_NAME: "You just changed your name or your accounts",
    constants.ACTION_USER_JOIN_TEAM: "%s has joined your team",
    constants.ACTION_CHANGE_SERVICE_PREFERENCE: "You just updated your application settings",
    constants.ACTION_EMAIL_VERIFIED: "Your email has been verified"
}


def create_message_by_action(action, from_uid, to_uid, object_id, object_type):
    """Creates notification message based on the nature of action
    """
    if action == constants.ACTION_CHANGE_NAME:
        pass


class LocationRegistry(object):

    def __init__(self, dbm=None):
        if dbm:
            self.dbm = dbm
        else:
            self.dbm = get_database_manager(0)

    def register(self, ipv4_address, lat, lon, connection=None):
        '''
        @return GeoLocation.location_id
        '''
        import time
        try:
            self_managed = False  # connection is not managed by this method. Connection will not be closed here
            if connection is None:
                self_managed = True  # connection is managed by this method
                connection = self.dbm.connection()
            if self_managed:
                with connection as conn:
                    if lon and lat:
                        t1 = time.time()
                        city_or_province, country = geotools.get_address_by_coordinates(lat, lon)
                        logger.info('Get address by coordinates elapsed time %s', time.time() - t1)
                    else:
                        if ipv4_address == '127.0.0.1':
                            # Get my public ip
                            ipv4_address = str(requests.get('http://wtfismyip.com/text').text.strip())
                            # city_or_province, country = 'Ho Chi Minh city', 'Vietnam'
                        # else:
                        t1 = time.time()
                        city_or_province, country = geotools.get_geo_info_by_ip(ipv4_address)
                        logger.info('Get address by ip elapsed time %s', time.time() - t1)
                    if city_or_province is None:
                        city_or_province, country = 'Unknown', 'Unknown'
                    return conn.insert(
                        'locations',
                        {
                            'country': country,  # user who generates the action
                            'country_code': None,
                            'state': None,
                            'city': city_or_province,
                            'ip': ipv4_address,
                            'longitude': lat,
                            'latitude': lon,
                            'time_zone': None
                        },
                        return_id='location_id',
                        autocommit=False
                    )

            if lon and lat:
                t1 = time.time()
                city_or_province, country = geotools.get_address_by_coordinates(lat, lon)
                logger.info('Get address by coordinates elapsed time %s', time.time() - t1)
            else:
                if ipv4_address == '127.0.0.1':
                    # Get my public ip
                    ipv4_address = str(requests.get('http://wtfismyip.com/text').text.strip())
                    # city_or_province, country = 'Ho Chi Minh city', 'Vietnam'
                # else:
                t1 = time.time()
                city_or_province, country = geotools.get_geo_info_by_ip(ipv4_address)
                logger.info('Get address by ip elapsed time %s', time.time() - t1)
            if city_or_province is None:
                city_or_province, country = 'Ho Chi Minh city', 'Vietnam'
            return connection.insert(
                'locations',
                {
                    'country': country,  # user who generates the action
                    'country_code': None,
                    'state': None,
                    'city': city_or_province,
                    'ip': ipv4_address,
                    'longitude': lat,
                    'latitude': lon,
                    'time_zone': None
                },
                return_id='location_id',
                autocommit=False
            )
        except BaseException as e:
            logger.exception(
                'Exception %s when register location ip: %s, loc: (%s, %s)',
                e, ipv4_address, lat, lon
            )
            return None


class ActivityTracker(object):

    def __init__(self, dbm=None):
        if dbm:
            self.dbm = dbm
        else:
            self.dbm = get_database_manager(0)

    def track_file_action(self, uid, action_name, client_info, file_id, target_uid, connection=None):
        '''
        If uid == target_uid -> self file revocation
        '''
        pass

    def track_user_action(self, uid, action_name, object_id, object_type, target_uid,
                          location_id, platform_name, indirect_target_id=None,
                          version=None, connection=None, created_time=None):
        '''Keeps track of non-sharing actions that user performs.
        Stored in activity_logs

        UID -> Action --> Object--> Target

        @param uid: User ID of the person who perform the action
        @param action_name: See constants.ACTION_*
        @param object_id: Can be file_id or None for actions like change name ...
        @param object_type: Can be 'profile' or 'file' (action is performed against an object of a specific type)
        @param target_uid: Who is affected (those who will be notified about the action)
        @param indirect_target_id: Deleted account
        @param client_info: A dict (location_id, os_name)
        @return a tuple (dict(activity_id), status)
        '''
        if not version:
            logger.warn('Need add version when call track_user_action')
        try:
            self_managed = False  # connection is not managed by this method. Connection will not be closed here
            if connection is None:
                self_managed = True  # connection is managed by this method
                connection = self.dbm.connection()
            if self_managed:
                with connection as conn:
                    # if object_id is None, user action only (not file-related)
                    activity_id = self._track_action(
                        uid, action_name, location_id, platform_name, object_id, target_uid, indirect_target_id,
                        version, conn, created_time
                    )
                    return {'activity_id': activity_id}, 1
            activity_id = self._track_action(
                uid, action_name, location_id, platform_name, object_id, target_uid, indirect_target_id,
                version, connection, created_time
            )
            return {'activity_id': activity_id}, 1
        except BaseException as e:
            logger.exception('Error while storing a user activity')
            if is_timeout_event(e):
                return {}, -2
            return {}, -1

    def _track_action(self, uid, action_name, location_id, platform_name,
                      object_id, target_uid, indirect_target_id, version, connection, created_time):
        '''
        @param object_id: File ID
        @param target_uid: Target user ID
        @return activity_id
        '''
        # A deletes B who shared files to C, D
        # A: actor_uid, target_uid
        # B: target_uid2
        insert_info = {
            'actor_uid': uid,  # user who generates the action
            'action': action_name,
            'file_id': object_id,
            'target_uid': target_uid,
            'location_id': location_id,
            'client_platform': platform_name,
            'version': version,
            'target_uid2': indirect_target_id
        }
        if created_time:
            insert_info['created_time'] = created_time
        return connection.insert(
                   'activity_logs', insert_info, return_id='activity_id', autocommit=False
               )


class NotificationManager(object):
    '''
    Manages notification messages in database
    '''
    def __init__(self, dbm=None):
        if dbm:
            self.dbm = dbm
        else:
            self.dbm = get_database_manager(0)

    def is_mobile_notification_required(self, action_name):
        if action_name in (constants.ACTION_MOVE, constants.ACTION_RENAME_FOLDER, constants.ACTION_DELETE_FOLDER):
            return False
        return True

    def find_device_tokens_by_user_id(self, uid, connection=None):
        '''
        @see proc_Notificationtoken_Select
        @return: a dict {platform: [(token, environ), ...]}
        '''
        # FIXME:NULL to be compatible. Remove later
        q = '''SELECT pn_token AS token, LOWER(pn_platform) AS platform, NULL AS environ
               FROM registered_devices
               WHERE owner_uid = %(user_id)s'''
        try:
            self_managed = False  # connection is not managed by this method. Connection will not be closed here
            if connection is None:
                self_managed = True  # connection is managed by this method
                connection = self.dbm.connection()
            if self_managed:
                with connection as conn:
                    rs = conn.fetch_all(q, {'user_id': uid})
            else:
                rs = connection.fetch_all(q, {'user_id': uid})
            tokens = {}
            # Why not default dict here? It is unreadable
            for row in rs:
                try:
                    tokens[row['platform']].append((row['token'], row['environ']))
                except:
                    tokens[row['platform']] = [(row['token'], row['environ']), ]
            return tokens, 1
        except BaseException as e:
            logger.exception('Error while fetching user-specific mobile device tokens')
            if is_timeout_event(e):
                return {}, -2
            return {}, -1

    def track_user_notification(self, from_uid, to_uid, action, object_id, object_type,
                                device_id, platform_name, activity_id, connection=None, online=False):
        '''
        @see ActionLogFactory.AddActionLog
        @param from_uid User who generates action or event
        @param to_uid: User who receives the affect of the action or event. If from_uid == to_uid, notify to the same user
                       See ActionLogFactory.NotifyToMe and proc_Notification_InsertMulti
        @see proc_Notificationtoken_Select
        @return: a dict {platform: [token1, token2, ...]}
        '''
        try:
            self_managed = False  # connection is not managed by this method. Connection will not be closed here
            if connection is None:
                self_managed = True  # connection is managed by this method
                connection = self.dbm.connection()
            if self_managed:
                with connection as conn:
                    return self._track_user_notification(from_uid, to_uid, action,
                                                         object_id, object_type,
                                                         device_id, platform_name,
                                                         activity_id, online, conn), 1
            return self._track_user_notification(from_uid, to_uid, action,
                                                 object_id, object_type,
                                                 device_id, platform_name,
                                                 activity_id, online, connection), 1
        except BaseException as e:
            logger.exception('Error while notifying user about the event %s', action)
            if is_timeout_event(e):
                return {}, -2
            return {}, -1

    def _track_user_notification(self, from_uid, to_uid, action, object_id, object_type,
                                 device_id, platform_name, activity_id, online, connection):
        '''
        Notify the all devices of a specific user

        @see FileStringService.GetNotifications
        @see proc_Notification_SelectByUserAndDevice
        @param object_id: Default to file_id
        @param object_type: Default to 'file'. Can be 'profile'
        @see ForwardNotification
        @see proc_Notification_InsertMulti
        '''
        utc_now = datetime.utcnow()

        if online:
            try:
                client = redis_store.connect(dbindex=app.config['QUEUE_NOTIFICATION_TRANSPORTER']['db_index'])
                client.rpush(
                    app.config['QUEUE_NOTIFICATION_TRANSPORTER']['name'],
                    ujson.dumps({
                        'job_type': constants.JOB_PUSH_NOTIFICATION_ONLINE,
                        'sharer': {
                            'id': from_uid
                        },
                        "recipient": {
                            "id": from_uid
                        },
                        "device_id": device_id,
                        "file_id": object_id,
                        "activity_id": activity_id,
                        "platform": platform_name
                    }))
            except BaseException as e:
                logger.exception('Error while notifying online user: %s', e.message)
        # @see proc_Notification_InsertMulti
        # Send to all devices of the user
        if platform_name.lower().strip() == 'web' or not device_id:
            connection.execute(
                '''
                  INSERT INTO notifications (
                    token, platform, user_id, file_id,
                    action, activity_id, message, created_time
                  )
                  SELECT device_id, platform, %(user_id)s, %(file_id)s,
                    %(action_name)s, %(activity_id)s, NULL, %(utc_now)s
                  FROM registered_devices
                  WHERE owner_uid = %(user_id)s
                ''',
                {
                    'user_id': from_uid,
                    'utc_now': utc_now,
                    'action_name': action,
                    'activity_id': activity_id,
                    'file_id': object_id
                })
        else:
            connection.execute(
                '''
                  INSERT INTO notifications (
                    token, platform, user_id, file_id,
                    action, activity_id, message, created_time
                  )
                  SELECT device_id, platform, %(user_id)s, %(file_id)s,
                    %(action_name)s, %(activity_id)s, NULL, %(utc_now)s
                  FROM registered_devices
                  WHERE owner_uid = %(user_id)s AND device_id != %(device_id)s
                ''',
                {
                    'user_id': from_uid,
                    'utc_now': utc_now,
                    'action_name': action,
                    'activity_id': activity_id,
                    'file_id': object_id,
                    'device_id': device_id
                })
        return {}

    def notify_user_device(self, from_uid, to_uid, action, object_id, object_type, device_id,
                           platform_name, activity_id, connection):
        '''
        Sends notifications to all other user devices (iOS and Android)
        :param object_id: str
               Can be None. Indicates: file-id
        '''
        ret = {'android': 0, 'ios': 0}
        if self.is_mobile_notification_required(action) is True:
            token_infos, status = self.find_device_tokens_by_user_id(to_uid, connection)
            logger.info('Notification tokens found: %s', token_infos)
            if status < 0:
                return ret, status
            msg = {
                   "user_id": str(to_uid),
                   "file_id": str(object_id) if object_id else None,
                   "activity_id": str(activity_id),
                   "action": action
                  }
            # Google Cloud Messaging
            if 'android' in token_infos:
                logger.info('Sending GCM message on %s to %s: %s', action, to_uid, msg)
                rs, status = notification_utils.fcm_push(
                                 'android', 'data', msg,
                                 [token_info[0] for token_info in token_infos['android']], None
                             )
                if status == 1:
                    ret['android'] = rs['count']
            # Apple Push Notification Service
            if 'ios' in token_infos:
                logger.info('Sending APNS message on %s to %s: %s', action, to_uid, msg)
                logger.info(token_infos['ios'])
                rs, status = notification_utils.fcm_push(
                                 'ios', 'data', msg,
                                 [token_info[0] for token_info in token_infos['ios']], None
                             )
                if status == 1:
                    ret['ios'] = rs['count']
            return ret, 1

    def notify_device(self, from_uid, to_uid, action, object_id, object_type, device_id,
                      platform_name, activity_id, connection):
        '''
        Notifies a single device only
        @note Not in use
        '''
        utc_now = datetime.utcnow()
        connection.insert('notifications',
                         {
                          'token': device_id,
                          'platform': platform_name,
                          'user_id': to_uid,
                          'file_id': object_id,
                          'action': action,
                          'activity_id': activity_id,
                          'message': None,
                          'created_time': utc_now
                         },
                         autocommit=False)

    def _notify_team_members(self, from_uid, action, object_id, object_type,
                            device_id, platform_name,
                            activity_id, team_member_uids, connection, online=False):
        '''Notify team members when team info/member changes'''
        utc_now = datetime.utcnow()
        if team_member_uids:
            try:
                if online:
                    client = redis_store.connect(dbindex=app.config['QUEUE_NOTIFICATION_TRANSPORTER']['db_index'])
                    for member_uid in team_member_uids:
                        # Online notification works as a hint without real content
                        client.rpush(
                            app.config['QUEUE_NOTIFICATION_TRANSPORTER']['name'],
                            ujson.dumps({
                                'job_type': constants.JOB_PUSH_NOTIFICATION_TEAM_INFO_UPDATE,
                                'actor': {
                                    'id': from_uid
                                },
                                "member": {
                                    "id": member_uid
                                },
                                "device_id": device_id,
                                "activity_id": activity_id,
                                "platform": platform_name
                            }))
            except BaseException:
                logger.exception('Error while notifying online team member')
            # Added off-line notifications for all members
            connection.execute(
                '''INSERT INTO notifications (
                     token, platform, user_id, file_id,
                     action, activity_id, message, created_time
                   )
                   SELECT device_id, platform, owner_uid, %(file_id)s,
                     %(action_name)s, %(activity_id)s, NULL, %(utc_now)s
                   FROM registered_devices
                   WHERE owner_uid IN %(user_ids)s''',
                {
                    'user_ids': tuple(team_member_uids),
                    'utc_now': utc_now,
                    'action_name': constants.EVENT_MAPPING[action],  # actor performs an action, which trigger an event at target user
                    'activity_id': activity_id,
                    'file_id': object_id
                })
        return len(team_member_uids)

    def notify_to_file_recipients(self, from_uid, action, object_id, object_type,
                                  device_id, platform_name, activity_id, recipients,
                                  connection, downstream=False, online=False):
        '''Add off-line notifications to registered file recipients
        @param recipients: List of recipients.It can be None or a list ["<uid>"]
        @param downstream: Notify downstream recipient or not.
                           Applicable when owner revokes access to a file from a direct file recipient
        @return a tuple (result, status)
        '''
        try:
            if action in (constants.ACTION_SHARE, constants.ACTION_REVOKE,
                          constants.ACTION_EDIT_SHARING, constants.ACTION_RESHARE,
                          constants.ACTION_ACCESS_EXPIRED,
                          constants.ACTION_DISTRIBUTE_FILE,
                          constants.ACTION_VIEW,
                          constants.ACTION_CHANGE_RECIPIENTS):
                broadcast_mode = 'selective'
            else:
                # disregard recipients
                broadcast_mode = 'all'
            self_managed = False  # connection is not managed by this method. Connection will not be closed here
            if connection is None:
                self_managed = True  # connection is managed by this method
                connection = self.dbm.connection()
            if self_managed:
                with connection as conn:
                    count = self._notify_to_file_recipients(
                                from_uid, action, object_id, object_type,
                                device_id, platform_name,
                                activity_id, recipients, broadcast_mode,
                                downstream, online, conn
                            )
                    return {'count': count}, 1
            count = self._notify_to_file_recipients(
                        from_uid, action, object_id, object_type,
                        device_id, platform_name,
                        activity_id, recipients, broadcast_mode,
                        downstream, online, connection
                    )
            return {'count': count}, 1
        except BaseException as e:
            logger.exception('Error while notifying user about the event %s', action)
            if is_timeout_event(e):
                return {}, -2
            return {}, -1

    def _notify_to_file_recipients(self, from_uid, action, object_id, object_type,
                                   device_id, platform_name, activity_id, recipients,
                                   broadcast_mode, downstream, online, connection):
        '''
        Stores offline notifications for FileString users

        @note File sharer changes her name -> notify that event to all of her file recipients
        '''
        # Find list of direct file recipients of from_uid
        # Send notification to them
        from fscore.service.file_retrieval import FileService
        file_registry = FileService(self.dbm)
        utc_now = datetime.utcnow()
        logger.info('Recipients %s - %s - %s', recipients, broadcast_mode, action)
        if broadcast_mode == 'all':  # disregard downstream
            # FIXME: Need option by file_id
            rs = file_registry._find_direct_file_sharees_by_uid(from_uid, connection, id_only=True)
            if not rs:
                return 0
            # @see proc_Notification_InsertMulti
            # Send to all devices of the user
            # FIXME: INSERT in a loop
            recipient_ids = [str(row['receiver_uid']).lower() for row in rs]
        else:
            if recipients:
                recipient_ids = recipients
            else:
                recipient_ids = []
            if downstream is True:  # File revoked by owner
                # FIXME: Need option by file_id
                rs = file_registry._find_downstream_recipients_by_sharer_uids(recipient_ids, connection, id_only=True)
                recipient_ids.extend([str(row['receiver_uid']) for row in rs])
        if recipient_ids:
            recipient_ids = list(set(recipient_ids))
            try:
                if online:
                    client = redis_store.connect(dbindex=app.config['QUEUE_NOTIFICATION_TRANSPORTER']['db_index'])
                    for recipient_id in recipient_ids:
                        client.rpush(
                            app.config['QUEUE_NOTIFICATION_TRANSPORTER']['name'],
                            ujson.dumps({
                                'job_type': constants.JOB_PUSH_NOTIFICATION_ONLINE,
                                'sharer': {
                                    'id': from_uid
                                },
                                "recipient": {
                                    "id": recipient_id
                                },
                                "device_id": device_id,
                                "file_id": object_id,
                                "activity_id": activity_id,
                                "platform": platform_name
                            }))
            except BaseException as e:
                logger.exception('Error while notifying online recipient : %s', e.message)
            # Added off-line notifications
            connection.execute(
                '''
                  INSERT INTO notifications (
                    token, platform, user_id, file_id,
                    action, activity_id, message, created_time
                  )
                  SELECT device_id, platform, owner_uid, %(file_id)s,
                    %(action_name)s, %(activity_id)s, NULL, %(utc_now)s
                  FROM registered_devices
                  WHERE owner_uid IN %(user_ids)s
                ''',
                {
                    'user_ids': tuple(recipient_ids),
                    'utc_now': utc_now,
                    'action_name': constants.EVENT_MAPPING[action],  # actor performs an action, which trigger an event at target user
                    'activity_id': activity_id,
                    'file_id': object_id
                })
        return len(recipient_ids)

    def track_notification_to_users_in_network(self, from_uid, object_id, object_type, activity_id, connection):
        pass

    def get_notifications_by_user_and_device(self, uid, device_id, connection=None):
        """

        :param uid:
        :param device_id:
        :param connection:
        :return: rs, status

        status:
            -2 Timeout
            -1 Exception
            1 Success
        """
        try:
            self_managed = False  # connection is not managed by this method. Connection will not be closed here
            if connection is None:
                self_managed = True  # connection is managed by this method
                connection = self.dbm.connection()
            if self_managed:
                with connection as conn:
                    return self._get_notifications_by_user_and_device(uid, device_id, conn)
            return self._get_notifications_by_user_and_device(uid, device_id, connection)
        except BaseException as e:
            logger.exception('Error while get notification by users %s', uid)
            if is_timeout_event(e):
                return {}, -2
            return {}, -1

    def _get_notifications_by_user_and_device(self, uid, device_id, connection):
        '''
        @note New notification structure
              activity_id: <int>
              user_id: <uid>
                  Who is informed about the activity. Used for filter
                  If stored in Redis, it will be part of key
              actor_id:
                  Who performs the action
              action:
                  The name of the activity. Can be: change_name, share_new_file, share_existing_file ...
              target_id:
                  User who is directly affected by "action"
              object_id:
                  The ID of the object or piece of content which "action" is performed against
                  Can be file_id in <actor: user X> <action: share_file> <object: file file_id> to <target: user Y>
              extra:
                  indirect_target: Can include object_id2 or target_id2
                  <actor: user X> <action: move_files> <object: file None> from <target: user Y1> to <target: user Y2>
        '''
        # verb: active action
        # verb_p: passive action
        q = """
            SELECT
              al.activity_id as activitylog_id,
              notification_id,
              u1.user_id as actor_id,
              u2.user_id as target_id,
              al.file_id,
              u1.first_name as actor_first_name,
              u1.last_name as actor_last_name,
              u1.email as actor_identity,
              u2.first_name as target_first_name,
              u2.last_name as target_last_name,
              u2.email as target_identity,
              f.file_name as file_name,
              f.is_dir as file_is_folder,
              f.owner_uid as file_owner_id,
              al.verb,
              al.verb_p,
              al.time,
              al.target_uid2 AS indirect_target_id
            FROM
              (SELECT
                      al.activity_id,
                      n.id AS notification_id,
                      actor_uid,
                      n.user_id as target_uid,
                      al.target_uid2,
                      n.file_id,
                      al.action as verb,
                      n.action AS verb_p,
                      n.created_time AT TIME ZONE 'UTC' as time
               FROM activity_logs al, notifications n
               WHERE al.activity_id = n.activity_id AND n.user_id = %(uid)s
                 AND n.token = %(device_id)s
              ) al LEFT JOIN files f on al.file_id = f.file_id
            INNER JOIN users u1
            ON u1.user_id = al.actor_uid
            LEFT JOIN users u2
            ON u2.user_id = al.target_uid"""

        # Note: target_uid2 (or indirect_target_id) is used when account is deleted
        rs = connection.fetch_all(q, {'uid': uid, 'device_id': device_id})
        ret = {
            'notifications': []
        }

        verb_p_map = {
            ('DownstreamReceiverAccessExpired', 'RecipientAccessExpired', 'AccessExpired'): 'expire',
            ('ChangedName', 'ChangeName', 'ChangeServicePreference',
             'ChangePassword', 'ChangedSender',
             'ChangeSender', 'EmailRemoved', 'EmailVerified',
             'PrimaryEmailChanged', 'EditFile',
             constants.ACTION_CHANGE_TEAM_INFO, constants.ACTION_USER_JOIN_TEAM,
             constants.ACTION_CHANGE_RECIPIENTS, constants.ACTION_CHANGE_USER_ROLE): 'change',
            ('CreateDirectory',): 'create',
            ('Delete', 'DeleteDirectory', 'DeleteFolder', 'SelfRevoke',
             constants.ACTION_DELETE_ACCOUNT, constants.EVENT_ACCOUNT_DELETED): 'delete',
            ('EditSharing', 'EditedSharing'): 'revise',
            ('Move', 'ChangeDirectory', 'RenameFolder'): 'move',
            ('Print', 'Printed'): 'print',
            ('PushUpdate', 'PushedUpdate'): 'distribute',
            ('Reconverted', 'Reconvert'): 'reconvert',
            ('Rename',): 'rename',
            ('Reshare', 'Reshared'): 'reshare',
            ('Revoked', 'DownstreamReceiverRevoked', 'Revoke', 'RecipientDelete'): 'revoke',
            ('Shared', 'Share'): 'share',
            ('DownstreamReceiverViewed', 'View', 'Viewed'): 'view',
            ('Refuse',): 'refuse'
        }

        verb_p_map_normalize = {}
        for k, v in verb_p_map.iteritems():
            for k1 in k:
                verb_p_map_normalize[k1.lower()] = v
        # file|profile|team|membership|account
        object_type_map = {
            ('ChangedName', 'ChangeName', 'ChangeServicePreference',
             'ChangePassword', 'EmailRemoved', 'EmailVerified', 'PrimaryEmailChanged'): 'profile',
            (constants.ACTION_CHANGE_TEAM_INFO,): 'team',
            (constants.ACTION_USER_JOIN_TEAM, constants.ACTION_CHANGE_USER_ROLE): 'membership',
            (constants.ACTION_DELETE_ACCOUNT, constants.EVENT_ACCOUNT_DELETED): 'account',
        }
        object_type_map_normalize = {}
        for k, v in object_type_map.iteritems():
            for k1 in k:
                object_type_map_normalize[k1.lower()] = v

        extend_object = {
            ('ChangedName', 'ChangeName'): {
                'target': 'info'
            },
            ('ChangeServicePreference',): {
                'target': 'setting'
            },
            ('EmailRemoved', 'EmailVerified', 'PrimaryEmailChanged'): {
                'target': 'email'
            },
            (constants.ACTION_CHANGE_RECIPIENTS,): {
                'target': 'recipient'
            }
        }
        extend_object_normalize = {}
        for k, v in extend_object.iteritems():
            for k1 in k:
                extend_object_normalize[k1.lower()] = v

        # Notifications that are redundant when its associated objects no longer exist
        expired_notifications = []
        for item in rs:
            verb = verb_p_map_normalize.get(item['verb_p'].lower(), None)
            if not verb:
                logger.warn('Notification: Not found mapping action %s', item['verb_p'])
                continue
            verb_info = app.config['VERBS'].get(
                verb,
                {
                    'id': None,
                    'infinitive': item['verb'],
                    'past_tense': item['verb_p']
                })
            object_type = object_type_map_normalize.get(item['verb_p'].lower(), None)
            if object_type:
                object_info = {
                    'type': object_type,
                }
            else:
                object_info = {
                    'type': 'file',
                    'id': item['file_id'],
                    'name': item['file_name'],
                    'is_folder': item['file_is_folder'],
                    'owner_id': str(item['file_owner_id']) if item['file_owner_id'] else None
                }
                if not item['file_owner_id'] and verb not in ['delete', 'revoke']:
                    expired_notifications.append(item['notification_id'])
                    logger.info('File %s had deleted, no need send action %s to client ', item['file_id'], verb)
                    continue
                if object_info['is_folder'] is None:
                    file_info = redis_store.vget(app.config['KV_FILE_INFO'] % item['file_id'])
                    if not file_info:
                        logger.warn('Not found file info in redis of file_id %s', item['file_id'])
                        object_info['is_folder'] = False
                    else:
                        file_info = ujson.loads(file_info)
                        object_info['is_folder'] = file_info['is_folder']
                        object_info['name'] = file_info['name']
                        object_info['owner_id'] = file_info['owner_id']
            extra_context = {
                'notification_id': item['notification_id'],
                'activitylog_id': item['activitylog_id'],
            }
            # Check active verb (not passive verb)
            if item["verb"] == constants.ACTION_DELETE_ACCOUNT and item['indirect_target_id']:
                extra_context["indirect_target"] = {
                    "id": str(item['indirect_target_id'])
                }
            if item['verb_p'].lower() in extend_object_normalize.keys():
                object_info.update(extend_object_normalize.get(item['verb_p'].lower()))
            # Build the structure
            ret['notifications'].append({
                'actor': {
                    'first_name': item['actor_first_name'],
                    'last_name': item['actor_last_name'],
                    'identity': item['actor_identity'],
                    'id': item['actor_id'],
                },
                'target': {
                    'first_name': item['target_first_name'],
                    'last_name': item['target_last_name'],
                    'identity': item['target_identity'],
                    'id': item['target_id'],
                },
                'object': object_info,
                'verb': verb_info,
                'extra_context': extra_context,
                'time': to_iso8601(item['time'])
            })

        # Delete excess notification
        if expired_notifications:
            connection.delete('notifications', {'id': tuple(expired_notifications)}, autocommit=False)
        return ret, 1

    def delete_notification(self, uid, notification_ids, connection=None):
        try:
            self_managed = False  # connection is not managed by this method. Connection will not be closed here
            if connection is None:
                self_managed = True  # connection is managed by this method
                connection = self.dbm.connection()
            if self_managed:
                with connection as conn:
                    conn.delete(
                        'notifications',
                        {
                            'user_id': uid,
                            'id': tuple(notification_ids)
                        },
                        autocommit=False
                    )
                    return {}, 1
            connection.delete(
                'notifications',
                {
                    'user_id': uid,
                    'id': tuple(notification_ids)
                },
                autocommit=False
            )
            return {}, 1
        except BaseException as e:
            logger.exception('Error while delete notification by users %s and notification %s', uid, notification_ids)
            if is_timeout_event(e):
                return {}, -2
            return {}, -1


class EmailNotification(object):
    '''
    Sends messages via emails
    '''
    def __init__(self, dbm=None):
        if dbm:
            self.dbm = dbm
        else:
            self.dbm = get_database_manager(0)

    def push_into_queue(self, message_type, receivers):
        pass

    def send(self, message_type, receiver, sender_info, file_info):
        '''
        @see Transoft.FileString.RespondCenterLibrary.BusinessLogic.EmailTransfer
        @see Transoft.FileString.RespondCenterLibrary.BusinessLogic.EmailHelper
        @see Transoft.FileString.RespondCenterLibrary.FileStringService.SendEmailNotfication
        @see D:\projects\Transoft.FileString.WebApp\Transoft.FileString.WebApp\Transoft.FileString.WebApp.Models\Resource\TemplateEmail
        '''

        if message_type == constants.MT_SHARED_FILE_EXPIRED:
            pass
        if message_type == constants.MT_SHARED_FILE_UPDATED:
            pass
        if message_type == constants.MT_SHARED_FILE_REVOKED:
            pass
        if message_type == constants.MT_SHARED_FILE_DELETED:
            pass
        if message_type == constants.MT_SHARED_FILE_DOWNLOADED:
            pass
        if message_type == constants.MT_SHARED_FILE_RESHARED:
            pass
        if message_type == constants.MT_SHARED_FILE_VIEWED:
            pass
        if message_type == constants.MT_SHARED_FILE_PRINTED:
            pass
        if message_type == constants.MT_SHARED_FILE_BY_OWNER:
            # TemplateEmail/ShareFileFirstRecipient.html
            # TemplateEmail/ShareFile.html
            send_email_to_recipient_on_file_shared(sender_info['email'], receiver['email'],
                                                   file_info['file_name'], file_info['file_id'], sender_info['message'],
                                                   sender_info['first_name'], sender_info['last_name'], sender_info['email'],
                                                   True if receiver['registered'] is True else False)
            return 1
        if message_type == constants.MT_SHARED_FILE_BY_FILE_RECIPIENT:
            # TemplateEmail/ShareFileFirstRecipient.html
            # TemplateEmail/ShareFile.html
            send_email_to_recipient_on_file_shared(sender_info['email'], receiver['email'],
                                                   file_info['file_name'], file_info['file_id'], sender_info['message'],
                                                   sender_info['first_name'], sender_info['last_name'], sender_info['email'],
                                                   True if receiver['registered'] is True else False)
            return 1


class Activity(object):

    def __init__(self, dbm=None):
        if dbm:
            self.dbm = dbm
        else:
            self.dbm = get_database_manager(0)

    def get_activities_by_file(self, sharer_id, file_id, from_time, to_time, connection=None):
        from fscore.service import file_retrieval as file_service
        try:

            self_managed = False  # connection is not managed by this method. Connection will not be closed here
            if connection is None:
                self_managed = True  # connection is managed by this method
                connection = self.dbm.connection()
            if self_managed:
                with connection as conn:
                    sharer_role = file_service.FileService()._find_role_in_file(
                        file_id, sharer_id, conn
                    )
                    if sharer_role == file_retrieval.ROLE_DOWNSTREAM:
                        return {}, -3
                    is_owner = sharer_role
                    return self._get_activities_by_file(sharer_id, file_id, from_time, to_time, is_owner, conn)

            sharer_role = file_service.FileService()._find_role_in_file(
                file_id, sharer_id, connection
            )
            if sharer_role == file_retrieval.ROLE_DOWNSTREAM:
                return {}, -3
            is_owner = sharer_role
            return self._get_activities_by_file(sharer_id, file_id, from_time, to_time, is_owner, connection)
        except BaseException as e:
            logger.exception('Error while get activities action by %s', file_id)
            if is_timeout_event(e):
                return {}, -12
            return {}, -11

    def _get_activities_by_file(self, sharer_id, file_id, from_time, to_time, is_owner, connection):
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
        #mapping column before make result data
        numbermap = {'email': 1, 'first_name': 2, 'last_name': 3, 'uid': 4, 'action': 5, 'client_city': 6, 'client_country': 7,
                     'client_platform': 8, 'created_time': 9, 'started_time': 10, 'timespan': 11, 'platform': 12,
                     'city': 13, 'country': 14
                     }
        # make up result to [(value1 of session 1, value2 of session 1 ...), (value1 of session 2, value of session 2) ....]
        for item in rs:
            item_cv = [tuple(item[i] for i in sorted(item, key=numbermap.__getitem__))]
            activity_makeup = activity_makeup + item_cv

        activity_makeup = sorted(activity_makeup, key=lambda activity: activity[4])
        logger.info('=====================================> activity_makeup is: {}'.format(activity_makeup))

        activities = []
        for infos, data in groupby(activity_makeup, key=itemgetter(0, 1, 2, 3)):
            activities_belong_user = [d for d in data]
            logger.info('activities_belong_user is: {}'.format(activities_belong_user))
            logger.info('=====================================> len of activities_belong_user is: {}'.format(len(activities_belong_user)))
            for open, session_data in groupby(activities_belong_user, key=itemgetter(9, 12, 13, 10, 11)):
                activity = {}
                # get infos of receiver about: first name, last name, email, uid
                activity['recipient'] = {}
                activity['recipient']['email'] = infos[0]
                activity['recipient']['first_name'] = infos[1]
                activity['recipient']['last_name'] = infos[2]
                activity['recipient']['uid'] = infos[3]
                # get infos about time, location, duration when a session has been opened.
                activity['open'] = {}
                activity['open']['started_time'] = to_iso8601(open[0])
                activity['open']['location'] = open[1] + ', ' + open[2] if open[1] and open[2] else ''
                activity['open']['duration'] = open[3]
                activity['open']['device_name'] = open[4]
                # group action print and download that belongs to this session.
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

    def get_activities_by_file_xxxx(self, file_id, sharer_id, from_date=None, to_date=None, limit=None, action=['view'], connection=None):
        def _find_permission(con):
            perm = file_retrieval.FileService(self.dbm)._find_permission(file_id, sharer_id,
                                                                         None, con)
            return perm

        def _excute(con):
            perm = _find_permission(con)
            if perm in (0, 3):
                return {}, perm
            rv = {
                'activities': []
            }
            if 'view' in action:
                _tmp, status = self._get_activities_by_file_xxxx(file_id, sharer_id, from_date, to_date, limit,
                                                               perm == file_retrieval.PERM_OWNER, con)
                if status == 1:
                    rv['activities'].extend(_tmp['activities'])
                action.remove('view')
            if action:
                _tmp, status = self._get_activities_by_file_xxxx(file_id, sharer_id, limit,
                                                            perm == file_retrieval.PERM_OWNER, action, con)
                if status == 1:
                    rv['activities'].extend(_tmp['activities'])
            rv['activities'] = sorted(rv['activities'], key=lambda k: k['time'])
            return rv, 1

        try:
            self_managed = False  # connection is not managed by this method. Connection will not be closed here
            if connection is None:
                self_managed = True  # connection is managed by this method
                connection = self.dbm.connection()
            if self_managed:
                with connection as conn:
                    return _excute(conn)
            return _excute(connection)
        except BaseException as e:
            logger.exception('Error while get activities action by %s', file_id)
            if is_timeout_event(e):
                return {}, -12
            return {}, -11

    def _get_activities_by_file_xxxx(self, file_id, sharer_id, limit, is_owner, action, connection):
        if not limit:
            limit = 100
        if is_owner:
            q = """
            SELECT
              u1.user_id as actor_id,
              u2.user_id as target_id,
              f.file_id,
              u1.first_name as actor_first_name,
              u1.last_name as actor_last_name,
              u1.email as actor_identity,
              u2.first_name as target_first_name,
              u2.last_name as target_last_name,
              u2.email as target_identity,
              f.file_name as file_name,
              verb,
              time
            FROM
              (SELECT actor_uid, target_uid, file_id, action as verb,
                      created_time as time
              FROM activity_logs al
              WHERE al.location_id IS NOT NUll
                      AND al.action IN %(action)s
              ORDER BY created_time DESC 
              %(additional_select_clause)s) al,
              users u1,
              users u2,
              files f
            WHERE u1.user_id = al.actor_uid AND u2.user_id = al.target_uid AND f.file_id = al.file_id
            """
        else:
            q = """
            SELECT
              u1.user_id as actor_id,
              u2.user_id as target_id,
              f.file_id,
              u1.first_name as actor_first_name,
              u1.last_name as actor_last_name,
              u1.email as actor_identity,
              u2.first_name as target_first_name,
              u2.last_name as target_last_name,
              u2.email as target_identity,
              f.file_name as file_name,
              verb,
              time
            FROM
              (SELECT actor_uid, target_uid, file_id, action as verb,
                      created_time as time
               FROM activity_logs al
               WHERE al.location_id IS NOT NUll
                     AND al.file_id = %(file_id)s
                     AND al.actor_uid = %(uid)s
                     AND al.action IN %(action)s
               ORDER BY created_time DESC %(additional_select_clause)s) al,
              users u1,
              users u2,
              files f
            WHERE u1.user_id = al.actor_uid AND u2.user_id = al.target_uid AND f.file_id = al.file_id
            """
        if limit:
            q = q.replace('%(additional_select_clause)s', ' LIMIT %(limit)s ')
        else:
            q = q.replace('%(additional_select_clause)s', ' ')
        rs = connection.fetch_all(
                q,
                {'limit': limit, 'uid': sharer_id, 'file_id': file_id, 'action': tuple(action)}
             )
        ret = {
            'activities': []
        }

        for item in rs:
            ret['activities'].append({
                'actor': {
                    'first_name': item['actor_first_name'],
                    'last_name': item['actor_last_name'],
                    'identity': item['actor_identity'],
                    'id': item['actor_id'],
                },
                'target': {
                    'first_name': item['target_first_name'],
                    'last_name': item['target_last_name'],
                    'identity': item['target_identity'],
                    'id': item['target_id'],
                },
                'object': {
                    'type': 'file',
                    'id': item['file_id'],
                    'name': item['file_name']
                },
                'verb': app.config['VERBS'].get(item['verb'].lower(), {}),
                'extra_context': {},
                'time': to_iso8601(item['time'])
            })
        return ret, 1

    def _get_view_activity_by_file(self, file_id, sharer_id, from_date=None, to_date=None, limit=None, is_owner=False, connection=None):
        addtional_where_clause = ''
        if is_owner:
            query = """
                SELECT %(additional_select_clause)s
                  mtf.started_time AS time,
                  mtf.user_id AS viewer_id,
                  u.first_name as viewer_first_name,
                  u.last_name as viewer_last_name,
                  u.email as viewer_identity,
                  fs.status as viewer_status,
                  mtf.file_id,
                  mtf.timespan as timespan,
                  mtd.platform as platform,
                  (CASE
                    WHEN gl.location_id IS NULL THEN 'Unknown'
                    ELSE CONCAT(gl.city, ', ', gl.country)
                  END) as location,
                  mtd.device_name as device_name
                FROM file_metrics mtf LEFT JOIN locations gl ON mtf.location_id = gl.location_id,
                     device_metrics mtd,
                     users u, shared_files fs
                WHERE mtf.tracking_id = mtd.tracking_id
                      AND mtf.user_id = u.user_id
                      AND mtf.user_id = fs.receiver_uid
                      AND mtf.file_id = fs.file_id
                      AND mtf.file_id = %(file_id)s
                      %(addtional_where_clause)s
                ORDER BY mtf.started_time DESC
            """
        else:
            query = """
            SELECT 
              mtf.started_time AS time,
              mtf.user_id AS viewer_id,
              u.first_name as viewer_first_name,
              u.last_name as viewer_last_name,
              u.email as viewer_identity,
              fs.status as viewer_status,
              mtf.file_id,
              mtf.timespan as timespan,
              mtd.platform as platform,
              (CASE
                WHEN gl.location_id IS NULL THEN 'Unknown'
                ELSE CONCAT(gl.City, ', ', gl.Country)
              END) as location,
              mtd.device_name as device_name
            FROM file_metrics mtf 
            LEFT JOIN locations gl ON mtf.location_id = gl.location_id
            INNER JOIN device_metrics mtd,
            shared_files fs, users u
            WHERE mtf.tracking_id = mtd.tracking_id
                  AND mtf.file_id = fs.file_id
                  AND mtf.user_id = fs.receiver_uid
                  AND mtf.user_id = u.user_id
                  AND mtf.file_id = %(file_id)s AND fs.sender_uid = %(sharer_id)s
                  %(addtional_where_clause)s
            ORDER BY mtf.started_time DESC
            %(additional_select_clause)s
            """
        if from_date:
            addtional_where_clause = ' AND mtf.started_time >= %(from_date)s AND mtf.started_time <= %(to_date)s'
        query = query.replace('%(addtional_where_clause)s', addtional_where_clause)
        if limit:
            query = query.replace('%(additional_select_clause)s', ' LIMIT %(limit)s ')
        else:
            query = query.replace('%(additional_select_clause)s', ' ')
        rs = connection.fetch_all(query, {'limit': limit,
                                          'file_id': file_id,
                                          'sharer_id': sharer_id,
                                          'from_date': from_date,
                                          'to_date': to_date})
        ret = {
            'activities': []
        }

        for item in rs:
            ret['activities'].append({
                'actor': {
                    'first_name': item['viewer_first_name'],
                    'last_name': item['viewer_last_name'],
                    'identity': item['viewer_identity'],
                    'id': item['viewer_id'],
                },
                'target': {},
                'object': {
                    'type': 'file',
                    'id': file_id
                },
                'verb': {
                    'id': 5,
                    'infinitive': 'view',
                    'past_tense': 'viewed'
                },
                'extra_context': {
                    'location': item['location'],
                    'device_name': item['device_name'],
                    'timespan': item['timespan'],
                    'platform': item['platform'],
                    'status': item['viewer_status']
                },
                'time': to_iso8601(item['time'])
            })
        return ret, 1

    def get_activities_by_users(self, uids, limit=20, connection=None):
        """

        :param uids:
        :param limit:
        :param connection:
        :return: rs, status

        status:
            -2 Timeout
            -1 Exception
            1 Success
        """
        try:
            self_managed = False  # connection is not managed by this method. Connection will not be closed here
            if connection is None:
                self_managed = True  # connection is managed by this method
                connection = self.dbm.connection()
            if self_managed:
                with connection as conn:
                    return self._get_activities_by_users(uids, limit, conn)
            return self._get_activities_by_users(uids, limit, connection)
        except BaseException as e:
            logger.exception('Error while get activities action by users %s', uids)
            if is_timeout_event(e):
                return {}, -2
            return {}, -1

    def _get_activities_by_users(self, uids, limit, connection):
        q = """
            SELECT
              u1.user_id as actor_id,
              u2.user_id as target_id,
              f.file_id,
              u1.first_name as actor_first_name,
              u1.last_name as actor_last_name,
              u1.email as actor_identity,
              u2.first_name as target_first_name,
              u2.last_name as target_last_name,
              u2.email as target_identity,
              f.file_name as file_name,
              verb,
              verb_p,
              time
            FROM
              (SELECT actor_uid, n.user_id as target_uid, file_id, action as verb, verb_p,
                      created_time AS time
               FROM activity_logs al, (SELECT DISTINCT user_id, activity_id, action as verb_p FROM notifications) n
               WHERE al.activity_id = n.activity_id
                      AND al.actor_uid IN %(uids)s
                      AND n.user_id IN %(uids)s
                      AND al.actor_uid != n.user_id
                      AND al.action IN ('Share','ReShare','Revoke')
              ORDER BY created_time DESC LIMIT %(limit)s) al,
              users u1,
              users u2,
              files f
            WHERE u1.user_id = al.actor_uid AND u2.user_id = al.target_uid AND f.file_id = al.file_id
        """
        rs = connection.fetch_all(q, {'limit': limit, 'uids': tuple(uids)})
        ret = {
            'activities': []
        }

        for item in rs:
            ret['activities'].append({
                'actor': {
                    'first_name': item['actor_first_name'],
                    'last_name': item['actor_last_name'],
                    'identity': item['actor_identity'],
                    'id': item['actor_id'],
                },
                'target': {
                    'first_name': item['target_first_name'],
                    'last_name': item['target_last_name'],
                    'identity': item['target_identity'],
                    'id': item['target_id'],
                },
                'object': {
                    'type': 'file',
                    'id': item['file_id'],
                    'name': item['file_name']
                },
                'verb': app.config['VERBS'].get(
                    item['verb'].lower(),
                    {
                        'id': None,
                        'infinitive': item['verb'],
                        'past_tense': item['verb_p']
                    }),
                'extra_context': {},
                'time': to_iso8601(item['time'])
            })
        return ret, 1

    def find_aggregated_activities_by_recipient_and_file(
            self, recipient_uid, file_id, from_time, to_time, connection=None):
        """
        See: https://communicate.atlassian.net/browse/NF-128
        @since: 27/12/2016
        """
        try:
            self_managed = False  # connection is not managed by this method. Connection will not be closed here
            if connection is None:
                self_managed = True  # connection is managed by this method
                connection = self.dbm.connection()
            if self_managed:
                with connection as conn:
                    return self._find_aggregated_activities_by_recipient_and_file(
                               recipient_uid, file_id, from_time, to_time, conn
                           )
            return self._find_aggregated_activities_by_recipient_and_file(
                       recipient_uid, file_id, from_time, to_time, connection
                   )
        except BaseException as e:
            logger.exception(
                'Error while finding aggregated activities by the recipient %s on file %s',
                recipient_uid, file_id
            )
            if is_timeout_event(e):
                return {}, -2
            return {}, -1

    def _find_aggregated_activities_by_recipient_and_file(
            self, recipient_uid, file_id, from_time, to_time, connection):
        # Get all activity related to View, Print and Download
        if from_time and to_time:
            q = """SELECT action, device_name, started_time,
                          country, city, state,
                   FROM (
                       SELECT 'open' AS action, d.platform AS device_name, f.started_time,
                              timespan AS duration, 
                              CASE
                                WHEN loc.location_id IS NULL THEN 'Unknown'
                                ELSE CONCAT(loc.city, ', ', loc.country)
                              END as location
                       FROM file_metrics f
                       INNER JOIN device_metrics d ON f.tracking_id = d.tracking_id
                       LEFT JOIN locations loc ON loc.location_id = f.location_id
                       WHERE f.file_id = %(file_id)s AND f.user_id = %(recipient_id)s
                       AND f.started_time >= %(start)s AND f.started_time <= %(end)s
                       UNION ALL
                       SELECT action, client_platform AS device_name, al.created_time AS started_time,
                              NULL AS duration,
                              CASE
                                WHEN loc.location_id IS NULL THEN 'Unknown'
                                ELSE CONCAT(loc.city, ', ', loc.country)
                              END as location
                       FROM activity_logs al
                       LEFT JOIN locations loc ON loc.location_id = al.location_id
                       WHERE actor_uid = %(recipient_id)s
                       AND action IN ('print', 'download') AND file_id = %(file_id)s
                       AND f.started_time >= %(start)s AND f.started_time <= %(end)s
                   ) m ORDER BY started_time ASC"""
            rs = connection.fetch_all(
                     q,
                     {
                         'recipient_id': recipient_uid,
                         'file_id': file_id,
                         'start': from_time,
                         'end': to_time
                     }
                 )
        else:
            q = """SELECT action, device_name, started_time,
                          country, city, state,
                   FROM (
                       SELECT 'open' AS action, d.platform AS device_name, f.started_time,
                              timespan AS duration, 
                              CASE
                                WHEN loc.location_id IS NULL THEN 'Unknown'
                                ELSE CONCAT(loc.city, ', ', loc.country)
                              END as location
                       FROM file_metrics f
                       INNER JOIN device_metrics d ON f.tracking_id = d.tracking_id
                       LEFT JOIN locations loc ON loc.location_id = f.location_id
                       WHERE f.file_id = %(file_id)s AND f.user_id = %(recipient_id)s
                       UNION ALL
                       SELECT action, client_platform AS device_name, al.created_time AS started_time,
                              NULL AS duration,
                              CASE
                                WHEN loc.location_id IS NULL THEN 'Unknown'
                                ELSE CONCAT(loc.city, ', ', loc.country)
                              END as location
                       FROM activity_logs al
                       LEFT JOIN locations loc ON loc.location_id = al.location_id
                       WHERE actor_uid = %(recipient_id)s
                       AND action IN ('print', 'download') AND file_id = %(file_id)s
                   ) m ORDER BY started_time ASC"""
            rs = connection.fetch_all(
                     q,
                     {
                         'recipient_id': recipient_uid,
                         'file_id': file_id
                     }
                 )
        if not rs:
            return {}
        # Separate data for first session: (from the first "open" to the next "open")
        # https://communicate.atlassian.net/browse/NF-128
        first_session = {
          "open": {},
          "print": [],
          "download": []
        }
        counter = 0  # row to discard
        session_counter = 0  # keep track of session: the first action "open" up to the next "open"action
        if rs[0]["action"] != "open":  # missing "open" action
            for row in rs:
                if row["action"] == "open":  # stop at the first encountered "open" action
                    break
                else:
                    action = row.pop("action")
                    first_session[action].append(row)
                counter += 1
        else:
            # Data is valid
            for row in rs:
                if row["action"] == "open":
                    session_counter += 1
                    if session_counter > 1:  # encounter the second "open" action
                        break
                    del row["action"]
                    first_session["open"] = row  # encounter the first "open" action
                else:
                    action = row.pop("action")
                    first_session[action].append(row)
                counter += 1
        counter = 0
        rs = rs[counter: ]
        ret = {
            "first": first_session,
            "others": rs
        }
        return ret

