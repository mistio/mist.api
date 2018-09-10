import argparse
import traceback

from pymongo import MongoClient

from mist.api import config
from mist.api.users.models import Organization
from mist.api.notifications.models import InAppNotification
from mist.api.notifications.models import NotificationOverride
from mist.api.notifications.models import UserNotificationPolicy


def migrate_notifications(collection):
    """Migrate all non-dismissed in-app notifications"""
    total = collection.find().count()
    failed = 0
    migrated = 0

    print
    print 'Will migrate %d notifications' % total
    print

    for old_ntf in collection.find({'dismissed': False,
                                    'migrated': {'$exists': False}}):
        try:
            print 'Migrating', old_ntf['_id'],
            try:
                owner = Organization.objects.get(id=old_ntf['organization'])
            except Exception:
                print '[ERROR]'
                failed += 1
                traceback.print_exc()
                continue
            ntf = InAppNotification()
            ntf.owner = owner
            ntf.subject = old_ntf['summary']
            ntf.text_body = old_ntf['body']
            ntf.html_body = old_ntf['html_body']
            ntf.rid = old_ntf['machine']['_ref'].id
            ntf.rtype = 'machine'
            ntf.created_at = old_ntf['created_date']
            ntf.save()
        except Exception:
            print '[ERROR]'
            failed += 1
            traceback.print_exc()
        else:
            try:
                collection.update_one({'_id': old_ntf['_id']},
                                      {'$set': {'migrated': True}})
            except Exception:
                print '[ERROR]'
                failed += 1
                traceback.print_exc()
                try:
                    ntf.delete()
                except:
                    pass
            else:
                print '[OK]'
                migrated += 1

    print
    print 'Migrated: %d/%d' % (migrated, total)
    print 'Failed: %d' % failed
    print
    print 'Completed %s' % ('with errors!' if failed else 'successfully!')
    print


def migrate_policies(collection):
    """Migrate all user notification policies with overrides > 0"""
    total = collection.find().count()
    failed = 0
    migrated = 0

    print
    print 'Will migrate %d notification policies' % total
    print

    for old_np in collection.find({'overrides.0': {'$exists': True},
                                   'migrated': {'$exists': False}}):
        try:
            print 'Migrating', old_np['_id'],
            try:
                owner = Organization.objects.get(id=old_np['organization'])
            except Exception:
                print '[ERROR]'
                failed += 1
                traceback.print_exc()
                continue
            np = UserNotificationPolicy()
            np.owner = owner
            np.user_id = old_np['user']
            for old_override in old_np['overrides']:
                channel = old_override.get('source', '')
                if channel == 'email_report':
                    channel = 'EmailReport'
                override = NotificationOverride()
                override.channel = channel
                if old_override.get('machine'):
                    override.rid = old_override['machine']['_ref'].id
                    override.rtype = 'machine'
                np.overrides.append(override)
            np.save()
        except Exception:
            print '[ERROR]'
            failed += 1
            traceback.print_exc()
        else:
            try:
                collection.update_one({'_id': old_np['_id']},
                                      {'$set': {'migrated': True}})
            except Exception:
                print '[ERROR]'
                failed += 1
                traceback.print_exc()
                try:
                    np.delete()
                except:
                    pass
            else:
                print '[OK]'
                migrated += 1

    print
    print 'Migrated: %d/%d' % (migrated, total)
    print 'Failed: %d' % failed
    print
    print 'Completed %s' % ('with errors!' if failed else 'successfully!')
    print


def main():
    argparser = argparse.ArgumentParser(
        description=('Migrate notifications and user policies. If neither '
                     'option is selected, both migrations will run')
    )
    argparser.add_argument(
        '-n', '--notifications', action='store_true',
        help='Migrate notifications'
    )
    argparser.add_argument(
        '-p', '--policies', action='store_true',
        help='Migrate user notification policies'
    )

    args = argparser.parse_args()

    client = MongoClient(config.MONGO_URI)
    db = client.get_database('mist2')

    if args.notifications:
        migrate_notifications(db['notification'])
    if args.policies:
        migrate_policies(db['user_notification_policy'])
    if not (args.notifications or args.policies):
        migrate_notifications(db['notification'])
        migrate_policies(db['user_notification_policy'])

    client.close()


if __name__ == '__main__':
    main()
