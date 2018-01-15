from mist.api.users.models import User
from mist.api.notifications.models import InAppRecommendation


def dismiss_scale_notifications(machine, feedback='NEUTRAL'):
    '''
    Convenience function to dismiss scale notifications from
    a machine.
    Calls dismiss on each notification's channel. May update
    the feedback field on each notification.
    '''
    recommendation = InAppRecommendation.objects(
        owner=machine.owner, model_id="autoscale_v1", rid=machine.id).first()
    # TODO Shouldn't we store which user executed the recommendations action?
    # Marking the recommendation as "dismissed by everyone" seems a bit wrong.
    # Perhaps recommendations' actions such as this one must be invoked by a
    # distinct API endpoint?
    recommendation.applied = feedback == "POSITIVE"
    user_ids = set(user.id for user in machine.owner.members)
    user_ids ^= set(recommendation.dismissed_by)
    recommendation.channel.dismiss(
        users=[user for user in User.objects(id__in=user_ids).only('id')]
    )
