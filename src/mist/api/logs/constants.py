"""Definition of constant variables.

Here we define constants required by our logging system.

The following definitions are important in order to properly query
Elasticsearch, process aggregations, and associate logs into stories.

"""

# Event fields that should be explicitly present in a story must be added here.
FIELDS = (
    'user_id',
    'owner_id',
    'cloud_id',
    'machine_id',
    'rule_id',
    'stack_id',
    'template_id',
    'schedule_id',
    'script_id',
    'volume_id',
    'key_id',
    'job_id',
    'shell_id',
    'session_id',
    'incident_id',
    'job',
    'su'
)

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Variables and relationship definitions required in order to create stories
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Pairs indicating the actions that may start and close a single job. Jobs
# may either be standalone stories or part of a broader story.
JOBS = {
    'run_script': (
        'script_finished',
    ),
    'create_machine': (
        'post_deploy_finished',
    ),
    'create_cluster': (
        'cluster_post_deploy_finished',
    ),
    'destroy_cluster': (
        'cluster_deletion_finished',
    ),
    'enable_monitoring': (
        'telegraf_deployment_finished',
    ),
    'disable_monitoring': (
        'telegraf_undeployment_finished',
    ),
}

# Following are actions that may open/close stories. The following tuples are
# necessary in order for new logs to be properly associated with any relevant
# story.

# Actions that may start a new story.
STARTS_STORY = (
    'open',
    'connect',
    'rule_triggered',
    'workflow_started',
    'schedule_started', ) + tuple(JOBS.keys())

# Actions that may close existing stories.
CLOSES_STORY = (
    'close',
    'disconnect',
    'rule_untriggered',
    'workflow_finished',
    'schedule_finished',
) + tuple(a for v in JOBS.values() for a in v) + ('end_job', )

# Actions that can close an open incident.
CLOSES_INCIDENT = (
    'update_rule',
    'delete_rule',
    'remove_cloud',
    'delete_script',
    'delete_volume',
    'delete_subnet',
    'delete_network',
    'delete_schedule',
    'delete_dns_zone',
    'delete_dns_record',
    'delete_key',
    'delete_stack',
    'delete_template',
    'destroy_machine',
    'disable_monitoring',
)

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Variables required for requesting and processing Elasticsearch aggregations
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Pairs indicating the Elasticsearch document types that searches should run
# against for a given story type. Searches may need to run against more than
# one document type. For instance, a job story may consist of logs of both
# type "job" and "request".
TYPES = {
    'job': 'job,request',
    'shell': 'shell,request',
    'session': 'session,request',
    'incident': 'incident,request',
}

# Buckets to be excluded when processing stories. The list of excluded buckets
# is important when iterating over the list of buckets returned in aggregation
# results, since the field we run aggregations against, consists not only of
# story IDs, but also actions, such as "opens" or "closes", as well as story
# types.
EXCLUDED_BUCKETS = (
    'opens',
    'closes',
    'updates', ) + tuple(TYPES.keys())
