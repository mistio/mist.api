# Fields that make up a story.
# Event fields that should be explicitly present in a story must be added here.
FIELDS = (
    'user_id',
    'owner_id',
    'cloud_id',
    'machine_id',
    'script_id',
    'rule_id',
    'stack_id',
    'template_id',
    'job_id',
    'shell_id',
    'session_id',
    'incident_id',
)

# Pairs indicating the Elasticsearch document types that searches should run
# against for a given story type. Searches may need to run against more than
# one document type. For instance, a job story may consist of logs of both
# type "job" and "request".
TYPES = {
    'job': 'job,request',
    'shell': 'shell',
    'session': 'session',
    'incident': 'incident,request'
}

# Dictionary of key-value pairs, which indicate actions that open and close a
# certain story.
JOBS = {
    'run_script': 'script_finished',
    'create_machine': 'post_deploy_finished',
    'enable_monitoring': 'deploy_collectd_finished',
    'disable_monitoring': 'undeploy_collectd_finished',
}

# Following are actions that may open/close stories. The following tuples are
# necessary in order for new logs to be properly associated with any relevant
# story.

# Actions that may start a new story.
STARTS_STORY = (
    'open',
    'connect',
    'end_job',
    'workflow_started', ) + tuple(JOBS.keys())

# Actions that may close existing stories.
CLOSES_STORY = (
    'close',
    'disconnect',
    'workflow_finished', ) + tuple(JOBS.values())

# Actions that can close an open incident.
CLOSES_INCIDENT = (
    'update_rule',
    'delete_rule',
    'delete_cloud',
    'destroy_machine',
    'rule_untriggered',
    'disable_monitoring',
)

# Buckets to be excluded when processing stories. The list of excluded buckets
# is important when iterating over the list of buckets returned in aggregation
# results, since the field we run aggregations against, consists not only of
# story IDs, but also actions, such as "opens" or "closes", as well as story
# types.
EXCLUDED_BUCKETS = (
    'opens',
    'closes',
    'updates', ) + tuple(TYPES.keys())
