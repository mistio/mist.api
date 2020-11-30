"""Series of tests to verify the aggregation of logs into stories."""

import time
import traceback

from mist.api.logs.methods import log_event
from mist.api.logs.methods import get_story
from mist.api.logs.methods import get_stories
from mist.api.logs.constants import TYPES


def get_owner_id(logs):
    """Returns the logs' owner_id."""
    return logs['job'][0]['owner_id']


def get_story_id(logs):
    """Returns the job_id of a run_script job."""
    for log in logs['job']:
        if log.get('job', '') == log.get('action', '') == 'run_script':
            return log['job_id']
    assert False


def test_log_event(load_logs):
    """Log events to be tested."""
    for type in ('job', 'shell', 'session', 'incident'):
        for log in load_logs[type]:
            try:
                log_event(**log)
            except Exception:
                traceback.print_exc()
                assert False
            else:
                # Wait to ensure log has actually been indexed.
                time.sleep(1)


def test_open_stories(load_logs):
    """Test open stories.

    Fetch open stories, ensure they are indeed pending, and verify their type.

    """
    owner_id = get_owner_id(load_logs)

    for story_type in ('job', 'shell', 'session'):
        stories = get_stories(story_type, owner_id=owner_id,
                              expand=True, pending=True)
        assert len(stories) is 1

        # Ensure stories are still pending.
        story = stories[0]
        assert not story['finished_at']
        assert story['type'] == story_type

        # Cross-verify the story_id and type.
        for log in story['logs']:
            assert log['type'] in TYPES[story_type]
            assert log['owner_id'] == story['owner_id']
            assert log['%s_id' % story_type] == story['story_id']


def test_closed_stories(load_logs):
    """Test closed stories."""
    owner_id = get_owner_id(load_logs)

    for story_type in ('job', ):
        stories = get_stories(story_type, owner_id=owner_id,
                              expand=True, pending=False)
        assert len(stories) is 2

        story = stories[0]
        assert story['finished_at']
        assert story['type'] == story_type

        for log in story['logs']:
            assert log['type'] in TYPES[story_type]
            assert log['owner_id'] == story['owner_id']
            assert log['%s_id' % story_type] == story['story_id']

    for story_type in ('shell', 'incident'):
        stories = get_stories(story_type, owner_id=owner_id,
                              expand=True, pending=False)
        assert len(stories) is 1

        story = stories[0]
        assert story['finished_at']
        assert story['type'] == story_type
        assert len(story['logs']) is 2

        for log in story['logs']:
            assert log['type'] in TYPES[story_type]
            assert log['owner_id'] == story['owner_id']
            assert log['%s_id' % story_type] == story['story_id']


def test_error_stories(load_logs):
    """Test stories that ended with an error."""
    owner_id = get_owner_id(load_logs)

    for story_type in ('job', ):
        stories = get_stories(story_type, owner_id=owner_id,
                              error=True, expand=True, pending=True)
        assert len(stories) is 0

    for story_type in ('job', ):
        stories = get_stories(story_type, owner_id=owner_id,
                              error=True, expand=True, pending=False)
        assert len(stories) is 1

    for story_type in ('job', ):
        stories = get_stories(story_type, owner_id=owner_id,
                              error=True, expand=True)
        assert len(stories) is 1

        story = stories[0]
        assert story['error']
        assert story['type'] == story_type

        for log in story['logs']:
            assert log['type'] in TYPES[story_type]
            assert log['owner_id'] == story['owner_id']
            assert log['%s_id' % story_type] == story['story_id']

        # Ensure there is a log with an error.
        for log in story['logs']:
            if log['error']:
                break
        else:
            assert False

        # Ensure all indexed logs are present in the story, if appropriate.
        logs = []
        for log in load_logs[story_type]:
            if log['%s_id' % story_type] == story['story_id']:
                logs.append(log)
        assert len(story['logs']) == len(logs)


def test_incidents(load_logs):
    """Test incidents."""
    owner_id = get_owner_id(load_logs)

    for story_type in ('incident', ):
        stories = get_stories(story_type, owner_id=owner_id,
                              expand=True, pending=True)
        assert len(stories) is 2

        story = stories[0]
        assert not story['finished_at']
        assert story['type'] == story_type

        for log in story['logs']:
            assert log['type'] in TYPES[story_type]
            assert log['owner_id'] == story['owner_id']
            assert log['%s_id' % story_type] == story['story_id']

        logs = []
        for log in load_logs[story_type]:
            if log['%s_id' % story_type] == story['story_id']:
                logs.append(log)
        assert len(story['logs']) == len(logs)

    # Publish new event, which is meant to close the open incident.
    for log in load_logs['request']:
        log_event(**log)

    # Wait to ensure log has actually been indexed.
    time.sleep(1)

    # Verify that the incident has closed.
    for story_type in ('incident', ):
        stories = get_stories(story_type, owner_id=owner_id,
                              expand=True, pending=True)
        assert len(stories) is 1


def test_single_story(load_logs):
    """Test fetching a single story.

    Fetch a single story and verify its list of logs.

    """
    owner_id = get_owner_id(load_logs)
    job_id = get_story_id(load_logs)

    story = get_story(owner_id=owner_id, story_id=job_id)
    assert story['finished_at']
    assert len(story['logs']) is 3

    for log in story['logs']:
        assert log['type'] in TYPES['job']
        assert log['owner_id'] == story['owner_id']
        assert log['job_id'] == story['story_id']
        assert log['action'] in ('run_script',
                                 'script_started',
                                 'script_finished')


def test_close_story(load_logs):
    """Test closing stories.

    Fetch an open story and close it manually.

    """
    owner_id = get_owner_id(load_logs)

    for story_type in ('incident', ):
        stories = get_stories(story_type, owner_id=owner_id,
                              expand=True, pending=True)
        assert len(stories) is 1

        story = stories[0]
        assert len(story['logs']) is 1
        assert not story['finished_at']
        assert story['type'] == story_type

        for log in story['logs']:
            assert log['type'] in TYPES[story_type]
            assert log['owner_id'] == story['owner_id']
            assert log['%s_id' % story_type] == story['story_id']

        # Close the story.
        log_event(owner_id=owner_id,
                  action='close_story',
                  event_type='request',
                  story_id=story['story_id'])

        # Wait for index refresh.
        time.sleep(1)

        # Ensure there are no more pending stories.
        stories = get_stories(story_type, owner_id=owner_id,
                              expand=True, pending=True)
        assert len(stories) is 0

        # Verify the story's `finished_at` timestamp.
        story = get_story(owner_id=owner_id, story_id=story['story_id'])
        assert story['finished_at']
        assert story['type'] == story_type
        assert len(story['logs']) is 2
