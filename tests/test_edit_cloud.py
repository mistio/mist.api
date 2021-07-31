"""test for update cloud credentials.
   tested on packet, linode, ec2, gce"""
import random
import string
import pytest

from conftest import CREDS
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import CloudUnauthorizedError
from mist.api.exceptions import CloudUnavailableError


def test_update_cloud(cloud):
    pre_updated_cloud = cloud
    print('=' * 80)
    print("update credentials")

    # choose the creds of relevant cloud provider
    kwargs = CREDS[cloud.name]
    if not kwargs:
        print('no creds provided')
        return
    print('* for cloud %s, update these creds %s' % (cloud.name,
                                                     list(kwargs.keys())))
    cloud.ctl.update(**kwargs)

    assert cloud == pre_updated_cloud
    print('- edit cloud credentials succeeded for cloud %s' % cloud.name)

    valid_kwargs = kwargs

    kwargs = dict((k + 'a', v) for k, v in list(valid_kwargs.items()))
    print('* test invalid creds keys %s ' % list(kwargs.keys()))
    print('- expected to raise BadRequestError')
    with pytest.raises(BadRequestError):
        cloud.ctl.update(fail_on_error=True,
                         fail_on_invalid_params=True, **kwargs)

    print('* test invalid credentials values')
    kwargs = dict((k, 'aa' + v) for k, v in list(valid_kwargs.items()))

    if cloud.name in ['packet']:
        print('- expected to raise CloudUnauthorizedError')
        with pytest.raises(CloudUnauthorizedError):
            cloud.ctl.update(fail_on_error=True,
                             fail_on_invalid_params=True, **kwargs)

    if cloud.name in ['gce']:
        print('- expected to raise CloudUnavailableError')
        with pytest.raises(CloudUnavailableError):
            cloud.ctl.update(fail_on_error=True,
                             fail_on_invalid_params=True, **kwargs)

    if cloud.name in ['ec2', 'linode']:
        print('- expected to raise CloudUnauthorizedError')
        with pytest.raises(CloudUnauthorizedError):
            cloud.ctl.update(fail_on_error=True,
                             fail_on_invalid_params=True, **kwargs)


def test_rename_cloud(cloud):
    print('rename cloud with name %s' % cloud.name)

    random_word = ''.join(random.choice(string.lowercase) for i in range(6))
    new_name = str(cloud.name) + '_' + random_word
    print('new name is %s' % new_name)

    cloud.ctl.rename(new_name)
    assert new_name == cloud.name
    print('rename cloud succeeded')
