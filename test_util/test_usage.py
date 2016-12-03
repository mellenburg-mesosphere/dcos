"""Tests for verifying key functionality of utilities
"""
import pytest

from test_util.cluster_api import ClusterApi, get_args_from_env
from test_util.helpers import ApiClient, DcosUser, Url


class MockResponse:
    def __init__(self, cluster):
        self.cookies = {'dcos-acs-auth-cookie': 'foo'}
        cluster.session.cookies.update(self.cookies)

    def raise_for_status(self):
        pass

    def json(self):
        return {'token': 'bar'}


@pytest.fixture
def trivial_env(monkeypatch):
    monkeypatch.setenv('DCOS_DNS_ADDRESS', 'http://mydcos.dcos')
    monkeypatch.setenv('MASTER_HOSTS', '127.0.0.1,0.0.0.0')
    monkeypatch.setenv('PUBLIC_MASTER_HOSTS', '127.0.0.1,0.0.0.0')
    monkeypatch.setenv('SLAVE_HOSTS', '127.0.0.1,0.0.0.0')
    monkeypatch.setenv('PUBLIC_SLAVE_HOSTS', '127.0.0.1,0.0.0.0')
    monkeypatch.setenv('DNS_SEARCH', 'false')
    monkeypatch.setenv('DCOS_PROVIDER', 'onprem')


def test_make_user_session(monkeypatch, trivial_env):
    monkeypatch.setattr(ClusterApi, 'post', lambda cluster, *args, **kwargs: MockResponse(cluster))
    user_1 = DcosUser({'foo': 'bar'})
    user_2 = DcosUser({'baz': 'qux'})
    args = get_args_from_env()
    args['web_auth_default_user'] = user_1
    cluster_none = ClusterApi(**args)
    # make user session from no auth
    cluster_1 = cluster_none.get_user_session(user_1)
    assert cluster_1.session.auth.auth_str == 'token=bar'
    assert cluster_1.session.cookies.get('dcos-acs-auth-cookie') == 'foo'
    # make user session from user
    cluster_2 = cluster_1.get_user_session(user_2)
    assert cluster_2.session.auth.auth_str == 'token=bar'
    assert cluster_2.session.cookies.get('dcos-acs-auth-cookie') == 'foo'
    # make no auth session from use session
    cluster_none = cluster_2.get_user_session(None)
    assert cluster_none.session.auth is None
    assert len(cluster_none.session.cookies.items()) == 0


class MyTestClient(ApiClient):
    def api_request(self, *args, **kwargs):
        r = super().api_request(*args, **kwargs)
        if r.status_code == 404:
            # arg0 is method, arg1 is path_ex
            new_args = list(args)
            new_args[1] = ''
            args = tuple(new_args)
            r = super().api_request(*args, **kwargs)
        return r


def test_api_client_wrapping():
    t = MyTestClient(Url.from_string('http://www.google.com'))
    r = t.get('thispageprobablydoesntexisthatwouldbereallysupercrazyifitdid')
    assert r.status_code == 200
