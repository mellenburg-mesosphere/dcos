"""Tests for verifying key functionality of utilities
"""
import pytest
import requests

from test_util.dcos_api_session import DcosApiSession, DcosUser, get_args_from_env
from test_util.helpers import ApiClientSession, Url


class MockResponse:
    def __init__(self):
        self.cookies = {'dcos-acs-auth-cookie': 'foo'}

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


def test_make_user_session(monkeypatch, trivial_env):
    monkeypatch.setattr(requests, 'post', lambda *args, **kwargs: MockResponse())
    monkeypatch.setattr(DcosApiSession, 'wait_for_dcos', lambda self: True)
    user_1 = DcosUser({'foo': 'bar'})
    user_2 = DcosUser({'baz': 'qux'})
    args = get_args_from_env()
    args['auth_user'] = user_1
    cluster_none = DcosApiSession(**args)
    # make user session from no auth
    cluster_1 = cluster_none.get_user_session(user_1)
    assert cluster_1.session.auth.auth_token == 'bar'
    # Add a cookie to this session to make sure it gets cleared
    cluster_1.session.cookies.update({'dcos-acs-auth-cookie': 'foo'})
    # make user session from user
    cluster_2 = cluster_1.get_user_session(user_2)
    assert cluster_2.session.auth.auth_token == 'bar'
    # check cleared cookie
    assert cluster_2.session.cookies.get('dcos-acs-auth-cookie') is None
    # make no auth session from use session
    cluster_none = cluster_2.get_user_session(None)
    assert cluster_none.session.auth is None
    assert len(cluster_none.session.cookies.items()) == 0


class MyTestClient(ApiClientSession):
    """Test wrapper that will retry the request with a deleted path
    when the first request returns 404
    """
    def api_request(self, method, path_extension, **kwargs):
        r = super().api_request(method, path_extension, **kwargs)
        if r.status_code == 404:
            r = super().api_request(method, '', **kwargs)
        return r


def test_api_client_wrapping():
    t = MyTestClient(Url.from_string('http://www.google.com'))
    r = t.get('thispageprobablydoesntexisthatwouldbereallysupercrazyifitdid')
    assert r.status_code == 200
