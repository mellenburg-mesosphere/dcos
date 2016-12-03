import pytest


@pytest.fixture(scope='module')
def auth_cluster(cluster):
    if cluster.session.auth is None:
        pytest.skip("Skipped because not running against cluster with auth.")
    return cluster


def test_adminrouter_access_control_enforcement(auth_cluster, noauth_cluster):
    r = noauth_cluster.get('/acs/api/v1')
    assert r.status_code == 401
    assert r.headers['WWW-Authenticate'] in ('acsjwt', 'oauthjwt')
    # Make sure that this is UI's error page body,
    # including some JavaScript.
    assert '<html>' in r.text
    assert '</html>' in r.text
    assert 'window.location' in r.text
    # Verify that certain locations are forbidden to access
    # when not authed, but are reachable as superuser.
    for path in ('/mesos_dns/v1/config', '/service/marathon/', '/mesos/'):
        r = noauth_cluster.get(path)
        assert r.status_code == 401
        r = auth_cluster.get(path)
        assert r.status_code == 200

    # Test authentication with auth cookie instead of Authorization header.
    authcookie = {
        'dcos-acs-auth-cookie': auth_cluster.web_auth_default_user.auth_cookie}
    r = noauth_cluster.get(
        '/service/marathon/',
        cookies=authcookie)
    assert r.status_code == 200


def test_logout(auth_cluster):
    """Test logout endpoint. It's a soft logout, instructing
    the user agent to delete the authentication cookie, i.e. this test
    does not have side effects on other tests.
    """
    r = auth_cluster.get('/acs/api/v1/auth/logout')
    cookieheader = r.headers['set-cookie']
    assert 'dcos-acs-auth-cookie=;' in cookieheader or 'dcos-acs-auth-cookie="";' in cookieheader
    assert 'expires' in cookieheader.lower()
