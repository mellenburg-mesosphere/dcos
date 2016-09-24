import logging
import copy
import uuid
from collections import namedtuple

import requests
import retrying

Host = namedtuple('Host', ['private_ip', 'public_ip'])
SshInfo = namedtuple('SshInfo', ['user', 'home_dir'])

TEST_APP_NAME_FMT = '/integration-test-{}'


class AuthedUser:
    """A lightweight user representation."""
    def __init__(self, auth_json):
        self.auth_json = auth_json
        self.auth_header = None
        self.auth_token = None
        self.auth_cookie = None

    def authenticate(self, cluster):
        r = cluster.post(path='/acs/api/v1/auth/login', user=None, json=self.auth_json)
        if r.status_code >= 400:
            return False
        self.auth_token = r.json()['token']
        self.auth_header = {'Authorization': 'token={}'.format(self.auth_token)}
        self.auth_cookie = r.cookies['dcos-acs-auth-cookie']
        return True


def wait_for_pong(url, timeout):
    """continually GETs /ping expecting JSON pong:true return
    Does not stop on exception as connection error may be expected
    """
    @retrying.retry(wait_fixed=3000, stop_max_delay=timeout * 1000)
    def ping_app():
        logging.info('Attempting to ping test application')
        r = requests.get('http://{}/ping'.format(url), timeout=10)
        assert r.ok, 'Bad response from test server: ' + str(r.status_code)
        assert r.json() == {"pong": True}, 'Unexpected response from server: ' + repr(r.json())
    ping_app()


def wait_for_len(fetch_fn, target_count, timeout):
    """Will call fetch_fn, get len() on the result and repeat until it is
    equal to target count or timeout (in seconds) has been reached
    """
    @retrying.retry(wait_fixed=3000, stop_max_delay=timeout * 1000,
                    retry_on_result=lambda res: res is False,
                    retry_on_exception=lambda ex: False)
    def check_for_match():
        items = fetch_fn()
        count = len(items)
        logging.info('Waiting for len({})=={}. Current count: {}. Items: {}'.format(
            fetch_fn.__name__, target_count, count, repr(items)))
        if count != target_count:
            return False
    check_for_match()


def get_test_app(custom_port=False):
    test_uuid = uuid.uuid4().hex
    app = copy.deepcopy({
        'id': TEST_APP_NAME_FMT.format(test_uuid),
        'cpus': 0.1,
        'mem': 32,
        'instances': 1,
        # NOTE: uses '.' rather than `source`, since `source` only exists in bash and this is
        # run by sh
        'cmd': '. /opt/mesosphere/environment.export && /opt/mesosphere/bin/python '
               '/opt/mesosphere/active/dcos-integration-test/python_test_server.py ',
        'env': {'DCOS_TEST_UUID': test_uuid},
        'healthChecks': [{
            'protocol': 'HTTP',
            'path': '/ping',
            'portIndex': 0,
            'gracePeriodSeconds': 5,
            'intervalSeconds': 10,
            'timeoutSeconds': 10,
            'maxConsecutiveFailures': 3}]})

    if not custom_port:
        app['cmd'] += '$PORT0'
        app['portDefinitions'] = [{
            "protocol": "tcp",
            "port": 0,
            "name": "test"}]

    return app, test_uuid


def get_test_app_in_docker(ip_per_container):
    app, test_uuid = get_test_app(custom_port=True)
    assert 'portDefinitions' not in app
    app['cmd'] += '9080'  # Fixed port for inside bridge networking or IP per container
    app['container'] = {
        'type': 'DOCKER',
        'docker': {
            # TODO(cmaloney): Switch to alpine with glibc
            'image':
                'debian:jessie',
                'portMappings': [{
                    'hostPort': 0,
                    'containerPort': 9080,
                    'protocol': 'tcp',
                    'name': 'test',
                    'labels': {}}]},
            'volumes': [{
                'containerPath': '/opt/mesosphere',
                'hostPath': '/opt/mesosphere',
                'mode': 'RO'}]}

    if ip_per_container:
        app['container']['docker']['network'] = 'USER'
        app['ipAddress'] = {'networkName': 'dcos'}
    else:
        app['container']['docker']['network'] = 'BRIDGE'

    return app, test_uuid
