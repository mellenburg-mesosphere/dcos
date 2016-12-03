"""Various helpers for test runners and integration testing directly
"""
import atexit
import copy
import functools
import logging
import os
import tempfile
import time
from collections import namedtuple
from urllib.parse import urlsplit, urlunsplit

import requests
import retrying
from botocore.exceptions import ClientError, WaiterError

Host = namedtuple('Host', ['private_ip', 'public_ip'])
SshInfo = namedtuple('SshInfo', ['user', 'home_dir'])


def path_join(p1, p2):
    return '{}/{}'.format(p1.rstrip('/'), p2.lstrip('/'))


class DcosUser:
    """A lightweight user representation."""
    def __init__(self, auth_json: dict):
        self.auth_json = auth_json
        self.auth_token = None
        self.auth_cookie = None
        self.auth = None

    def authenticate(self, cluster):
        logging.info('Attempting authentication')
        # explicitly use a session with no user authentication for requesting auth headers
        r = cluster.post('/acs/api/v1/auth/login', json=self.auth_json, auth=None)
        r.raise_for_status()
        logging.info('Received authorization blob: {}'.format(r.json()))
        self.auth_token = r.json()['token']
        self.auth_cookie = r.cookies['dcos-acs-auth-cookie']
        logging.info('Authentication successful')
        # Set requests auth
        self.auth = DcosAuth('token={}'.format(self.auth_token))


class DcosAuth(requests.auth.AuthBase):
    def __init__(self, auth_str):
        self.auth_str = auth_str

    def __call__(self, r):
        r.headers['Authorization'] = self.auth_str
        return r


class Url:
    """URL abstraction to allow convenient substitution of URL anatomy
    """
    def __init__(self, scheme, host, path, query, fragment, port):
        self.scheme = scheme
        self.host = host
        self.path = path
        self.query = query
        self.fragment = fragment
        self.port = port

    @classmethod
    def from_string(cls, url_str):
        u = urlsplit(url_str)
        if ':' in u.netloc:
            s = u.netloc.split(':')
            host = s[0]
            port = s[1]
        else:
            host = u.netloc
            port = None
        return cls(u.scheme, host, u.path, u.query, u.fragment, port)

    @property
    def netloc(self):
        return '{}:{}'.format(self.host, self.port) if self.port else self.host

    def __str__(self):
        return urlunsplit((
            self.scheme,
            self.netloc,
            self.path,
            self.query if self.query else '',
            self.fragment if self.fragment else ''))

    def get_url(self, scheme=None, host=None, path=None, query=None, fragment=None, port=None):
        """return new Url with any component replaced
        """
        return Url(
            scheme if scheme is not None else self.scheme,
            host if host is not None else self.host,
            path if path is not None else self.path,
            query if query is not None else self.query,
            fragment if fragment is not None else self.fragment,
            port if port is not None else self.port)


class ApiClient:
    """utilizes requests.session with some URL handling to remove boilerplate for making
    cluster requests. Can also be used to bind advanced helper methods of a given service
    """
    def __init__(self, url: Url, get_node_port=None):
        """
        Args:
            url: Url object to which requests will be made
        Keyword Args:
            get_node_port: a callback that takes a node string as an argument. This function
                must return the port for that string. Intended for communicating with an API
                that uses different ports on different hosts (e.g. AdminRouter, Mesos )
        """
        self.url = url
        self.session = requests.Session()
        self._get_node_port = get_node_port

    def get_client(self, scheme=None, host=None, path=None, query=None, fragment=None, port=None):
        """Takes the same arguments as Url.get_url
        """
        clone = copy.deepcopy(self)
        clone.url = self.url.get_url(scheme=scheme, host=host, path=path, query=query, fragment=fragment, port=port)
        return clone

    def api_request(self, method, path_ex, scheme=None, host=None, query=None,
                    fragment=None, path=None, port=None, node=None, **kwargs):
        """ Direct wrapper for session.request. Returns request.Response
        Args:
            method: the HTTP request method to be used
            path_ex: the extension to the path that is set as the default Url

        Keyword Args:
            All the named keyword args except node are identical to Url.get_url
            node: can only be used if a get_node_port is set.
            **kwargs: anything that can be passed to requests.request
        """
        if node is not None:
            assert port is None, 'node is intended to retrieve port; cannot set both simultaneously'
            assert host is None, 'node is intended to retrieve host; cannot set both simultaneously'
            assert self._get_node_port is not None, 'get_node_netloc must be specified for this ApiClient!'
            port = self._get_node_port(node)
            # do not explicitly declare default ports
            host = node
            if (port == 80 and self.url.scheme == 'http') or (port == 443 and self.url.scheme == 'https'):
                port = None

        final_path = path_join(path if path else self.url.path, path_ex)

        request_url = str(self.url.get_url(
            scheme=scheme,
            host=host,
            path=final_path,
            query=query,
            fragment=fragment,
            port=port))

        logging.info('Request method {}: {}'.format(method, request_url))

        return self.session.request(method, request_url, **kwargs)

    @property
    def get(self):
        return functools.partial(self.api_request, 'get')

    @property
    def post(self):
        return functools.partial(self.api_request, 'post')

    @property
    def put(self):
        return functools.partial(self.api_request, 'put')

    @property
    def delete(self):
        return functools.partial(self.api_request, 'delete')

    @property
    def patch(self):
        return functools.partial(self.api_request, 'patch')

    @property
    def options(self):
        return functools.partial(self.api_request, 'options')

    @property
    def head(self):
        return functools.partial(self.api_request, 'head')


def retry_boto_rate_limits(boto_fn, wait=2, timeout=60 * 60):
    """Decorator to make boto functions resilient to AWS rate limiting and throttling.
    If one of these errors is encounterd, the function will sleep for a geometrically
    increasing amount of time
    """
    @functools.wraps(boto_fn)
    def ignore_rate_errors(*args, **kwargs):
        local_wait = copy.copy(wait)
        local_timeout = copy.copy(timeout)
        while local_timeout > 0:
            next_time = time.time() + local_wait
            try:
                return boto_fn(*args, **kwargs)
            except (ClientError, WaiterError) as e:
                if isinstance(e, ClientError):
                    error_code = e.response['Error']['Code']
                elif isinstance(e, WaiterError):
                    error_code = e.last_response['Error']['Code']
                else:
                    raise
                if error_code in ['Throttling', 'RequestLimitExceeded']:
                    logging.warn('AWS API Limiting error: {}'.format(error_code))
                    logging.warn('Sleeping for {} seconds before retrying'.format(local_wait))
                    time_to_next = next_time - time.time()
                    if time_to_next > 0:
                        time.sleep(time_to_next)
                    else:
                        local_timeout += time_to_next
                    local_timeout -= local_wait
                    local_wait *= 2
                    continue
                raise
        raise Exception('Rate-limit timeout encountered waiting for {}'.format(boto_fn.__name__))
    return ignore_rate_errors


def wait_for_pong(url, timeout):
    """continually GETs /ping expecting JSON pong:true return
    Does not stop on exception as connection error may be expected
    """
    @retrying.retry(wait_fixed=3000, stop_max_delay=timeout * 1000)
    def ping_app():
        logging.info('Attempting to ping test application')
        r = requests.get('http://{}/ping'.format(url), timeout=10)
        r.raise_for_status()
        assert r.json() == {"pong": True}, 'Unexpected response from server: ' + repr(r.json())
    ping_app()


def wait_for_len(fetch_fn, target_count, timeout):
    """Will call fetch_fn every 10s, get len() on the result and repeat until it is
    equal to target count or timeout (in seconds) has been reached
    """
    @retrying.retry(wait_fixed=10000, stop_max_delay=timeout * 1000,
                    retry_on_result=lambda res: res is False,
                    retry_on_exception=lambda ex: False)
    def check_for_match():
        items = fetch_fn()
        count = len(items)
        logging.info('Waiting for len()=={}. Current count: {}. Items: {}'.format(target_count, count, repr(items)))
        if count != target_count:
            return False
    check_for_match()


def session_tempfile(data):
    """Writes bites to a named temp file and returns its path
    the temp file will be removed when the interpreter exits
    """
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        temp_path = f.name

    def remove_file():
        if os.path.exists(temp_path):
            os.remove(temp_path)

    # Attempt to remove the file upon normal interpreter exit.
    atexit.register(remove_file)
    return temp_path


def lazy_property(property_fn):
    cache_name = '{}_cached'.format(property_fn.__name__)

    @property
    @functools.wraps(property_fn)
    def _lazy_prop(self):
        if not hasattr(self, cache_name):
            setattr(self, cache_name, property_fn(self))
        return getattr(self, cache_name)
    return _lazy_prop
