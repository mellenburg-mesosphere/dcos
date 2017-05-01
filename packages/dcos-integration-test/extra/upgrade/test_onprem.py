"""Integration test for onprem DC/OS upgraded from latest stable.
"""
import logging
import os
import pprint
import random
import uuid
from typing import Iterator, Tuple

import pytest
import retrying
from retrying import retry, RetryError

import ssh
import test_util.onprem
from test_util.helpers import marathon_app_id_to_mesos_dns_subdomain

from test_helpers import expanded_config

log = logging.getLogger(__name__)

TEST_APP_NAME_FMT = 'upgrade-{}'


@pytest.fixture
def ssher():
    if 'DCOS_SSH_USER' not in os.environ or 'DCOS_SSH_PRIVATE_KEY' not in os.environ:
        pytest.skip('DCOS_SSH_USER and DCOS_SSH_PRIVATE_KEY must be set in environment to run this test!')
    return ssh.ssher.Ssher(os.getenv('DCOS_SSH_USER'), os.getenv('DCOS_SSH_PRIVATE_KEY'))


@pytest.fixture(scope='session')
def viplisten_app():
    return {
        "id": '/' + TEST_APP_NAME_FMT.format('viplisten-' + uuid.uuid4().hex),
        "cmd": '/usr/bin/nc -l -p $PORT0',
        "cpus": 0.1,
        "mem": 32,
        "instances": 1,
        "container": {
            "type": "MESOS",
            "docker": {
              "image": "alpine:3.5"
            }
        },
        'portDefinitions': [{
            'labels': {
                'VIP_0': '/viplisten:5000'
            }
        }],
        "healthChecks": [{
            "protocol": "COMMAND",
            "command": {
                "value": "/usr/bin/nslookup viplisten.marathon.l4lb.thisdcos.directory && pgrep -x /usr/bin/nc"
            },
            "gracePeriodSeconds": 300,
            "intervalSeconds": 60,
            "timeoutSeconds": 20,
            "maxConsecutiveFailures": 3
        }]
    }


@pytest.fixture(scope='session')
def viptalk_app():
    return {
        "id": '/' + TEST_APP_NAME_FMT.format('viptalk-' + uuid.uuid4().hex),
        "cmd": "/usr/bin/nc viplisten.marathon.l4lb.thisdcos.directory 5000 < /dev/zero",
        "cpus": 0.1,
        "mem": 32,
        "instances": 1,
        "container": {
            "type": "MESOS",
            "docker": {
              "image": "alpine:3.5"
            }
        },
        "healthChecks": [{
            "protocol": "COMMAND",
            "command": {
                "value": "pgrep -x /usr/bin/nc && sleep 5 && pgrep -x /usr/bin/nc"
            },
            "gracePeriodSeconds": 300,
            "intervalSeconds": 60,
            "timeoutSeconds": 20,
            "maxConsecutiveFailures": 3
        }]
    }


@pytest.fixture(scope='session')
def healthcheck_app():
    # HTTP healthcheck app to make sure tasks are reachable during the upgrade.
    # If a task fails its healthcheck, Marathon will terminate it and we'll
    # notice it was killed when we check tasks on exit.
    return {
        "id": '/' + TEST_APP_NAME_FMT.format('healthcheck-' + uuid.uuid4().hex),
        "cmd": "python3 -m http.server 8080",
        "cpus": 0.5,
        "mem": 32.0,
        "instances": 1,
        "container": {
            "type": "DOCKER",
            "docker": {
                "image": "python:3",
                "network": "BRIDGE",
                "portMappings": [
                    {"containerPort": 8080, "hostPort": 0}
                ]
            }
        },
        "healthChecks": [
            {
                "protocol": "HTTP",
                "path": "/",
                "portIndex": 0,
                "gracePeriodSeconds": 5,
                "intervalSeconds": 1,
                "timeoutSeconds": 5,
                "maxConsecutiveFailures": 1
            }
        ],
    }


@pytest.fixture(scope='session')
def dns_app(healthcheck_app):
    # DNS resolution app to make sure DNS is available during the upgrade.
    # Periodically resolves the healthcheck app's domain name and logs whether
    # it succeeded to a file in the Mesos sandbox.
    healthcheck_app_id = healthcheck_app['id'].lstrip('/')
    return {
        "id": '/' + TEST_APP_NAME_FMT.format('dns-' + uuid.uuid4().hex),
        "cmd": """
while true
do
    printf "%s " $(date --utc -Iseconds) >> $MESOS_SANDBOX/$DNS_LOG_FILENAME
    if host -W $TIMEOUT_SECONDS $RESOLVE_NAME
    then
        echo SUCCESS >> $MESOS_SANDBOX/$DNS_LOG_FILENAME
    else
        echo FAILURE >> $MESOS_SANDBOX/$DNS_LOG_FILENAME
    fi
    sleep $INTERVAL_SECONDS
done
""",
        "env": {
            'RESOLVE_NAME': marathon_app_id_to_mesos_dns_subdomain(healthcheck_app_id) + '.marathon.mesos',
            'DNS_LOG_FILENAME': 'dns_resolve_log.txt',
            'INTERVAL_SECONDS': '1',
            'TIMEOUT_SECONDS': '1',
        },
        "cpus": 0.5,
        "mem": 32.0,
        "instances": 1,
        "container": {
            "type": "DOCKER",
            "docker": {
                "image": "branden/bind-utils",
                "network": "BRIDGE",
            }
        },
        "dependencies": [healthcheck_app_id],
    }


@retrying.retry(
    wait_fixed=(1 * 1000),
    stop_max_delay=(120 * 1000),
    retry_on_result=lambda x: not x)
def wait_for_dns(dcos_api, hostname):
    """Return True if Mesos-DNS has at least one entry for hostname."""
    hosts = dcos_api.get('/mesos_dns/v1/hosts/' + hostname).json()
    return any(h['host'] != '' and h['ip'] != '' for h in hosts)


def get_master_task_state(dcos_api, task_id):
    """Returns the JSON blob associated with the task from /master/state."""
    response = dcos_api.get('/mesos/master/state')
    response.raise_for_status()
    master_state = response.json()

    for framework in master_state['frameworks']:
        for task in framework['tasks']:
            if task_id in task['id']:
                return task


def app_task_ids(dcos_api, app_id):
    """Return a list of Mesos task IDs for app_id's running tasks."""
    assert app_id.startswith('/')
    response = dcos_api.marathon.get('/v2/apps' + app_id + '/tasks')
    response.raise_for_status()
    tasks = response.json()['tasks']
    return [task['id'] for task in tasks]


def parse_dns_log(dns_log_content):
    """Return a list of (timestamp, status) tuples from dns_log_content."""
    dns_log = [line.strip().split(' ') for line in dns_log_content.strip().split('\n')]
    if any(len(entry) != 2 or entry[1] not in ['SUCCESS', 'FAILURE'] for entry in dns_log):
        message = 'Malformed DNS log.'
        log.debug(message + ' DNS log content:\n' + dns_log_content)
        raise Exception(message)
    return dns_log


@retry(
    wait_fixed=1000 * 5,
    stop_max_delay=1000 * 60 * 5,
    retry_on_result=lambda result: result is False)
def wait_for_mesos_metric(cluster, host, key, value):
    """Return True when host's Mesos metric key is equal to value."""
    response = cluster.get('/metrics/snapshot', mesos_node=host)
    return response.json().get(key) == value


@pytest.fixture(scope='session')
def setup_workload(dcos_api_session, viptalk_app, viplisten_app, healthcheck_app, dns_app):
    # TODO(branden): We ought to be able to deploy these apps concurrently. See
    # https://mesosphere.atlassian.net/browse/DCOS-13360.
    dcos_api_session.marathon.deploy_app(viplisten_app)
    dcos_api_session.marathon.ensure_deployments_complete()
    # viptalk app depends on VIP from viplisten app, which may still fail
    # the first try immediately after ensure_deployments_complete
    dcos_api_session.marathon.deploy_app(viptalk_app, ignore_failed_tasks=True)
    dcos_api_session.marathon.ensure_deployments_complete()

    dcos_api_session.marathon.deploy_app(healthcheck_app)
    dcos_api_session.marathon.ensure_deployments_complete()
    # This is a hack to make sure we don't deploy dns_app before the name it's
    # trying to resolve is available.
    wait_for_dns(dcos_api_session, dns_app['env']['RESOLVE_NAME'])
    dcos_api_session.marathon.deploy_app(dns_app, check_health=False)
    dcos_api_session.marathon.ensure_deployments_complete()

    test_apps = [healthcheck_app, dns_app, viplisten_app, viptalk_app]
    test_app_ids = [app['id'] for app in test_apps]

    tasks_start = {app_id: sorted(app_task_ids(dcos_api_session, app_id)) for app_id in test_app_ids}
    log.debug('Test app tasks at start:\n' + pprint.pformat(tasks_start))

    for app in test_apps:
        assert app['instances'] == len(tasks_start[app['id']])

    # Save the master's state of the task to compare with
    # the master's view after the upgrade.
    # See this issue for why we check for a difference:
    # https://issues.apache.org/jira/browse/MESOS-1718
    task_state_start = get_master_task_state(dcos_api_session, tasks_start[test_app_ids[0]][0])

    return test_app_ids, tasks_start, task_state_start


def dcos_generate_config_path(base_dir):
    return os.path.join(base_dir, 'dcos_generate_config.sh')


def run_docker_container_daemon(ssher, container_name, image, docker_run_args):
    ssher.command(
        ['docker', 'run', '--name', container_name, '--detach=true'] + docker_run_args + [image])


@pytest.fixture
def bootstrap_host():
    assert 'DCOS_BOOTSTRAP_HOST' in os.environ
    return os.getenv('DCOS_BOOTSTRAP_HOST')


@pytest.fixture
def installer_url():
    assert 'DCOS_UPGRADE_INSTALLER_URL' in os.environ
    return os.getenv('DCOS_UPGRADE_INSTALLER_URL')


@pytest.fixture(scope='session')
def bootstrap_home(ssher, bootstrap_host):
    return ssher.get_home_dir(bootstrap_host)


def config_overrides() -> Iterator[Tuple[str, str]]:
    prefix = 'DCOS_UPGRADE_TEST_CONFIG_'
    for env_var in os.environ:
        if env_var.startswith(prefix):
            yield env_var.replace(prefix, ''), os.environ[env_var]


@pytest.skipif(expanded_config['provider'] != 'onprem', reason='Upgrade only supported for onprem provider')
@pytest.fixture(scope='session')
def upgrade_dcos(dcos_api_session, ssher, installer_path, bootstrap_home, config_overrides):
    """
    """
    # check to see if previous installer is running and terminate if necessary
    version = dcos_api_session.get_version()
    ssher.command(['bash', '-c', "'docker ps -a | grep dcos-genconf | xargs docker kill'"])
    installer_path = dcos_generate_config_path(ssher.get_home_dir(bootstrap_host))
    test_util.onprem.download_dcos_installer(ssher, bootstrap_host, installer_path, installer_url)
    # start the bootstrap zk to support upgrade
    # TODO: check if this is running first
    run_docker_container_daemon(
        ssher,
        'dcos-bootstrap-zk',
        'jplock/zookeeper',
        ['--publish=2181:2181', '--publish=2888:2888', '--publish=3888:3888'])
    # inject current cluster, ssh user, ssh key, bootstrap zk, and then override wih user-defined
    # run genconf
    # bootstrap_url = 'http://' + bootstrap_host
    upgrade_script_path = ssher.command(
        ['bash', 'dcos_generate_config.sh', "--generate-node-upgrade-script " + version]
    ).decode('utf-8').splitlines()[-1].split("Node upgrade script URL: ", 1)[1]
    # Remove docker (and associated journald) restart from the install
    # script. This prevents Docker-containerized tasks from being killed
    # during agent upgrades.
    ssher.command([
        'sudo', 'sed', '-i',
        '-e', '"s/systemctl restart systemd-journald//g"',
        '-e', '"s/systemctl restart docker//g"',
        bootstrap_home + '/genconf/serve/dcos_install.sh'])
    # Start nginx to host upgrade files
    run_docker_container_daemon(
        ssher,
        'dcos-bootstrap-nginx',
        'nginx',
        ['--publish=80:80', '--volume={}/genconf/serve:/usr/share/nginx/html:ro'.format(bootstrap_home)])
    # upgrading can finally start
    upgrade_ordering = [
        # Upgrade masters in a random order.
        ('master', 'master', random.sample(dcos_api_session.masters, len(dcos_api_session.masters))),
        ('slave', 'agent', dcos_api_session.agents),
        ('slave_public', 'public agent', dcos_api_session.public_agents)]
    logging.info('\n'.join(
        ['Upgrade plan:'] +
        ['{} ({})'.format(host, role_name) for _, role_name, hosts in upgrade_ordering for host in hosts]
    ))
    for role, role_name, hosts in upgrade_ordering:
        log.info('Upgrading {} nodes: {}'.format(role_name, repr(hosts)))
        for host in hosts:
            log.info('Upgrading {}: {}'.format(role_name, repr(host)))
            with ssher.tunnel(bootstrap_host) as tunnel:
                tunnel.command([
                    'curl',
                    '--silent',
                    '--verbose',
                    '--show-error',
                    '--fail',
                    '--location',
                    '--keepalive-time', '2',
                    '--retry', '20',
                    '--speed-limit', '100000',
                    '--speed-time', '60',
                    '--remote-name', upgrade_script_path])
                tunnel.command(['sudo', 'bash', 'dcos_node_upgrade.sh'])
                wait_metric = {
                    'master': 'registrar/log/recovered',
                    'slave': 'slave/registered',
                    'slave_public': 'slave/registered',
                }[role]
                log.info('Waiting for {} to rejoin the cluster...'.format(role_name))
                try:
                    wait_for_mesos_metric(dcos_api_session, host, wait_metric, 1)
                except RetryError as exc:
                    raise Exception(
                        'Timed out waiting for {} to rejoin the cluster after upgrade: {}'.
                        format(role_name, repr(host))
                    ) from exc


@pytest.mark.usefixtures(upgrade_dcos)
class TestUpgrade:
    def test_marathon_app_tasks_survive(self, dcos_api_session, setup_workload):
        tasks_end = {app_id: sorted(app_task_ids(dcos_api_session, app_id)) for app_id in setup_workload[0]}
        log.debug('Test app tasks at end:\n' + pprint.pformat(tasks_end))
        assert setup_workload[1] == tasks_end

    def test_mesos_task_state_remains_consistent(self, dcos_api_session, setup_workload):
        task_state_end = self.get_master_task_state(dcos_api_session, self.tasks_start[self.test_app_ids[0]][0])
        assert setup_workload[2] == task_state_end

    def test_app_dns_survive(self, dcos_api_session, dns_app):
        marathon_framework_id = dcos_api_session.marathon.get('/v2/info').json()['frameworkId']
        dns_app_task = dcos_api_session.marathon.get('/v2/apps' + dns_app['id'] + '/tasks').json()['tasks'][0]
        dns_log = parse_dns_log(dcos_api_session.mesos_sandbox_file(
            dns_app_task['slaveId'],
            marathon_framework_id,
            dns_app_task['id'],
            dns_app['env']['DNS_LOG_FILENAME']))
        dns_failure_times = [entry[0] for entry in dns_log if entry[1] != 'SUCCESS']
        assert len(dns_failure_times) == 0, 'Failed to resolve Marathon app hostname {hostname} at least once' \
            'Hostname failed to resolve at these times:\n{failures}'.format(
                hostname=dns_app['env']['RESOLVE_NAME'],
                failures='\n'.join(dns_failure_times))
