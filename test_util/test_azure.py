#!/usr/bin/env python3
"""Deploys DC/OS AWS CF template and then runs integration_test.py

The following environment variables control test procedure:

AGENTS: integer (default=2)
    The number of agents to create in a new cluster.

DCOS_TEMPLATE_URL: string
    The template to be used for deployment testing

DCOS_NAME: string
    Instead of providing a template, supply the name (or id) of an already
    existing cluster

DCOS_SSH_KEY_PATH: string
    path for the SSH key to be used with a preexiting cluster.
    Defaults to 'default_ssh_key'

CI_FLAGS: string (default=None)
    If provided, this string will be passed directly to py.test as in:
    py.test -vv CI_FLAGS integration_test.py

TEST_ADD_ENV_*: string (default=None)
    Any number of environment variables can be passed to integration_test.py if
    prefixed with 'TEST_ADD_ENV_'. The prefix will be removed before passing
"""
import logging
import os
import sys

from contextlib import ExitStack

from gen.calc import calculate_environment_variable
from ssh.tunnel import Tunnel
from test_util.azure import AzureWrapper, TemplateDeployment
from test_util.helpers import random_id
from test_util.test_runner import integration_test

LOGGING_FORMAT = '[%(asctime)s|%(name)s|%(levelname)s]: %(message)s'
logging.basicConfig(format=LOGGING_FORMAT, level=logging.DEBUG)
log = logging.getLogger(__name__)


def check_environment():
    """Test uses environment variables to play nicely with TeamCity config templates
    Grab all the environment variables here to avoid setting params all over

    Returns:
        object: generic object used for cleanly passing options through the test

    Raises:
        AssertionError: if any environment variables or resources are missing
            or do not conform
    """
    options = type('Options', (object,), {})()

    # Required
    options.public_ssh_key = calculate_environment_variable('AZURE_PUBLIC_SSH_KEY')
    options.subscription_id = calculate_environment_variable('AZURE_SUBSCRIPTION_ID')
    options.tenant_id = calculate_environment_variable('AZURE_TENANT_ID')
    options.client_id = calculate_environment_variable('AZURE_CLIENT_ID')
    options.client_secret = calculate_environment_variable('AZURE_CLIENT_SECRET')
    options.template_url = calculate_environment_variable('DCOS_TEMPLATE_URL')

    # Provided if not set
    options.name = os.getenv('DCOS_NAME', 'testing-{}'.format(random_id(10)))
    options.ssh_key_path = os.getenv('DCOS_SSH_KEY_PATH', 'ssh_key')
    options.location = os.getenv('AZURE_LOCATION', 'East US')
    options.linux_user = os.getenv('AZURE_LINUX_USER', 'dcos')
    # Prefixes must not begin with a number
    options.agent_prefix = os.getenv('AZURE_AGENT_PREFIX', 'test' + random_id(10).lower())
    options.master_prefix = os.getenv('AZURE_MASTER_PREFIX', 'test' + random_id(10).lower())
    options.vm_size = os.getenv('AZURE_VM_SIZE', 'Standard_D2')
    options.num_agents = int(os.getenv('AGENTS', '2'))
    options.name_suffix = os.getenv('AZURE_DCOS_SUFFIX', '12345')
    options.oauth_enabled = os.getenv('AZURE_OAUTH_ENABLED', 'false') == 'true'
    options.vm_diagnostics_enabled = os.getenv('AZURE_VM_DIAGNOSTICS_ENABLED', 'true') == 'true'
    options.azure_cleanup = os.getenv('AZURE_CLEANUP', 'true') == 'true'
    options.ci_flags = os.getenv('CI_FLAGS', '')

    add_env = {}
    prefix = 'TEST_ADD_ENV_'
    for k, v in os.environ.items():
        if k.startswith(prefix):
            add_env[k.replace(prefix, '')] = v
    options.add_env = add_env
    options.pytest_cmd = os.getenv('DCOS_PYTEST_CMD', "py.test -vv -s -rs -m 'not ccm' ") + os.getenv('CI_FLAGS', '')
    return options


def main():
    options = check_environment()
    aw = AzureWrapper(
        options.subscription_id,
        options.tenant_id,
        options.client_id,
        options.client_secret)
    arm_deploy = TemplateDeployment.create(
        azure_wrapper=aw,
        template_uri=options.template_url,
        location=options.location,
        group_name=options.name,
        public_key=options.public_ssh_key,
        master_prefix=options.master_prefix,
        agent_prefix=options.agent_prefix,
        admin_name=options.linux_user,
        oauth_enabled=options.oauth_enabled,
        vm_size=options.vm_size,
        agent_count=options.num_agents,
        name_suffix=options.name_suffix,
        vm_diagnostics_enabled=options.vm_diagnostics_enabled)
    result = 1
    with ExitStack() as stack:
        if options.azure_cleanup:
            stack.push(arm_deploy)
        arm_deploy.wait_for_deployment()
        t = stack.enter_context(
            Tunnel(options.linux_user, options.ssh_key_path, arm_deploy.outputs['masterFQDN'], port=2200))
        result = integration_test(
            tunnel=t,
            test_dir='/home/{}'.format(options.linux_user),
            dcos_dns=arm_deploy.get_master_ips()[0],
            master_list=arm_deploy.get_master_ips(),
            agent_list=arm_deploy.get_private_ips(),
            public_agent_list=arm_deploy.get_public_ips(),
            provider='azure',
            test_dns_search=False,
            add_env=options.add_env,
            pytest_cmd=options.pytest_cmd)
    if result == 0:
        log.info('Test successsful!')
    else:
        logging.warning('Test exited with an error')
    if options.ci_flags:
        result = 0  # Wipe the return code so that tests can be muted in CI
    sys.exit(result)


if __name__ == '__main__':
    main()
