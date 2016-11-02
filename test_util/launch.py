"""DC/OS Launch

Usage:
  dcos-launch config [--config-path=<path>] CONFIG_TYPE
  dcos-launch create [--no-wait] [--dump-info=<path>] CLUSTER_CONFIG_PATH
  dcos-launch (describe|delete) CLUSTER_INFO_PATH


Commands:
  config    Generate default config for either aws, aws-advanced, or onprem
  create    Consumes config and creates an appropriate cluster. A info JSON is
              created for use with describe and delete
  describe  Consumes cluster info JSON and returns IP address in JSON format
  delete    Consumes cluster info JSON and completely deletes the cluster


Options:
  --config-path=<path>  Write path for generated config [default: config.yaml].
  --no-wait             Do not block until cluster is considered up
  --dump-info=<path>    Write path for cluster details [default: cluster_info.json].
"""
import json
import logging
import os
import sys
import yaml
from docopt import docopt
from pkgpanda.util import load_json, load_string, write_json

from test_util.aws import BotoWrapper, DcosCfAdvanced, DcosCfSimple, VpcCfStack
from test_util.cluster import Cluster, install_dcos
from test_util.helpers import random_id, session_tempfile, SshInfo

LOGGING_FORMAT = '[%(asctime)s|%(name)s|%(levelname)s]: %(message)s'
logging.basicConfig(format=LOGGING_FORMAT, level=logging.INFO)
log = logging.getLogger('dcos-launch')

SIMPLE_CF_CONFIG = {
    'provider': 'aws',
    'stack_name': 'DCOS-SimpleCF-{}'.format(random_id(10)),
    'template_url': 'http://s3-us-west-2.amazonaws.com/downloads.dcos.io/dcos/testing/master/cloudformation/single-master.cloudformation.json',  # noqa
    'num_public_agents': 0,
    'num_private_agents': 0,
    'admin_location': '0.0.0.0/0',
    'key_pair_name': 'default'}

ADVANCED_CF_CONFIG = {
    'provider': 'aws',
    'stack_name': 'DCOS-AdvancedCF-{}'.format(random_id(10)),
    'template_url': 'http://s3-us-west-2.amazonaws.com/downloads.dcos.io/dcos/testing/master/cloudformation/coreos-zen-1.json',  # noqa
    'num_public_agents': 0,
    'num_private_agents': 0,
    'key_pair_name': 'default',
    'private_agent_type': 'm3.xlarge',
    'public_agent_type': 'm3.xlarge',
    'master_type': 'm3.xlarge',
    'vpc': None,
    'gateway': None,
    'private_subnet': None,
    'public_subnet': None}

ONPREM_CONFIG = {
    'provider': 'onprem',
    'stack_name': 'DCOS-AWS-OnPrem-{}'.format(random_id(10)),
    'installer_url': 'http://downloads.dcos.io/dcos/testing/master/dcos_generate_config.sh',
    'num_masters': 1,
    'num_public_agents': 0,
    'num_private_agents': 0,
    'admin_location': '0.0.0.0/0',
    'key_pair_name': 'default',
    'instance_type': 'm3.xlarge',
    'instance_os': 'cent-os-7-dcos-prereqs',
    'ssh_key_path': '/this/path/is/required',
    'use_installer_api': True}

DEFAULT_CONFIG = {
    'aws': SIMPLE_CF_CONFIG,
    'aws-advanced': ADVANCED_CF_CONFIG,
    'onprem': ONPREM_CONFIG}


def check_env(keys):
    failed = []
    for k in keys:
        if k in os.environ:
            failed.append(False)
        else:
            log.error('{} must be set!'.format(k))
            failed.append(True)
    if any(failed):
        log.error('Key(s) must be set in environment')
        sys.exit(1)


def convert_host_list(host_list):
    # see Host NamedTuple in test_util.helpers
    return [{'private_ip': h.private_ip, 'public_ip': h.public_ip} for h in host_list]


def is_advanced_template(template):
    return not template.endswith('single-master.cloudformation.json') and \
        not template.endswith('multi-master.cloudformation.json')


def aws_client():
    log.info('Attemping to authenticate with AWS')
    check_env([
        'AWS_REGION',
        'AWS_ACCESS_KEY_ID',
        'AWS_SECRET_ACCESS_KEY'])
    return BotoWrapper(
        os.environ['AWS_REGION'],
        os.environ['AWS_ACCESS_KEY_ID'],
        os.environ['AWS_SECRET_ACCESS_KEY'])


def azure_client():
    log.info('Attempting to authentice with ARM')
    check_env([
        'AZURE_LOCATION',
        'AZURE_CLIENT_ID',
        'AZURE_CLIENT_SECRET',
        'AZURE_TENANT_ID',
        'AZURE_SUBSCRIPTION_ID'])
    raise NotImplementedError


def provide_cluster(config, cluster_info_path, wait):
    # onprem only supported for AWS provided raw-VPCs
    if config['provider'] == 'aws':
        provide_aws(config, cluster_info_path, wait)
    elif config['provider'] == 'onprem':
        provide_onprem(config, cluster_info_path, wait)
    elif config['provider'] == 'azure':
        provide_azure(config, cluster_info_path, wait)
    else:
        logging.error('Unrecognized provider: {}'.format(config['provider']))
        sys.exit(1)


def provide_aws(config, cluster_info_path, wait):
    bw = aws_client()
    if is_advanced_template(config['template_url']):
        final_config = ADVANCED_CF_CONFIG
        final_config.update(config)
        cf, _ = DcosCfAdvanced.create(
            stack_name=final_config['stack_name'],
            template_url=final_config['template_url'],
            public_agents=final_config['num_public_agents'],
            private_agents=final_config['num_private_agents'],
            key_pair_name=final_config['key_pair_name'],
            private_agent_type=final_config['private_agent_type'],
            public_agent_type=final_config['public_agent_type'],
            master_type=final_config['master_type'],
            vpc=final_config['vpc'],
            gateway=final_config['gateway'],
            private_subnet=final_config['private_subnet'],
            public_subnet=final_config['public_subnet'],
            boto_wrapper=bw)
    else:
        final_config = SIMPLE_CF_CONFIG
        final_config.update(config)
        cf, _ = DcosCfSimple.create(
            stack_name=final_config['stack_name'],
            template_url=final_config['template_url'],
            public_agents=final_config['num_public_agents'],
            private_agents=final_config['num_private_agents'],
            admin_location=final_config['admin_location'],
            key_pair_name=final_config['key_pair_name'],
            boto_wrapper=bw)
    # dump info to disk ASAP
    cluster_info = {
        'template_url': final_config['template_url'],
        'stack_name': cf.stack.stack_name,
        'provider': 'aws'}
    write_json(cluster_info_path, cluster_info)
    logging.info('Cluster launch has started, cluster info provided at: {}'.format(cluster_info_path))
    if wait:
        cf.wait_for_stack_creation(wait_before_poll_min=5)


def provide_onprem(config, cluster_info_path, wait):
    # FIXME: wait currently does nothing for onprem
    bw = aws_client()
    # Ensure we do not start without a ssh_key
    assert os.path.exists(config['ssh_key_path']), 'A valid ssh_key_path must be set!'
    final_config = ONPREM_CONFIG
    final_config.update(config)
    num_masters = final_config['num_masters']
    num_private_agents = final_config['num_private_agents']
    num_public_agents = final_config['num_public_agents']
    instance_count = num_masters + num_public_agents + num_private_agents + 1
    cf, ssh_info = VpcCfStack.create(
        stack_name=config['stack_name'],
        instance_type=config['instance_type'],
        instance_os=config['instance_os'],
        instance_count=instance_count,
        admin_location=config['admin_location'],
        key_pair_name=config['key_pair_name'],
        boto_wrapper=bw)
    # dump info to disk ASAP
    cluster_info = {
        'stack_name': cf.stack.stack_name,
        'provider': 'onprem',
        'installer_url': final_config['installer_url'],
        # Needed for sshing and running commands on hosts (required for describe)
        'ssh_user': ssh_info.user,
        'ssh_dir': ssh_info.home_dir,
        'ssh_key': load_string(config['ssh_key_path']),
        # Composition must be included so partition can be evaluated
        'num_masters': num_masters,
        'num_private_agents': num_private_agents,
        'num_public_agents': num_public_agents}
    write_json(cluster_info_path, cluster_info)
    logging.info('Cluster launch has started, cluster info provided at: {}'.format(cluster_info_path))

    # onprem cannot do non-blocking create as local host is driving install
    cf.wait_for_stack_creation()
    cluster = Cluster.from_vpc(
        cf,
        ssh_info,
        ssh_key_path=config['ssh_key_path'],
        num_masters=num_masters,
        num_agents=num_private_agents,
        num_public_agents=num_public_agents)

    # Filter extra entries from onprem config to pass to genconf
    add_config = {}
    for k, v in config.items():
        if k in ONPREM_CONFIG.keys():
            continue
        add_config[k] = v

    install_dcos(
        cluster,
        installer_url=final_config['installer_url'],
        setup=True,
        api=final_config['use_installer_api'],
        add_config_path=session_tempfile(yaml.dump(add_config).encode()),
        installer_api_offline_mode=False,
        install_prereqs=True,
        install_prereqs_only=False)


def provide_azure(config):
    raise NotImplementedError


def attach_aws(info):
    bw = aws_client()
    if is_advanced_template(info['template_url']):
        return DcosCfAdvanced(info['stack_name'], bw)
    else:
        return DcosCfSimple(info['stack_name'], bw)


def describe(info):
    """Returns extra information about clusters:
    """
    # Note: onprem is only suported in aws provided VPCs
    if info['provider'] == 'aws':
        cf = attach_aws(info)
        extra_info = {
            'masters': convert_host_list(cf.get_master_ips()),
            'private_agents': convert_host_list(cf.get_private_agent_ips()),
            'public_agents': convert_host_list(cf.get_public_agent_ips())}
    elif info['provider'] == 'onprem':
        cluster = Cluster.from_vpc(
            VpcCfStack(info['stack_name'], aws_client()),
            SshInfo(info['ssh_user'], info['ssh_dir']),
            ssh_key_path=session_tempfile(info['ssh_key'].encode()),
            num_masters=info['num_masters'],
            num_agents=info['num_private_agents'],
            num_public_agents=info['num_public_agents'])
        extra_info = {
            'masters': convert_host_list(cluster.masters),
            'private_agents': convert_host_list(cluster.agents),
            'public_agents': convert_host_list(cluster.public_agents),
            'bootstrap_host': convert_host_list([cluster.bootstrap_host])}
    elif info['provider'] == 'azure':
        raise NotImplementedError
    else:
        raise Exception('Provider not recognized: {}'.format(info['provider']))
    info.update(extra_info)
    print(json.dumps(info, indent=4))


def delete(info):
    if info['provider'] == 'aws':
        attach_aws(info).delete()
    if info['provider'] == 'onprem':
        VpcCfStack(info['stack_name'], aws_client()).delete()


def main():
    args = docopt(__doc__, version='DC/OS Launch 1.0')

    if args['config']:
        with open(args['--config-path'], 'w') as fh:
            config_type = args['CONFIG_TYPE']
            assert config_type in DEFAULT_CONFIG.keys(), \
                '{} is not a supported config type!'.format(config_type)
            yaml.dump(DEFAULT_CONFIG[config_type], fh, default_flow_style=False,
                      explicit_start=True)
        sys.exit(0)

    if args['create']:
        cluster_info = provide_cluster(
            config=yaml.load(load_string(args['CLUSTER_CONFIG_PATH'])),
            cluster_info_path=args['--dump-info'],
            wait=not args['--no-wait'])
        sys.exit(0)

    # All following options require a loaded cluster info
    cluster_info = load_json(args['CLUSTER_INFO_PATH'])

    if args['describe']:
        describe(cluster_info)
        sys.exit(0)

    if args['delete']:
        delete(cluster_info)
        sys.exit(0)


if __name__ == '__main__':
    main()
