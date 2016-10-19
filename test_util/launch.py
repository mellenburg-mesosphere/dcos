"""DC/OS Launch

Usage:
  dcos-launch create [--wait] [--dump-info=<path>] CLUSTER_CONFIG_PATH
  dcos-launch (describe|delete) CLUSTER_INFO_PATH

Options:
  --dump-info=<path>   Use this path to dump the [default: cluster_info.json].
"""
# TODO: provide onprem_provider option for spinning up onprem in aws, gce, etc
# TODO: provide non-blocking deployment option. Requires dropping a setup script
#  for the onprem case which does not die on SIG-HUP
# TODO: add Azure
import logging
import os
import pprint
import sys
import yaml
from docopt import docopt
from pkgpanda.util import load_json, load_string, write_json

from test_util.aws import BotoWrapper, DcosCfAdvanced, DcosCfSimple, VpcCfStack
from test_util.cluster import Cluster, install_dcos
from test_util.helpers import Host, random_id, session_tempfile, SshInfo

LOGGING_FORMAT = '[%(asctime)s|%(name)s|%(levelname)s]: %(message)s'
logging.basicConfig(format=LOGGING_FORMAT, level=logging.INFO)
log = logging.getLogger('dcos-launch')


def check_keys(keys, my_dict, dict_name):
    failed = []
    for k in keys:
        if k in my_dict:
            failed.append(False)
        else:
            log.error('{} must be set in {}!'.format(k, dict_name))
            failed.append(True)
    if any(failed):
        log.error('Key(s) must be set in {}'.format(dict_name))
        sys.exit(1)


def filtered_config(config):
    """Takes in given config file and removes and onprem-launch-specific
    keys and then passes the rest of the config as the add_config for
    onprem installation (e.g. security, credientials, etc...)
    """
    launch_config_keys = [
        'installer_url',
        'num_masters',
        'num_public_agents',
        'num_private_agents',
        'stack_name',
        'instance_type',
        'instance_os',
        'admin_location',
        'key_pair_name',
        'ssh_key_path',
        'use_installer_api',
        'provider']
    filtered_config = {}
    for k, v in config.items():
        if k in launch_config_keys:
            continue
        filtered_config[k] = v
    return filtered_config


def convert_host_list(host_list):
    return [{'private_ip': h.private_ip, 'public_ip': h.public_ip} for h in host_list]


def parse_host_string(host_string):
    # FIXME: this function will probably not be used
    return [Host(*h.split('/')) for h in host_string.split(',')]


def is_advanced_template(template):
    return not template.endswith('single-master.cloudformation.json') and \
        not template.endswith('multi-master.cloudformation.json')


def aws_client():
    log.info('Attemping to authenticate with AWS')
    check_keys([
        'AWS_REGION',
        'AWS_ACCESS_KEY_ID',
        'AWS_SECRET_ACCESS_KEY'],
        os.environ,
        'environment')
    return BotoWrapper(
        os.environ['AWS_REGION'],
        os.environ['AWS_ACCESS_KEY_ID'],
        os.environ['AWS_SECRET_ACCESS_KEY'])


def azure_client():
    logging.info('Attempting to authentice with ARM')
    check_keys([
        'AZURE_LOCATION',
        'AZURE_CLIENT_ID',
        'AZURE_CLIENT_SECRET',
        'AZURE_TENANT_ID',
        'AZURE_SUBSCRIPTION_ID'],
        os.environ,
        'environment')
    raise NotImplementedError


def provide_cluster(config):
    # onprem only supported for AWS provided raw-VPCs
    if config['provider'] == 'aws':
        return provide_aws(config)
    elif config['provider'] == 'onprem':
        return provide_onprem(config)
    elif config['provider'] == 'azure':
        return provide_azure(config)
    else:
        logging.error('Unrecognized provider: {}'.format(config['provider']))
        sys.exit(1)


def provide_aws(config):
    """Only required config parameter to launch is template URL
    """
    bw = aws_client()
    check_keys(['template_url'], config, 'config.yaml')
    if is_advanced_template(config['template_url']):
        # Populate defaults
        raise NotImplementedError('Advanced cleanup needs some work')
        cf, _ = DcosCfAdvanced.create(
            stack_name=config.get('stack_name', 'DCOS-AdvancedCF-{}'.format(random_id(10))),
            template_url=config['template_url'],
            private_agents=config.get('num_private_agents', 0),
            public_agents=config.get('num_public_agents', 0),
            key_pair_name=config.get('key_pair_name', 'default'),
            private_agent_type=config.get('private_agent_type', 'm3.xlarge'),
            public_agent_type=config.get('public_agent_type', 'm3.xlarge'),
            master_type=config.get('master_type', 'm3.xlarge'),
            vpc=config.get('vpc', None),
            gateway=config.get('gateway', None),
            private_subnet=config.get('private_subnet', None),
            public_subnet=config.get('public_subnet', None),
            boto_wrapper=bw)
    else:
        cf, _ = DcosCfSimple.create(
            stack_name=config.get('stack_name', 'DCOS-SimpleCF-{}'.format(random_id(10))),
            template_url=config['template_url'],
            public_agents=config.get('num_public_agents', 0),
            private_agents=config.get('num_private_agents', 0),
            admin_location=config.get('admin_location', '0.0.0.0/0'),
            key_pair_name=config.get('key_pair_name', 'default'),
            boto_wrapper=bw)
    return {
        'template_url': config['template_url'],
        'stack_name': cf.stack.stack_name,
        'provider': 'aws'}


def provide_onprem(config):
    # TODO: add onprem_provider to config to allow other than AWS
    # AWS-provided VPC onprem install
    # TODO: allow using plaintext password in config
    bw = aws_client()
    check_keys([
        'installer_url',
        'num_masters',
        'ssh_key_path'],
        config,
        'config.yaml')
    num_masters = config['num_masters']
    num_private_agents = int(config.get('num_private_agents', '0'))
    num_public_agents = int(config.get('num_public_agents', '0'))
    instance_count = num_masters + num_public_agents + num_private_agents + 1
    cf, ssh_info = VpcCfStack.create(
        stack_name=config.get('stack_name', 'DCOS-AWS-onprem-{}'.format(random_id(10))),
        instance_type=config.get('instance_type', 'm3.xlarge'),
        instance_os=config.get('instance_os', 'cent-os-7-dcos-prereqs'),
        instance_count=instance_count,
        admin_location=config.get('admin_location', '0.0.0.0/0'),
        key_pair_name=config.get('key_pair_name', 'default'),
        boto_wrapper=bw)
    # onprem cannot do non-blocking create as local host is driving install
    cf.wait_for_stack_creation()
    cluster = Cluster.from_vpc(
        cf,
        ssh_info,
        ssh_key_path=config['ssh_key_path'],
        num_masters=num_masters,
        num_agents=num_private_agents,
        num_public_agents=num_public_agents)

    install_dcos(
        cluster,
        installer_url=config['installer_url'],
        setup=True,
        api=config.get('use_installer_api', 'true') == 'true',
        add_config_path=session_tempfile(yaml.dump(filtered_config(config))),
        installer_api_offline_mode=False,
        install_prereqs=True,
        install_prereqs_only=False)
    return {
        'stack_name': cf.stack.stack_name,
        'provider': 'onprem',
        'installer_url': config['installer_url'],
        'ssh_user': ssh_info.user,
        'ssh_dir': ssh_info.home_dir,
        'ssh_key': load_string(config['ssh_key_path']),
        # Composition must be included so partition can be evaluated
        'num_masters': num_masters,
        'num_private_agents': num_private_agents,
        'num_public_agents': num_public_agents}


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
            ssh_key_path=session_tempfile(info['ssh_key']),
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
    pprint.pprint(info)


def delete(info):
    if info['provider'] == 'aws':
        attach_aws(info).delete()
    if info['provider'] == 'onprem':
        VpcCfStack(info['stack_name'], aws_client()).delete()


def main():
    args = docopt(__doc__, version='DC/OS Launch 1.0')
    if args['create']:
        cluster_info = provide_cluster(yaml.load(load_string(args['CLUSTER_CONFIG_PATH'])))
        write_json(args['--dump-info'], cluster_info)
        logging.info('Cluster launch has started, cluster info provided at: {}'.format(args['--dump-info']))
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
