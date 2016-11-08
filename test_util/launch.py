"""DC/OS Launch

Usage:
  dcos-launch create [--info-path=<path>] [--config-path=<path>]
  dcos-launch wait [--info-path=<path>]
  dcos-launch (describe|delete) [--info-path=<path>]

Commands:
  create
  describe
  delete

Options:
  --config-path=<path>  Write path for generated config [default: config.yaml].
  --info-path=<path>    Write path for cluster details [default: cluster_info.json].
"""
import abc
import json
import sys
import yaml
from docopt import docopt
from pkgpanda.util import load_json, load_string, write_json

from test_util.aws import BotoWrapper, DcosCfSimple


class AbstractLauncher(metaclass=abc.ABCMeta):
    def __init__(self):
        raise NotImplementedError()

    def create(self):
        raise NotImplementedError()

    def wait(self):
        raise NotImplementedError()

    def describe(self):
        raise NotImplementedError()

    def delete(self):
        raise NotImplementedError()


class AwsLauncher(AbstractLauncher):
    def __init__(self, aws_region, aws_access_key_id, aws_secret_access_key):
        self.boto_wrapper = BotoWrapper(aws_region, aws_access_key_id, aws_secret_access_key)

    def create(self, cluster_config):
        self.boto_wrapper.create_stack(
            cluster_config['stack_name'], cluster_config['template_url'], cluster_config['parameters'])
        return {
            'stack_name': cluster_config['stack_name'],
            'launch_type': 'aws_simple'}

    def wait(self, cluster_info):
        # TODO: should this support the case where the cluster is being updated?
        cf = self.get_stack(cluster_info)
        status = cf.get_stack_details()['StackStatus']
        if status == 'CREATE_IN_PROGRESS':
            cf.wait_for_stack_creation(wait_for_poll_min=0)
        elif status == 'CREATE_COMPLETE':
            pass
        else:
            raise Exception('')
        print('Cluster is ready!')

    def describe(self, cluster_info):
        cf = self.get_stack(cluster_info)
        return {
            'masters': convert_host_list(cf.get_master_ips()),
            'private_agents': convert_host_list(cf.get_private_agent_ips()),
            'public_agents': convert_host_list(cf.get_public_agent_ips())}

    def delete(self, cluster_info):
        self.get_stack(cluster_info).delete()

    def get_stack(self, cluster_info):
        return DcosCfSimple(cluster_info['stack_name'], self.boto_wrapper)


def get_launcher(config):
    if 'aws_simple' in config:
        aws_config = config['aws_simple']
        assert 'region_name' in aws_config
        assert 'access_key_id' in aws_config
        assert 'secret_access_key' in aws_config
        return AwsLauncher(aws_config['region_name'], aws_config['access_key_id'], aws_config['secret_access_key'])
    elif 'aws_advanced' in config:
        raise NotImplementedError()
    else:
        raise Exception('Unsupported configuration!')


def convert_host_list(host_list):
    """ Makes Host tuples more readable when using describe
    """
    return [{'private_ip': h.private_ip, 'public_ip': h.public_ip} for h in host_list]


def main():
    args = docopt(__doc__, version='DC/OS Launch 1.0')

    if args['create']:
        config = yaml.load(load_string(args['--config-path']))
        assert 'this_is_a_temporary_config_format_do_not_put_in_production' in config
        write_json(get_launcher.create())
        sys.exit(0)

    cluster_info = load_json(args['--info-path'])

    if args['wait']:
        get_launcher.wait(cluster_info)
        sys.exit(0)

    if args['describe']:
        print(json.dumps(get_launcher().describe(cluster_info), indent=4))
        sys.exit(0)

    if args['delete']:
        get_launcher().delete(cluster_info)
        sys.exit(0)


if __name__ == '__main__':
    main()
