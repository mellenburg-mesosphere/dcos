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
import os
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
    def __init__(self, aws_region, aws_access_key_id, aws_secret_access_key, config):
        self.boto_wrapper = BotoWrapper(aws_region, aws_access_key_id, aws_secret_access_key)
        self.config = config

    def create(self):
        parameters = {k: str(v) for k, v in self.config['parameters'].items()}
        self.boto_wrapper.create_stack(
            self.config['stack_name'], self.config['template_url'], parameters)
        return {
            'cloudformation': {
                'stack_name': self.config['stack_name'],
                'region': self.config['region'],
                'access_key_id': self.config['access_key_id'],
                'secret_access_key': self.config['secret_access_key']}}

    def wait(self):
        # TODO: should this support the case where the cluster is being updated?
        cf = self.get_stack()
        status = cf.get_stack_details()['StackStatus']
        if status == 'CREATE_IN_PROGRESS':
            cf.wait_for_stack_creation(wait_for_poll_min=0)
        elif status == 'CREATE_COMPLETE':
            pass
        else:
            raise Exception('')
        print('Cluster is ready!')

    def describe(self):
        cf = self.get_stack()
        return {
            'masters': convert_host_list(cf.get_master_ips()),
            'private_agents': convert_host_list(cf.get_private_agent_ips()),
            'public_agents': convert_host_list(cf.get_public_agent_ips())}

    def delete(self):
        self.get_stack().delete()

    def get_stack(self):
        """Returns the correct class interface depending how the AWS CF is configured
        NOTE: only supports Simple Cloudformation currently
        """
        return DcosCfSimple(self.config['stack_name'], self.boto_wrapper)


def get_launcher(config):
    """Returns a launcher given a python dictionary
    """
    if 'cloudformation' in config:
        aws_config = config['cloudformation']
        assert 'region' in aws_config
        assert 'access_key_id' in aws_config
        assert 'secret_access_key' in aws_config
        return AwsLauncher(
            aws_config['region'], aws_config['access_key_id'], aws_config['secret_access_key'], aws_config)
    else:
        raise Exception('Unsupported configuration!')


def convert_host_list(host_list):
    """ Makes Host tuples more readable when using describe
    """
    return [{'private_ip': h.private_ip, 'public_ip': h.public_ip} for h in host_list]


def do_create(config_path, info_path):
    assert not os.path.exists(info_path), 'There is already a cluster info at {}'.format(info_path)
    config = yaml.load(load_string(config_path))
    assert 'this_is_a_temporary_config_format_do_not_put_in_production' in config
    write_json(info_path, get_launcher(config).create())
    return 0


def main():
    args = docopt(__doc__, version='DC/OS Launch 1.0')

    if args['create']:
        sys.exit(do_create(args['--config-path'], args['--info-path']))

    cluster_info = load_json(args['--info-path'])

    if args['wait']:
        get_launcher(cluster_info).wait()
        sys.exit(0)

    if args['describe']:
        print(json.dumps(get_launcher(cluster_info).describe(), indent=4))
        sys.exit(0)

    if args['delete']:
        get_launcher(cluster_info).delete()
        sys.exit(0)


if __name__ == '__main__':
    main()
