import test_util
from test_util.launch import do_create
from pkgpanda.util import load_json


def test_aws_simple_create(monkeypatch, tmpdir):
    monkeypatch.setattr(test_util.aws.BotoWrapper, 'create_stack', lambda x, y, z, w: None)
    aws_simple_config = """
---
this_is_a_temporary_config_format_do_not_put_in_production: yes_i_agree
cloudformation:
  template_url: http://us-west-2.amazonaws.com/downloads
  stack_name: foobar
  region: us-west-2
  access_key_id: asdf09iasdf3m19238jowsfn
  secret_access_key: asdf0asafawwa3j8ajn
  parameters:
    KeyName: default
    AdminLocation: 0.0.0.0/0
    PublicSlaveInstanceCount: 1
    SlaveInstanceCount: 5
"""
    config_path = tmpdir.join('config.yaml')
    config_path.write(aws_simple_config)
    info_path = tmpdir.join('cluster_info.json')
    do_create(str(config_path), str(info_path))
    cluster_info = load_json(str(info_path))
    assert 'cloudformation' in cluster_info
    assert 'stack_name' in cluster_info['cloudformation']
    assert 'region' in cluster_info['cloudformation']
    assert 'access_key_id' in cluster_info['cloudformation']
    assert 'secret_access_key' in cluster_info['cloudformation']
