import os
import pytest

from test_util.aws import AwsApiClient, AwsApiError, CfStack, stringify_element


@pytest.fixture
def aws_client():
    return AwsApiClient('us-west-2', os.environ['AWS_ACCESS_KEY_ID'], os.environ['AWS_SECRET_ACCESS_KEY'])


class TestEc2Api:
    def test_dryrun(self, aws_client):
        try:
            aws_client.ec2.get('', query='Action=DescribeInstances&DryRun=true')
        except AwsApiError as e:
            assert e.code == 'DryRunOperation'


class TestCloudformationApi:
    def test_error(self, aws_client):
        try:
            aws_client.cloudformation.get('', query='Action=DescribeStacks&StackName=this-stack-totally-doesnt-exist')
        except AwsApiError as e:
            assert e.code == 'ValidationError'


    # stack = CfStack('tamar-qnjdhxr', aws_client)
    # from xml.etree import ElementTree
    # print(ElementTree.tostring(stack.get_stack_details()).decode())
    # print('\n'.join(['{}: {}'.format(c.tag, c.text) for e in stack.get_stack_events() for c in list(e)]))
