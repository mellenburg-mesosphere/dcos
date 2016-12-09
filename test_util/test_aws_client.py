import os

from test_util.aws import AwsApiClient, CfStack


def test_aws_auth():
    aws_client = AwsApiClient('us-west-2', os.environ['AWS_ACCESS_KEY_ID'], os.environ['AWS_SECRET_ACCESS_KEY'])
    r = aws_client.ec2.get('/', query='Action=DescribeInstances')
    r.raise_for_status()
    assert r.xml.find('reservationSet').findall('item')

    r = aws_client.cloudformation.get('', query='Action=DescribeStacks&StackName=tamar-qnjdhxr')
    r.raise_for_status()

    stack = CfStack('tamar-qnjdhxr', aws_client)
    from xml.etree import ElementTree
    print(ElementTree.tostring(stack.get_stack_details()).decode())
    # print('\n'.join(['{}: {}'.format(c.tag, c.text) for e in stack.get_stack_events() for c in list(e)]))
