import os

from test_util.aws import AwsApiClient


def test_aws_auth():
    aws_client = AwsApiClient(os.environ['AWS_ACCESS_KEY_ID'], os.environ['AWS_SECRET_ACCESS_KEY'])
    ec2 = aws_client.get_service('ec2', 'us-west-2', '2016-11-15')
    r = ec2.get('/', query='Action=DescribeInstances')
    print(r.xml.find('reservationSet').findall('item'))
