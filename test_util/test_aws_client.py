import os
from urllib.parse import urlencode
import pytest

from test_util.aws import AwsApiClient, AwsApiError


@pytest.fixture
def aws_client():
    return AwsApiClient('us-west-2', os.environ['AWS_ACCESS_KEY_ID'], os.environ['AWS_SECRET_ACCESS_KEY'])


class TestEc2Api:
    def test_dryrun(self, aws_client):
        with pytest.raises(AwsApiError) as e:
            aws_client.ec2.get('', query=urlencode([
                ('Action', 'DescribeInstances'),
                ('DryRun', 'true')]))
        assert e.value.code == 'DryRunOperation'

    def test_error(self, aws_client):
        with pytest.raises(AwsApiError) as e:
            aws_client.ec2.get('', query=urlencode([
                ('Action', 'DescribeInstances'),
                ('InstanceId.1', 'this-instance-totally-doesnt-exist')]))
        assert e.value.code == 'InvalidInstanceID.Malformed'

    def test_good_response(self, aws_client):
        r = aws_client.ec2.get('', query=urlencode([
            ('Action', 'DescribeRegions')]))
        region_list = [region.find('regionName').text for region
                       in r.xml.find('regionInfo').findall('item')]
        assert aws_client.region in region_list


class TestCloudformationApi:
    def test_error(self, aws_client):
        with pytest.raises(AwsApiError) as e:
            aws_client.cloudformation.get('', query=urlencode([
                ('Action', 'DescribeStacks'),
                ('StackName', 'this-stack-totally-doesnt-exist')]))
        assert e.value.code == 'ValidationError'

    def test_good_response(self, aws_client):
        r = aws_client.cloudformation.get('', query='Action=DescribeAccountLimits')
        limits = [lim.find('Name').text for lim in
                  r.xml.find('DescribeAccountLimitsResult')
                  .find('AccountLimits').findall('member')]
        assert 'StackLimit' in limits


class TestAutoscalingApi:
    def test_good_response(self, aws_client):
        r = aws_client.autoscaling.get('', query='Action=DescribeAccountLimits')
        limits = [lim.tag for lim in list(r.xml.find('DescribeAccountLimitsResult'))]
        assert 'MaxNumberOfAutoScalingGroups' in limits

    def test_bad_response(self, aws_client):
        with pytest.raises(AwsApiError) as e:
            aws_client.autoscaling.get('', query=urlencode([
                ('Action', 'DescribeAutoScalingInstances'),
                ('InstanceIds.memeber.1', 'totally-not-a-real-instance')]))
        assert e.value.code == 'ValidationError'
