#!/usr/bin/env python3
import datetime
import logging
import hashlib
import hmac
import time
from io import StringIO
from xml.etree import ElementTree

import boto3
import retrying
from requests.auth import AuthBase

from test_util.helpers import ApiClient, Host, retry_boto_rate_limits, SshInfo, Url

LOGGING_FORMAT = '[%(asctime)s|%(name)s|%(levelname)s]: %(message)s'
logging.basicConfig(format=LOGGING_FORMAT, level=logging.DEBUG)
# AWS verbosity in debug mode overwhelms meaningful logging
logging.getLogger('botocore').setLevel(logging.INFO)
log = logging.getLogger(__name__)

VPC_TEMPLATE_URL = 'https://s3.amazonaws.com/vpc-cluster-template/vpc-cluster-template.json'
VPC_EBS_ONLY_TEMPLATE_URL = 'https://s3.amazonaws.com/vpc-cluster-template/vpc-ebs-only-cluster-template.json'


def template_by_instance_type(instance_type):
    if instance_type.split('.')[0] in ('c4', 't2', 'm4'):
        return VPC_EBS_ONLY_TEMPLATE_URL
    else:
        return VPC_TEMPLATE_URL


@retry_boto_rate_limits
def instances_to_hosts(instances):
    return [Host(i.private_ip_address, i.public_ip_address) for i in instances]


def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def getSignatureKey(key, dateStamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning


def etree_without_namespace(xml_str):
    """Homegenous XML namespace in AWS responses serve little to no purpose
    """
    it = ElementTree.iterparse(StringIO(xml_str))
    for _, elem in it:
        if elem.tag[0] == '{':
            elem.tag = elem.tag[elem.tag.find('}') + 1:]
    return it.root


class AwsAuth(AuthBase):
    """http://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
    """
    def __init__(self, access_key_id, secret_access_key):
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key

    def __call__(self, r):
        # use our Url to hand the requests url
        url = Url.from_string(r.url)
        service, region = service_region_from_endpoint(url.host)
        # STEP 1: Canonical Request: http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
        # sorted_query = urllib.parse.quote('&'.join(sorted(url.query.split('&'))))
        sorted_query = '&'.join(sorted(url.query.split('&')))
        r.url = str(url.get_url(query=sorted_query))  # query parameters must be sorted
        t = datetime.datetime.utcnow()
        amzdate = t.strftime('%Y%m%dT%H%M%SZ')
        # these headers must be in the signed headers
        r.headers.update({'x-amz-date': amzdate, 'host': url.host})
        header_str = ''
        new_headers = {}
        # first, reformat headers
        for k, v in r.headers.items():
            key = k.lower().strip()
            val = r.headers[k].strip()
            new_headers[key] = val
        r.headers = new_headers
        # now, create canonical header string
        for k, v in sorted(r.headers.items()):
            header_str += '{}:{}\n'.format(k, v)

        signed_headers = ';'.join(sorted([h for h in r.headers.keys()]))

        payload = r.body if r.body is not None else ''
        canonical_request = '\n'.join([
            r.method.upper(),
            url.path,
            sorted_query,
            header_str,
            signed_headers,
            hashlib.sha256(payload.encode()).hexdigest()])

        # STEP 2 create the string to sign
        algorithm = 'AWS4-HMAC-SHA256'
        datestamp = t.strftime('%Y%m%d')
        credential_scope = '/'.join([datestamp, region, service, 'aws4_request'])
        string_to_sign = '\n'.join([
            algorithm,
            amzdate,
            credential_scope,
            hashlib.sha256(canonical_request.encode()).hexdigest()])

        # STEP 3 Calculate the signature
        signing_key = getSignatureKey(self.secret_access_key, datestamp, region, service)
        signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

        # STEP 4 ADD SIGNING INFO TO REQUEST
        r.headers.update({
            'Authorization': '{} Credential={}/{},SignedHeaders={},Signature={}'.format(
                algorithm, self.access_key_id, credential_scope, signed_headers, signature)})
        return r


def endpoint_from_service_region(service, region):
    if service == 's3':
        return 's3-{}.amazonaws.com'.format(region)
    elif service == 'es':
        return '{}.es.amazonaws.com'.format(region)
    else:
        return '{}.{}.amazonaws.com'.format(service, region)


def service_region_from_endpoint(endpoint):
    """endpoint must be a host string (i.e. not scheme or path)
    """
    if endpoint.startswith('s3'):
        return 's3', endpoint.split('.')[0][3:]
    else:
        service, region = endpoint.split('.')[:2]
        if region == 'es':
            return region, service
        else:
            return service, region


def stringify_element(elem):
    return ElementTree.tostring(elem).decode()


class AwsApiError(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message

    def __repr__(self):
        return '{}: {}'.format(self.code, self.message)

    @classmethod
    def from_element(cls, elem):
        return cls(elem.find('Code').text, elem.find('Message').text)


class AwsApiClient(ApiClient):
    def __init__(self, region, access_key_id, secret_access_key):
        """ElasticSearch and S3 doesnt use region convention
        """
        super().__init__(Url.from_string('https://amazonaws.com'))
        self.region = region
        self.session.auth = AwsAuth(access_key_id, secret_access_key)
        self.version = None
        self.service = None

    def get_service(self, service, version):
        service_client = super().get_client(host=endpoint_from_service_region(service, self.region))
        service_client.version = version
        service_client.service = service
        return service_client

    def get_url(self, path_ex, scheme=None, host=None, query=None,
                fragment=None, path=None, port=None, node=None):
        if query is None:
            query = ''
        if 'Version' not in query:
            query = query + '&Version={}'.format(self.version)
        return super().get_url(path_ex, scheme=scheme, host=host, query=query,
                               fragment=fragment, path=path, port=port, node=node)

    def api_request(self, *args, **kwargs):
        sleep = 2
        resp = super().api_request(*args, **kwargs)
        while self._should_retry(resp):
            time.sleep(sleep)
            resp = super().api_request(*args, **kwargs)
            sleep *= 2
        if resp.content:
            resp.xml = etree_without_namespace(resp.content.decode())
        if not resp.ok:
            logging.error('AWS Client recieved status {} from {}'.format(resp.status_code, resp.url))
            if resp.xml:
                raise self._extract_error(resp.xml)
            else:
                resp.raise_for_status()
        return resp

    def _should_retry(self, resp):
        if resp.ok:
            return False  # successful; nothing to retry
        if resp.status_code == 503:
            return True  # represents temporarily unavailable across all services
        if not resp.content:
            return False  # Error code without content that is not 503, do not retry
        xml = etree_without_namespace(resp.content.decode())
        if self.service in ['autoscaling', 'cloudformation']:
            if resp.status_code == 400 and self._extract_error(xml).code == 'Throttling':
                return True
        if self.service == 'ec2':
            if self._extract_error(xml).code == 'RequestLimitExceeded':
                return True
        return False

    def _extract_error(self, xml):
        if self.service in ['autoscaling', 'cloudformation']:
            return AwsApiError.from_element(xml.find('Error'))
        elif self.service == 'ec2':
            errors = xml.find('Errors').findall('Error')
            if len(errors) == 1:
                return AwsApiError.from_element(errors[0])
            else:
                return AwsApiError('AggregateError', '\n' + '\n'.join(
                    [repr(AwsApiError.from_element(e)) for e in errors]))
        else:
            return AwsApiError('UnknownError-NoSchema', stringify_element(xml))

    @property
    def cloudformation(self):
        return self.get_service('cloudformation', '2010-05-15')

    @property
    def ec2(self):
        return self.get_service('ec2', '2016-11-15')

    @property
    def autoscaling(self):
        return self.get_service('autoscaling', ' 2011-01-01')


class BotoWrapper():
    def __init__(self, region, aws_access_key_id, aws_secret_access_key):
        self.region = region
        self.session = boto3.session.Session(
            aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

    def client(self, name):
        return self.session.client(service_name=name, region_name=self.region)

    def resource(self, name):
        return self.session.resource(service_name=name, region_name=self.region)

    def create_key_pair(self, key_name):
        """Retruns private key of newly generated pair
        """
        key = self.resource('ec2').KeyPair(key_name)
        return key.key_material

    def delete_key_pair(self, key_name):
        self.resource('ec2').KeyPair(key_name).delete()

    def create_stack(self, name, template_url, user_parameters, deploy_timeout=60):
        """Returns boto stack object
        """
        log.info('Requesting AWS CloudFormation...')
        cf_parameters = []
        for k, v in user_parameters.items():
            cf_parameters.append({'ParameterKey': k, 'ParameterValue': v})
        self.resource('cloudformation').create_stack(
            StackName=name,
            TemplateURL=template_url,
            DisableRollback=True,
            TimeoutInMinutes=deploy_timeout,
            Capabilities=['CAPABILITY_IAM'],
            Parameters=cf_parameters)
        return CfStack(name, self)


class CfStack():
    def __init__(self, stack_name, aws_client):
        self.aws_client = aws_client
        self.stack_name = stack_name
        self._host_cache = {}

    def wait_for_status_change(self, state_1, state_2, wait_before_poll_min, timeout=60 * 60):
        """
        Note: Do not use unwrapped boto waiter class, it has very poor error handling

        Stacks can have one of the following statuses. See:
        http://boto3.readthedocs.io/en/latest/reference/
        services/cloudformation.html#CloudFormation.Client.describe_stacks

        CREATE_IN_PROGRESS, CREATE_FAILED, CREATE_COMPLETE
        ROLLBACK_IN_PROGRESS, ROLLBACK_FAILED, ROLLBACK_COMPLETE
        DELETE_IN_PROGRESS, DELETE_FAILED, DELETE_COMPLETE
        UPDATE_IN_PROGRESS, UPDATE_COMPLETE_CLEANUP_IN_PROGRESS
        UPDATE_COMPLETE, UPDATE_ROLLBACK_IN_PROGRESS
        UPDATE_ROLLBACK_FAILED, UPDATE_ROLLBACK_COMPLETE
        UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS
        """
        log.info('Waiting for status to change from {} to {}'.format(state_1, state_2))
        log.info('Sleeping for {} minutes before polling'.format(wait_before_poll_min))
        time.sleep(60 * wait_before_poll_min)

        @retrying.retry(wait_fixed=10 * 1000,
                        stop_max_delay=timeout * 1000,
                        retry_on_result=lambda res: res is False,
                        retry_on_exception=lambda ex: False)
        def wait_loop():
            stack_details = self.get_stack_details()
            stack_status = stack_details.find('StackStatus').text
            if stack_status == state_2:
                return True
            if stack_status != state_1:
                log.error('Stack Details: {}'.format(stringify_element(stack_details)))
                log.error('Stack Events: {}'.format(
                    '\n'.join(['{}: {}'.format(c.tag, c.text) for e in self.get_stack_events() for c in list(e)])))
                raise Exception('StackStatus changed unexpectedly to: {}'.format(stack_status))
            return False
        wait_loop()

    def get_stack_details(self):
        """returns an XML element for the local stack
        """
        log.debug('Requesting stack details')
        r = self.aws_client.cloudformation.get(
            '', query='Action=DescribeStacks&StackName={}'.format(self.stack_name))
        r.raise_for_status()
        return r.xml.find('DescribeStacksResult').find('Stacks').find('member')

    def get_stack_events(self):
        """returns a list of event elements
        """
        log.debug('Requesting stack events')
        r = self.aws_client.cloudformation.get(
            '', query='Action=DescribeStackEvents&StackName={}'.format(self.stack_name))
        r.raise_for_status()
        return r.xml.find('DescribeStackEventsResult').find('StackEvents').findall('member')

    def wait_for_stack_creation(self, wait_before_poll_min=3):
        self.wait_for_status_change('CREATE_IN_PROGRESS', 'CREATE_COMPLETE', wait_before_poll_min)

    def wait_for_stack_deletion(self, wait_before_poll_min=3):
        self.wait_for_status_change('DELETE_IN_PROGRESS', 'DELETE_COMPLETE', wait_before_poll_min)

    def get_parameter(self, param):
        raise NotImplementedError()

    def get_auto_scaling_instances(self, logical_id):
        """ get stack resources, then describe autoscaling groups and grab instance set
        """
        ec2 = self.boto_wrapper.resource('ec2')
        return [ec2.Instance(i['InstanceId']) for asg in self.boto_wrapper.client('autoscaling').
                describe_auto_scaling_groups(
                    AutoScalingGroupNames=[self.stack.Resource(logical_id).physical_resource_id])
                ['AutoScalingGroups'] for i in asg['Instances']]

    def get_hosts_cached(self, group_name, refresh=False):
        if refresh or group_name not in self._host_cache:
            host_list = instances_to_hosts(self.get_auto_scaling_instances(group_name))
            self._host_cache[group_name] = host_list
            return host_list
        return self._host_cache[group_name]


class DcosCfSimple(CfStack):
    @classmethod
    def create(cls, stack_name, template_url, public_agents, private_agents,
               admin_location, key_pair_name, boto_wrapper):
        parameters = {
            'KeyName': key_pair_name,
            'AdminLocation': admin_location,
            'PublicSlaveInstanceCount': str(public_agents),
            'SlaveInstanceCount': str(private_agents)}
        stack = boto_wrapper.create_stack(stack_name, template_url, parameters)
        # Use stack_name as the binding identifier. At time of implementation,
        # stack.stack_name returns stack_id if Stack was created with ID
        return cls(stack.stack.stack_name, boto_wrapper), SSH_INFO['coreos']

    def delete(self):
        log.info('Starting deletion of CF stack')
        # boto stacks become unusable after deletion (e.g. status/info checks) if name-based
        self.stack = self.boto_wrapper.resource('cloudformation').Stack(self.stack.stack_id)
        self.stack.delete()
        self.empty_and_delete_s3_bucket_from_stack()

    def empty_and_delete_s3_bucket_from_stack(self):
        bucket_id = self.stack.Resource('ExhibitorS3Bucket').physical_resource_id
        s3 = self.boto_wrapper.resource('s3')
        bucket = s3.Bucket(bucket_id)
        log.info('Starting bucket {} deletion'.format(bucket))
        all_objects = bucket.objects.all()
        obj_count = len(list(all_objects))
        if obj_count > 0:
            assert obj_count == 1, 'Expected one object in Exhibitor S3 bucket but found: ' + str(obj_count)
            exhibitor_object = list(all_objects)[0]
            log.info('Trying to delete object from bucket: {}'.format(repr(exhibitor_object)))
            exhibitor_object.delete()
        log.info('Trying deleting bucket {} itself'.format(bucket))
        bucket.delete()
        log.info('Delete successfully triggered for {}'.format(self.stack.stack_name))

    def get_master_ips(self, refresh=False):
        return self.get_hosts_cached('MasterServerGroup', refresh=refresh)

    def get_public_agent_ips(self, refresh=False):
        return self.get_hosts_cached('PublicSlaveServerGroup', refresh=refresh)

    def get_private_agent_ips(self, refresh=False):
        return self.get_hosts_cached('SlaveServerGroup', refresh=refresh)


class DcosCfAdvanced(CfStack):
    @classmethod
    def create(cls, stack_name, boto_wrapper, template_url,
               public_agents, private_agents, key_pair_name,
               private_agent_type, public_agent_type, master_type,
               vpc_cidr='10.0.0.0/16', public_subnet_cidr='10.0.128.0/20',
               private_subnet_cidr='10.0.0.0/17',
               gateway=None, vpc=None, private_subnet=None, public_subnet=None):
        ec2 = boto_wrapper.client('ec2')
        if not vpc:
            log.info('Creating new VPC...')
            vpc = ec2.create_vpc(CidrBlock=vpc_cidr, InstanceTenancy='default')['Vpc']['VpcId']
            ec2.get_waiter('vpc_available').wait(VpcIds=[vpc])
            ec2.create_tags(Resources=[vpc], Tags=[{'Key': 'Name', 'Value': stack_name}])
        log.info('Using VPC with ID: ' + vpc)

        if not gateway:
            log.info('Creating new InternetGateway...')
            gateway = ec2.create_internet_gateway()['InternetGateway']['InternetGatewayId']
            ec2.attach_internet_gateway(InternetGatewayId=gateway, VpcId=vpc)
            ec2.create_tags(Resources=[gateway], Tags=[{'Key': 'Name', 'Value': stack_name}])
        log.info('Using InternetGateway with ID: ' + gateway)

        if not private_subnet:
            log.info('Creating new PrivateSubnet...')
            private_subnet = ec2.create_subnet(VpcId=vpc, CidrBlock=private_subnet_cidr)['Subnet']['SubnetId']
            ec2.create_tags(Resources=[private_subnet], Tags=[{'Key': 'Name', 'Value': stack_name + '-private'}])
            ec2.get_waiter('subnet_available').wait(SubnetIds=[private_subnet])
        log.info('Using PrivateSubnet with ID: ' + private_subnet)

        if not public_subnet:
            log.info('Creating new PublicSubnet...')
            public_subnet = ec2.create_subnet(VpcId=vpc, CidrBlock=public_subnet_cidr)['Subnet']['SubnetId']
            ec2.create_tags(Resources=[public_subnet], Tags=[{'Key': 'Name', 'Value': stack_name + '-public'}])
            ec2.get_waiter('subnet_available').wait(SubnetIds=[public_subnet])
        log.info('Using PublicSubnet with ID: ' + public_subnet)

        parameters = {
            'KeyName': key_pair_name,
            'Vpc': vpc,
            'InternetGateway': gateway,
            'MasterInstanceType': master_type,
            'PublicAgentInstanceCount': str(public_agents),
            'PublicAgentInstanceType': public_agent_type,
            'PublicSubnet': public_subnet,
            'PrivateAgentInstanceCount': str(private_agents),
            'PrivateAgentInstanceType': private_agent_type,
            'PrivateSubnet': private_subnet}
        stack = boto_wrapper.create_stack(stack_name, template_url, parameters)
        try:
            os_string = template_url.split('/')[-1].split('.')[-2].split('-')[0]
            ssh_info = CF_OS_SSH_INFO[os_string]
        except (KeyError, IndexError):
            log.exception('Unexpected template URL: {}'.format(template_url))
            if os_string:
                log.exception('No SSH info for OS string: {}'.format(os_string))
            raise
        return cls(stack.stack.stack_name, boto_wrapper), ssh_info

    def delete(self, delete_vpc=False):
        log.info('Starting deletion of CF Advanced stack')
        vpc_id = self.get_parameter('Vpc')
        # boto stacks become unusable after deletion (e.g. status/info checks) if name-based
        self.stack = self.boto_wrapper.resource('cloudformation').Stack(self.stack.stack_id)
        log.info('Deleting Infrastructure Stack')
        infrastack = DcosCfSimple(self.get_resource_stack('Infrastructure').stack.stack_id, self.boto_wrapper)
        infrastack.delete()
        log.info('Deleting Master Stack')
        self.get_resource_stack('MasterStack').stack.delete()
        log.info('Deleting Private Agent Stack')
        self.get_resource_stack('PrivateAgentStack').stack.delete()
        log.info('Deleting Public Agent Stack')
        self.get_resource_stack('PublicAgentStack').stack.delete()
        self.stack.delete()
        if delete_vpc:
            self.wait_for_stack_deletion()
            self.boto_wrapper.resource('ec2').Vpc(vpc_id).delete()

    def get_master_ips(self, refresh=False):
        return self.get_resource_stack('MasterStack').get_hosts_cached('MasterServerGroup', refresh=refresh)

    def get_private_agent_ips(self, refresh=False):
        return self.get_resource_stack('PrivateAgentStack').get_hosts_cached('PrivateAgentServerGroup', refresh=refresh)

    def get_public_agent_ips(self, refresh=False):
        return self.get_resource_stack('PublicAgentStack').get_hosts_cached('PublicAgentServerGroup', refresh=refresh)

    def get_resource_stack(self, resource_name):
        """Returns a CfStack for a given resource
        """
        return CfStack(self.stack.Resource(resource_name).physical_resource_id, self.boto_wrapper)


class VpcCfStack(CfStack):
    @classmethod
    def create(cls, stack_name, instance_type, instance_os, instance_count,
               admin_location, key_pair_name, boto_wrapper):
        ami_code = OS_AMIS[instance_os][boto_wrapper.region]
        template_url = template_by_instance_type(instance_type)
        parameters = {
            'KeyPair': key_pair_name,
            'AllowAccessFrom': admin_location,
            'ClusterSize': str(instance_count),
            'InstanceType': str(instance_type),
            'AmiCode': ami_code}
        stack = boto_wrapper.create_stack(stack_name, template_url, parameters)
        return cls(stack.stack.stack_name, boto_wrapper), OS_SSH_INFO[instance_os]

    def delete(self):
        # boto stacks become unusable after deletion (e.g. status/info checks) if name-based
        self.stack = self.boto_wrapper.resource('cloudformation').Stack(self.stack.stack_id)
        self.stack.delete()

    def get_vpc_host_ips(self):
        # the vpc templates use the misleading name CentOSServerAutoScale for all deployments
        # https://mesosphere.atlassian.net/browse/DCOS-11534
        return self.get_hosts_cached('CentOSServerAutoScale')


SSH_INFO = {
    'centos': SshInfo(
        user='centos',
        home_dir='/home/centos',
    ),
    'coreos': SshInfo(
        user='core',
        home_dir='/home/core',
    ),
    'debian': SshInfo(
        user='admin',
        home_dir='/home/admin',
    ),
    'rhel': SshInfo(
        user='ec2-user',
        home_dir='/home/ec2-user',
    ),
    'ubuntu': SshInfo(
        user='ubuntu',
        home_dir='/home/ubuntu',
    ),
}


OS_SSH_INFO = {
    'cent-os-7': SSH_INFO['centos'],
    'cent-os-7-dcos-prereqs': SSH_INFO['centos'],
    'coreos': SSH_INFO['coreos'],
    'debian-8': SSH_INFO['debian'],
    'rhel-7': SSH_INFO['rhel'],
    'ubuntu-16-04': SSH_INFO['ubuntu'],
}

CF_OS_SSH_INFO = {
    'el7': SSH_INFO['centos'],
    'coreos': SSH_INFO['coreos']
}


OS_AMIS = {
    'cent-os-7': {'ap-northeast-1': 'ami-965345f8',
                  'ap-southeast-1': 'ami-332de750',
                  'ap-southeast-2': 'ami-c80320ab',
                  'eu-central-1': 'ami-1548ae7a',
                  'eu-west-1': 'ami-2ea92f5d',
                  'sa-east-1': 'ami-2921ad45',
                  'us-east-1': 'ami-fa9b9390',
                  'us-west-1': 'ami-12b3ce72',
                  'us-west-2': 'ami-edf11b8d'},
    'cent-os-7-dcos-prereqs': {'ap-northeast-1': 'ami-965345f8',
                               'ap-southeast-1': 'ami-332de750',
                               'ap-southeast-2': 'ami-c80320ab',
                               'eu-central-1': 'ami-1548ae7a',
                               'eu-west-1': 'ami-2ea92f5d',
                               'sa-east-1': 'ami-2921ad45',
                               'us-east-1': 'ami-fa9b9390',
                               'us-west-1': 'ami-12b3ce72',
                               'us-west-2': 'ami-edf11b8d'},
    'coreos': {'ap-northeast-1': 'ami-84e0c7ea',
               'ap-southeast-1': 'ami-84e0c7ea',
               'ap-southeast-2': 'ami-f35b0590',
               'eu-central-1': 'ami-fdd4c791',
               'eu-west-1': 'ami-55d20b26',
               'sa-east-1': 'ami-f35b0590',
               'us-east-1': 'ami-37bdc15d',
               'us-west-1': 'ami-27553a47',
               'us-west-2': 'ami-00ebfc61'},
    'debian-8': {'ap-northeast-1': 'ami-fe54f3fe',
                 'ap-southeast-1': 'ami-60989c32',
                 'ap-southeast-2': 'ami-07e3993d',
                 'eu-central-1': 'ami-b092aaad',
                 'eu-west-1': 'ami-0ed89d79',
                 'sa-east-1': 'ami-a5bd3fb8',
                 'us-east-1': 'ami-8b9a63e0',
                 'us-west-1': 'ami-a5d621e1',
                 'us-west-2': 'ami-3d56520d'},
    'rhel-7': {'ap-northeast-1': 'ami-35556534',
               'ap-southeast-1': 'ami-941031c6',
               'ap-southeast-2': 'ami-83e08db9',
               'eu-central-1': 'ami-e25e6cff',
               'eu-west-1': 'ami-8cff51fb',
               'sa-east-1': 'ami-595ce844',
               'us-east-1': 'ami-a8d369c0',
               'us-west-1': 'ami-33cdd876',
               'us-west-2': 'ami-99bef1a9'},
    'ubuntu-16-04': {'ap-northeast-1': 'ami-0919cd68',
                     'ap-southeast-1': 'ami-42934921',
                     'ap-southeast-2': 'ami-623c0d01',
                     'eu-central-1': 'ami-a9a557c6',
                     'eu-west-1': 'ami-643d4217',
                     'sa-east-1': 'ami-60bd2d0c',
                     'us-east-1': 'ami-2ef48339',
                     'us-west-1': 'ami-a9a8e4c9',
                     'us-west-2': 'ami-746aba14'}
}
