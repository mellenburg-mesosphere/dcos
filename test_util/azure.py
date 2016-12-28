"""
The real REST API spec:
https://msdn.microsoft.com/en-us/library/azure/mt163658.aspx
"""
import functools
import logging
import os
import re

import requests

from test_util.helpers import ApiClientSession, Url

LOGGING_FORMAT = '[%(asctime)s|%(name)s|%(levelname)s]: %(message)s'
logging.basicConfig(format=LOGGING_FORMAT, level=logging.DEBUG)


class AzureAuth(requests.auth.AuthBase):
    def __init__(self, access_token):
        self.access_token = access_token

    def __call__(self, request):
        # also should include a Host header, but requests automatically adds it
        request.headers['Authorization'] = 'Bearer {}'.format(self.access_token)
        return request


class AzureClient(ApiClientSession):
    """See:
    https://docs.microsoft.com/en-us/rest/api/
    https://msdn.microsoft.com/en-us/library/azure/
    """

    def __init__(self, client_id, client_secret, tenant_id, subscription_id):
        super().__init__(Url.from_string('https://management.azure.com/subscriptions/{}'.format(subscription_id)))
        self.default_url.query = 'api-version=2016-09-01'
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id
        self.subscription_id = subscription_id
        self.authenticate()

    def authenticate(self):
        """See:
        https://docs.microsoft.com/en-us/azure/active-directory/active-directory-protocols-oauth-service-to-service
        https://docs.microsoft.com/en-us/azure/active-directory/active-directory-protocols-oauth-code
        """
        params = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'resource': str(self.default_url.copy(path='/', query=''))}  # azure resources must end with '/'
        r = requests.post(
            'https://login.microsoftonline.com/{}/oauth2/token'.format(self.tenant_id),
            data=params)
        r.raise_for_status()
        self.session.auth = AzureAuth(r.json()['access_token'])

    def api_request(self, method, path_extension, scheme=None, host=None, query=None,
                    fragment=None, port=None, **kwargs):
        """ Wrapper to automatically retry requests if Authentication fails
        """
        super_request = functools.partial(super().api_request, method, path_extension, scheme=scheme,
                                          host=host, query=query, fragment=fragment, port=port, **kwargs)
        r = super_request()
        if not r.ok:
            resp = r.json()
            if 'error' in resp:
                logging.error(resp['error']['code'] + ':' + resp['error']['message'])
        if r.status_code == 401:
            if 'error' in resp:
                if resp['error']['code'] == 'AuthenticationFailed':
                    logging.info('Trying authentication and retrying request')
                    self.authenticate()
                    r = super_request()
        return r


class DcosResourceGroup:
    def __init__(self, group_name, azure_client):
        self.group_name = group_name  # each DC/OS deployment is assumed to be in its own, exclusive resource group
        self.azure_client = azure_client

    @classmethod
    def deploy(
            cls, azure_wrapper, template_uri, location, group_name,
            public_key, master_prefix, agent_prefix, admin_name, oauth_enabled,
            vm_size, agent_count, name_suffix, vm_diagnostics_enabled):
        # assert master_prefix != agent_prefix, 'Master and agents must have unique prefixs'
        # assert re.match('^[a-z][a-z0-9-]{1,61}[a-z0-9]$', master_prefix),\
        #     'Invalid master DNS prefix: {}'.format(master_prefix)
        # assert re.match('^[a-z][a-z0-9-]{1,61}[a-z0-9]$', agent_prefix),\
        #    'Invalid agent DNS prefix: {}'.format(agent_prefix)
        deployment_name = '{}-deployment'.format(group_name)
        try:
            r = azure_wrapper.put('resourcegroups/{}'.format(group_name), json={'location': location})
            r.raise_for_status()
            logging.info('Created ResourceGroup: {}'.format(r.json()))
            template_params = {
                'sshRSAPublicKey': public_key,
                # must be lower or validation will fail
                'masterEndpointDNSNamePrefix': master_prefix.lower(),
                'agentEndpointDNSNamePrefix': agent_prefix.lower(),
                'linuxAdminUsername': admin_name,
                'agentVMSize': vm_size,
                'agentCount': agent_count,
                'nameSuffix': name_suffix,
                'oauthEnabled': repr(oauth_enabled).lower(),
                # oauth uses string, vm diagnostic uses bool
                'enableVMDiagnostics': vm_diagnostics_enabled}
            logging.info('Provided template parameters: {}'.format(template_params))
            # add worthless required 'value' fields
            template_parameters = {k: {'value': v} for k, v in template_params.items()}
            r = azure_wrapper.post('resourcegroups/{group_name}/providers/Microsoft.Resources/'
                                   'deployments/{deployment_name}/validate'.format(group_name=group_name,
                                                                                   deployment_name=deployment_name),
                                   json={
                                       'properties': {
                                           'templateLink': {
                                               'uri': template_uri},
                                           'mode': 'Incremental',
                                           'parameters': template_parameters}})
            if r.status_code == 400:
                logging.error(r.json()['error']['details'])
            r.raise_for_status()
        except:
            azure_wrapper.delete('resourcegroups/{}'.format(group_name))
            raise


comment = """

class TemplateDeployment:
    def __init__(self, group_name, azure_wrapper):
        self.group_name = group_name  # each DC/OS deployment is assumed to be in its own, exclusive resource group
        self.azure_wrapper = azure_wrapper

    @classmethod
    def create(
            cls, azure_wrapper, template_uri, location, group_name,
            public_key, master_prefix, agent_prefix, admin_name, oauth_enabled,
            vm_size, agent_count, name_suffix, vm_diagnostics_enabled):


        # Resource group must be created before validation can occur
        if azure_wrapper.rmc.resource_groups.check_existence(group_name):
            raise Exception("Group name already exists / taken: {}".format(group_name))
        log.info('Starting resource group_creation')
        azure_wrapper.rmc.resource_groups.create_or_update(
            group_name,
            ResourceGroup(location=location))
        deployment_properties = DeploymentProperties(
            template_link=TemplateLink(uri=template_uri),
            mode=DeploymentMode.incremental,
            parameters=template_parameters)
        # Use RPC against azure to validate the ARM template is well-formed
        log.info('Validating template deployment')
        try:
            result = azure_wrapper.rmc.deployments.validate(
                group_name, deployment_name, properties=deployment_properties)
            if result.error:
                for details in result.error.details:
                    log.error('{}: {}'.format(details.code, details.message))
                raise Exception("Template verification failed!")
        except:
            # no point in leaving a fresh resource group with nothing in it around
            log.exception('Deployment is invalide, deleting provisioned resource group')
            azure_wrapper.rmc.resource_groups.delete(group_name)
            raise

        log.info('Starting template deployment')
        azure_wrapper.rmc.deployments.create_or_update(
            group_name, deployment_name, deployment_properties)

        new_deploy = cls(group_name, azure_wrapper)
        return new_deploy

    def wait_for_deployment(self, timeout=60 * 60):
        log.info('Waiting for deployment to finish')

        @retry(wait_fixed=30 * 1000, stop_max_delay=timeout * 1000,
               retry_on_result=lambda res: res is False,
               retry_on_exception=lambda ex: isinstance(ex, CloudError))
        def check_deployment_operations():
            deploy_state = self.azure_wrapper.rmc.deployments.get(
                self.group_name, DEPLOYMENT_NAME.format(self.group_name)).properties.provisioning_state
            if deploy_state == 'Succeeded':
                return True
            elif deploy_state == 'Failed':
                log.info('Deployment failed. Checking deployment operations...')
                deploy_ops = self.azure_wrapper.rmc.deployment_operations.list(
                    self.group_name, DEPLOYMENT_NAME.format(self.group_name))
                failures = [(op.properties.status_code, op.properties.status_message) for op
                            in deploy_ops if op.properties.provisioning_state == 'Failed']
                for failure in failures:
                    log.error('Deployment operation failed! {}: {}'.format(*failure))
                raise Exception('Deployment Failed!')
            else:
                log.info('Waiting for deployment. Current state: {}'.format(deploy_state))
                return False

        check_deployment_operations()

    def get_ip_buckets(self):
        ip_buckets = {
            'master': [],
            'private': [],
            'public': []}
        for resource in self.azure_wrapper.rmc.resource_groups.list_resources(
                self.group_name,
                filter=("resourceType eq 'Microsoft.Network/networkInterfaces' or "
                        "resourceType eq 'Microsoft.Compute/virtualMachineScaleSets'")):
            if resource.type == 'Microsoft.Network/networkInterfaces':
                nics = [self.azure_wrapper.nmc.network_interfaces.get(self.group_name, resource.name)]
            elif resource.type == 'Microsoft.Compute/virtualMachineScaleSets':
                nics = list(self.azure_wrapper.nmc.network_interfaces.list_virtual_machine_scale_set_network_interfaces(
                    virtual_machine_scale_set_name=resource.name, resource_group_name=self.group_name))
            else:
                raise('Unexpected resourceType: {}'.format(resource.type))

            for bucket_name in ip_buckets:
                if bucket_name in resource.name:
                    for n in nics:
                        for config in n.ip_configurations:
                            ip_buckets[bucket_name].append(config.private_ip_address)
        return ip_buckets

    @lazy_property
    def ip_buckets(self):
        return self.get_ip_buckets()

    def get_outputs(self):
        return {k: v['value'] for k, v in self.azure_wrapper.rmc.deployments.
                get(self.group_name, DEPLOYMENT_NAME.format(self.group_name)).properties.outputs.items()}

    @lazy_property
    def outputs(self):
        return self.get_outputs()

    def get_master_ips(self):
        return self.ip_buckets['master']

    def get_public_ips(self):
        return self.ip_buckets['public']

    def get_private_ips(self):
        return self.ip_buckets['private']

    def delete(self):
        log.info('Triggering delete')
        self.azure_wrapper.rmc.resource_groups.delete(self.group_name)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, exc_tb):
        self.delete()
"""

if __name__ == '__main__':
    ac = AzureClient(
        os.environ['AZURE_CLIENT_ID'],
        os.environ['AZURE_CLIENT_SECRET'],
        os.environ['AZURE_TENANT_ID'],
        os.environ['AZURE_SUBSCRIPTION_ID'])
    r = ac.get('resourcegroups')
    print(r.json())
    # r = ac.put('resourcegroups/foooo-barrr', json={'location': 'West US'})
    # print(r.status_code)
    # print(r.json())

    dcos = DcosResourceGroup.deploy(
        ac,
        os.environ['DCOS_TEMPLATE_URL'],
        'West US',
        'foo-bar-test-group',
        os.environ['AZURE_PUBLIC_SSH_KEY'],
        'asdfaeasf',  # master_prefix,
        '11aff333r3',  # agent_prefix,
        'dcos',  # admin_name,
        True,  # oauth_enabled,
        'Standard_D2',  # vm_size,
        2,  # agent_count,
        '12312',  # name_suffix,
        False)  # vm_diagnostics_enabled)
