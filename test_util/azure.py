"""Working with azure effectively requires a few too many individual clients
with rather specific APIs. This module is intended to give the most basic functionality
to accomodate DC/OS testing
"""
import logging
import re

import azure.common.credentials
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource.resources import ResourceManagementClient
from azure.mgmt.resource.resources.models import (DeploymentMode,
                                                  DeploymentProperties,
                                                  ResourceGroup, TemplateLink)
from msrestazure.azure_exceptions import CloudError
from retrying import retry

from test_util.helpers import lazy_property


# Very noisy loggers that do not help much in debug mode
logging.getLogger("msrest").setLevel(logging.INFO)
logging.getLogger("requests_oauthlib").setLevel(logging.INFO)
log = logging.getLogger(__name__)

# This interface is designed to only use a single deployment
# Being as the azure interface is based around resource groups, deriving
# deployment name from group names makes it easier to attach to creating deploys
DEPLOYMENT_NAME = '{}-Deployment'


class AzureWrapper:
    def __init__(self, subscription_id, tenant_id, client_id, client_secret):
        self.credentials = azure.common.credentials.ServicePrincipalCredentials(
            client_id=client_id,
            secret=client_secret,
            tenant=tenant_id)
        self.rmc = ResourceManagementClient(self.credentials, subscription_id)
        self.nmc = NetworkManagementClient(self.credentials, subscription_id)


class TemplateDeployment:
    def __init__(self, group_name, azure_wrapper):
        # each template deployment is a resource group
        self.group_name = group_name
        self.azure_wrapper = azure_wrapper

    @classmethod
    def create(
            cls, azure_wrapper, template_uri, location, group_name,
            public_key, master_prefix, agent_prefix, admin_name, oauth_enabled,
            vm_size, agent_count, name_suffix, vm_diagnostics_enabled):
        """ Creates a new resource group and deploys the DC/OS template to it
        """
        assert master_prefix != agent_prefix, 'Master and agents must have unique prefixs'
        assert re.match('^[a-z][a-z0-9-]{1,61}[a-z0-9]$', master_prefix),\
            'Invalid master DNS prefix: {}'.format(master_prefix)
        assert re.match('^[a-z][a-z0-9-]{1,61}[a-z0-9]$', agent_prefix),\
            'Invalid agent DNS prefix: {}'.format(agent_prefix)

        deployment_name = DEPLOYMENT_NAME.format(group_name)

        # Resource group must be created before validation can occur
        if azure_wrapper.rmc.resource_groups.check_existence(group_name):
            raise Exception("Group name already exists / taken: {}".format(group_name))
        log.info('Starting resource group_creation')
        azure_wrapper.rmc.resource_groups.create_or_update(
            group_name,
            ResourceGroup(location=location))

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
        log.info('Provided template parameters: {}'.format(template_params))
        # add worthless required 'value' fields
        template_parameters = {k: {'value': v} for k, v in template_params.items()}
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
        """
        Azure will not register a template instantly after deployment, so
        CloudError must be expected as retried. Once the ops are retrieved, this
        loops through all operations in the group's only deployment
        if any operations are still in progress, then this function will sleep
        once all operations are complete, if there any failures, those will be
        printed to the log stream
        """
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
