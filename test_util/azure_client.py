"""
The real REST API spec:
https://msdn.microsoft.com/en-us/library/azure/mt163658.aspx
"""
import os
import logging
from pprint import pprint
from urllib.parse import urlparse

import requests

from test_util.helpers import ApiClient

LOGGING_FORMAT = '[%(asctime)s|%(name)s|%(levelname)s]: %(message)s'
logging.basicConfig(format=LOGGING_FORMAT, level=logging.DEBUG)


class AzureClient(ApiClient):
    """See:
    https://docs.microsoft.com/en-us/rest/api/
    """

    def __init__(self, resource_url, client_id, client_secret, tenant_id, subscription_id):
        super().__init__(default_host_url=resource_url, api_base='subscriptions/{}'.format(subscription_id))
        self.resource_url = resource_url
        assert resource_url.endswith('/'), 'Azure API resources must end with forward slash'
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id
        self.subscription_id = subscription_id
        parse_result = urlparse(resource_url)
        self.host = parse_result.netloc.split(':')[0]

    def authenticate(self):
        """See:
        https://docs.microsoft.com/en-us/azure/active-directory/active-directory-protocols-oauth-service-to-service
        https://docs.microsoft.com/en-us/azure/active-directory/active-directory-protocols-oauth-code
        """
        params = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'resource': self.resource_url}
        r = requests.post(
            'https://login.microsoftonline.com/{}/oauth2/token'.format(self.tenant_id),
            data=params)
        r.raise_for_status()
        self.access_token = r.json()['access_token']
        self.default_headers = {
            'Authorization': 'Bearer {}'.format(self.access_token),
            'Host': self.host}


if __name__ == '__main__':
    ac = AzureClient(
        'https://management.azure.com/',
        os.environ['AZURE_CLIENT_ID'],
        os.environ['AZURE_CLIENT_SECRET'],
        os.environ['AZURE_TENANT_ID'],
        os.environ['AZURE_SUBSCRIPTION_ID'])
    ac.authenticate()
    print(ac.access_token)
    r = ac.get('resourcegroups?api-version=2016-09-01'.format(ac.subscription_id))
    r.raise_for_status()
    pprint(r.json())
