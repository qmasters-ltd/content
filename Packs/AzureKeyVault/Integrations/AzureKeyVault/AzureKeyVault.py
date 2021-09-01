from CommonServerPython import *
from typing import Dict, Tuple, List
import requests
from datetime import datetime
import copy

'''CONSTANTS'''
APP_NAME = 'azure-key-vault'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

MANAGEMENT_RESOURCE = 'https://management.azure.com'
VAULT_RESOURCE = 'https://vault.azure.net'
VAULT_NAME_CONTEXT_FIELD = 'key_vault_name'

DEFAULT_LIMIT = 50
DEFAULT_OFFSET = 0


class KeyVaultClient:
    """
    Key Vault API Client
    """
    def __init__(self, tenant_id: str, client_id: str, client_secret: str,
                 subscription_id: str, resource_group_name: str,
                 verify: bool, proxy: bool):
        self._headers = {
            'Content-Type': 'application/json'
        }
        self.ms_client = MicrosoftClient(
            self_deployed=True,
            auth_id=client_id,
            enc_key=client_secret,
            token_retrieval_url=f'https://login.microsoftonline.com/{tenant_id}/oauth2/token',
            grant_type=CLIENT_CREDENTIALS,
            app_name=APP_NAME,
            base_url=f'https://management.azure.com/subscriptions/{subscription_id}/'
                     f'resourceGroups/{resource_group_name}/providers/Microsoft.KeyVault',
            verify=verify,
            proxy=proxy,
            multi_resource=True,
            resources=[MANAGEMENT_RESOURCE, VAULT_RESOURCE],
            resource='',
            scope='',
            tenant_id=tenant_id,
            ok_codes=(200, 201, 202, 204, 400, 401, 403, 404)
        )

    def http_request(self, method:str, url_suffix:str=None, full_url:str=None, params:dict={}, data:dict=None,
                     resource:str=MANAGEMENT_RESOURCE):
        """
        Wrapper to MicrosoftClient http_request method.

        """
        params['api-version'] = '2019-09-01' if resource == MANAGEMENT_RESOURCE else '7.2'
        res = self.ms_client.http_request(method=method,
                                          url_suffix=url_suffix,
                                          full_url=full_url,
                                          json_data=data,
                                          params=params,
                                          resp_type='response',
                                          return_empty_response=True,
                                          resource=resource
                                          )
        if res.text:
            res_json = res.json()
        else:  # in case an empty response returned line in delete key vault command
            res_json = {'status_code': res.status_code}

        return res_json

    """integration commands requests"""

    def create_or_update_key_vault_request(self, vault_name: str, object_id: str, location: str,
                                           sku_name: str,
                                           keys: List[str], secrets: List[str],
                                           certificates: List[str], storage: List[str], enabled_for_deployment: bool,
                                           enabled_for_disk_encryption: bool,
                                           enabled_for_template_deployment: bool,
                                           default_action: str, bypass: str, vnet_subnet_id: str,
                                           ignore_missing_vnet_service_endpoint: bool,
                                           ip_rules: List[str], private_endpoint_connection_id: str,
                                           private_endpoint_connection_etag: str,
                                           provisioning_state, private_endpoint_id, private_link_status: str,
                                           private_link_actions_required: str,
                                           private_link_description: str) -> Dict[str, Any]:
        """
        Create or update a key vault in the specified subscription.

        Args:
            vault_name (str): Key Vault name.
            object_id (str): The object ID of a user, service principal or security group in the Azure Active Directory.
            location (str): Key Vault supported Azure location.
            sku_name (str): Sku name.
            keys (List[str]): Permissions to keys.
            secrets (List[str]): Permissions to secrets.
            certificates (List[str]): Permissions to certificates.
            storage (List[str]): Permissions to storage accounts.
            enabled_for_deployment (bool): permission for Azure VM to retrieve certificates stored as secrets.
            enabled_for_disk_encryption (bool): permission for Azure Disk Encryption to retrieve secrets.
            enabled_for_template_deployment (bool): permission for Azure Resource Manager to retrieve secrets.
            default_action (str): The default action.
            bypass (str): bypass network rules.Network acl property.Default is 'AzureServices'.
            vnet_subnet_id:(str): Full resource id of a vnet subnet.
            ignore_missing_vnet_service_endpoint (bool): NRP will ignore the check.
            ip_rules List[str](optional) : The list of IP address rules.
            private_endpoint_connection_id (str) : Connection ID.
            private_endpoint_connection_etag (str): Connection Etag.
            provisioning_state(str): Provisioning state.
            private_endpoint_id: Full identifier of the private endpoint resource.
            private_link_status (str): Connection status.
            private_link_actions_required (str): Required actions.
            private_link_description (str):Reason for approval or rejection.

        Returns:
            Dict[str, Any]: API response from Azure.
        """
        # permissions property
        permissions = self.config_vault_permission(
            keys, secrets, certificates, storage)

        # network property
        network_acl = self.config_vault_network_acls(default_action, bypass, vnet_subnet_id,
                                                     ignore_missing_vnet_service_endpoint, ip_rules)
        # private end point connection property
        private_endpoint_connections = self.config_vault_private_endpoint_connections(private_endpoint_connection_id,
                                                                                      private_endpoint_connection_etag,
                                                                                      provisioning_state,
                                                                                      private_endpoint_id,
                                                                                      private_link_status,
                                                                                      private_link_actions_required,
                                                                                      private_link_description)

        properties = self.config_vault_properties(object_id, self.ms_client.tenant_id, enabled_for_deployment,
                                                  enabled_for_disk_encryption,
                                                  enabled_for_template_deployment, sku_name, permissions, network_acl,
                                                  private_endpoint_connections)

        data = {"location": location, "properties": properties}

        url_suffix = f'/vaults/{vault_name}'
        response = self.http_request('PUT', url_suffix=url_suffix, data=data)

        return response

    def delete_key_vault_request(self, vault_name: str) -> Dict[str, Any]:
        """
        Delete the specified key vault.

        Args:
            vault_name (str): Key Vault name.

        Returns:
            Dict[str, Any]: API response from Azure.
        """
        url_suffix = f'/vaults/{vault_name}'
        response = self.http_request('DELETE', url_suffix=url_suffix)

        return response

    def get_key_vault_request(self, vault_name: str) -> Dict[str, Any]:
        """
        Get the key vault by vault name argument.

        Args:
            vault_name (str): Key Vault name.

        Returns:
            Dict[str, Any]: API response from Azure.
        """
        url_suffix = f'/vaults/{vault_name}'
        response = self.http_request('GET', url_suffix=url_suffix)

        return response

    def list_key_vaults_request(self, limit: int, offset: int) -> List[dict]:
        """
        List key Vaults.

        Args:
            limit(int): limit the number of key vaults to return.Default is 50.
            offset(int): First index to retrieve from. Default is 0.
        Returns:
            Dict[str, Any]: API response from Azure.
        """
        url_suffix = '/vaults'
        response = self.http_request(
            'GET', url_suffix=url_suffix)
        return self.get_entities_independent_of_pages(response, limit, offset)

    def update_access_policy_request(self, vault_name: str, operation_kind: str, object_id: str,
                                     keys: List[str], secrets: List[str], certificates: List[str],
                                     storage: List[str]) -> Dict[str, Any]:
        """
        Update access policy of a Key Vault."

        Args:
            vault_name (str): Key Vault name.
            operation_kind (str): The operation to make on the access policy.
            object_id (str): The object ID of a user, service principal or security group in the Azure Active Directory.
            keys (List[str]): Permissions to keys.
            secrets (List[str]): Permissions to secrets.
            certificates (List[str]): Permissions to certificates.
            storage (List[str]): Permissions to storage accounts.

        Returns:
            Dict[str, Any]: API response from Azure.
        """
        permissions = self.config_vault_permission(
            keys, secrets, certificates, storage)
        data = {"properties": {"accessPolicies": [
            {"objectId": object_id, "permissions": permissions, "tenantId": self.ms_client.tenant_id}]}}
        url_suffix = f'/vaults/{vault_name}/accessPolicies/{operation_kind}'

        response = self.http_request('PUT', url_suffix=url_suffix, data=data)

        return response

    def get_key_request(self, vault_name: str, key_name: str, key_version: str) -> Dict[str, Any]:
        """
        Get the public part of a stored key.

        Args:
            vault_name (str): Key Vault name.
            key_name (str): Key name.
            key_version (str): Key version.

        Returns:
            Dict[str, Any]: API response from Azure.
        """

        url = f'https://{vault_name}.vault.azure.net/keys/{key_name}'
        if key_version:
            url = url + f'/{key_version}'
        response = self.http_request(
            'GET', full_url=url, resource=VAULT_RESOURCE)

        return response

    def list_keys_request(self, vault_name: str, limit: int, offset: int) -> List[dict]:
        """ List keys in the specified vault.

        Args:
            vault_name(str): Key Vault name.
            limit (str): Limit on the number of certificates to return. Default value is 50.
            offset(int): First index to retrieve from. Default value is 0.

        Returns:
            Dict[str, Any]: API response from Azure.

        """
        url = f'https://{vault_name}.vault.azure.net/keys'
        response = self.http_request(
            'GET', full_url=url, resource=VAULT_RESOURCE)

        return self.get_entities_independent_of_pages(response, limit, offset, VAULT_RESOURCE)

    def delete_key_request(self, vault_name: str, key_name: str) -> Dict[str, Any]:
        """
        Delete a key of any type from storage in Azure Key vault.

        Args:
            vault_name (str): key vault's name.
            key_name (str): The name of the key to delete.

        Returns:
            Dict[str, Any]: response json
        """
        url = f'https://{vault_name}.vault.azure.net/keys/{key_name}'
        response = self.http_request(
            'DELETE', full_url=url, resource=VAULT_RESOURCE)

        return response

    def get_secret_request(self, vault_name: str, secret_name: str, secret_version: str) -> Dict[str, Any]:
        """
        Get a specified secret from a given key vault.

        Args:
            vault_name (str): Key vault's name.
            secret_name (str): The name of the secret to retrieve.
            secret_version (str) : The version of the secret.
        Returns:
            Dict[str, Any]: API response from Azure.
        """
        url = f'https://{vault_name}.vault.azure.net/secrets/{secret_name}'
        if secret_version:
            url = url + f'/{secret_version}'
        response = self.http_request(
            'GET', full_url=url, resource=VAULT_RESOURCE)

        return response

    def list_secrets_request(self, vault_name: str, limit: int, offset: int) -> List[dict]:
        """
        List secrets in a specified key vault.

        Args:
            vault_name (str): Key Vault name.
            limit(int): Maximum number of secrets to retrieve.Default is 50.
            offset(int): First index to retrieve from. Default value is 0.

        Returns:
            Dict[str, Any]: API response from Azure.
        """
        url = f'https://{vault_name}.vault.azure.net/secrets'
        response = self.http_request(
            'GET', full_url=url, resource=VAULT_RESOURCE)

        return self.get_entities_independent_of_pages(response, limit, offset, VAULT_RESOURCE)

    def delete_secret_request(self, vault_name: str, secret_name: str) -> Dict[str, Any]:
        """
        Delete a secret from a specified key vault.

        Args:
            vault_name (str): Key vault's name.
            secret_name (str): The name of the secret to delete.

        Returns:
            Dict[str, Any]: API response from Azure.
        """
        url = f'https://{vault_name}.vault.azure.net/secrets/{secret_name}'
        response = self.http_request(
            'DELETE', full_url=url, resource=VAULT_RESOURCE)
        return response

    def get_certificate_request(self, vault_name: str, certificate_name: str, certificate_version: str) -> Dict[
        str, Any]:
        """
        Get a specified secret from a given key vault.

        Args:
            vault_name (str): key vault's name.
            certificate_name (str): the name of the certificate to retrieve.
            certificate_version(str): The version of the certificate
        Returns:
            Dict[str, Any]: API response from Azure.
        """
        url = f'https://{vault_name}.vault.azure.net/certificates/{certificate_name}'
        if certificate_version:
            url = url + f'/{certificate_version}'
        response = self.http_request(
            'GET', full_url=url,
            resource=VAULT_RESOURCE)

        return response

    def list_certificates_request(self, vault_name: str, limit: int, offset: int) -> List[dict]:
        """
        List certificates in a specified key vault.

        Args:
            vault_name (str): Key Vault name of the certificate.
            limit(int):maximum number of certificates to retrieve. Default is 50.
            offset (int): First index to retrieve from. Default value is 0.

        Returns:
            Dict[str, Any]: response json
        """
        url = f'https://{vault_name}.vault.azure.net/certificates'

        response = self.http_request(
            'GET', full_url=url, resource=VAULT_RESOURCE)

        return self.get_entities_independent_of_pages(response, limit, offset, VAULT_RESOURCE)

    def delete_certificate_request(self, vault_name: str, certificate_name: str) -> Dict[str, Any]:
        """
        List certificates in a specified key vault.

        Args:
            vault_name (str): key vault's name.
            certificate_name (str): the name of the certificate to delete.

        Returns:
            Dict[str, Any]: API response from Azure.
        """
        url = f'https://{vault_name}.vault.azure.net/certificates/{certificate_name}'
        response = self.http_request(
            'DELETE', full_url=url, resource=VAULT_RESOURCE)

        return response

    def get_certificate_policy_request(self, vault_name: str, certificate_name: str) -> Dict[str, Any]:
        """
        List the policy for a certificate.

        Args:
            vault_name (str): Key Vault name.
            certificate_name (str): the name of the certificate to retrieve it's policy.

        Returns:
            Dict[str, Any]: API response from Azure.
        """
        url = f'https://{vault_name}.vault.azure.net/certificates/{certificate_name}/policy'
        response = self.http_request(
            'GET', full_url=url, resource=VAULT_RESOURCE)

        return response

    ''' INTEGRATION HELPER METHODS  '''

    def config_vault_permission(self, keys: List[str], secrets: List[str], certificates: List[str],
                                storage: List[str]) -> Dict[str, Any]:
        """
        Returns the permissions field of an access policy property of a Key Vault.

        Args:
            keys (List[str]): Permissions to keys.
            secrets (List[str]): Permissions to secrets.
            certificates (List[str]): Permissions to certificates.
            storage (List[str]): Permissions to storage accounts.

        Returns:
            Dict[str,Any]: permissions.
        """
        permissions = {}
        if keys:
            permissions['keys'] = keys
        if secrets:
            permissions['secrets'] = secrets
        if certificates:
            permissions['certificates'] = certificates
        if storage:
            permissions['storage'] = storage
        return permissions

    def config_vault_network_acls(self, default_action: str, bypass: str, vnet_sub_id,
                                  ignore_missing_vnet_service_endpoint,
                                  ip_rules: List[str]) -> Dict[str, Any]:
        """
        Configures the network acl property of a Key Vault.

        Args:
            default_action (str): Default action.
            bypass (str): Tells what traffic can bypass network rules.
            vnet_sub_id (str): Full resource id of a vnet subnet.
            ignore_missing_vnet_service_endpoint (bool): Specify whether NRP will ignore the check.
            ip_rules (List[str]):The list of IP address rules.

        Returns:
            Dict[str,Any]: Network acls property.
        """
        network_acls = {}
        if default_action:
            network_acls['defaultAction'] = default_action
        if bypass:
            network_acls['bypass'] = bypass
        if vnet_sub_id:
            network_acls['virtualNetworkRules'] = [
                {'id': vnet_sub_id, 'ignoreMissingVnetServiceEndpoint': ignore_missing_vnet_service_endpoint}]

        if ip_rules:
            network_acls["ipRules"] = []
            for ip in ip_rules:
                network_acls["ipRules"].append({'value': ip})

        return network_acls

    def config_vault_private_endpoint_connections(self, private_endpoint_connection_id: str,
                                                  private_endpoint_connection_etag: str,
                                                  provisioning_state, private_endpoint_id, private_link_status: str,
                                                  private_link_actions_required: str, private_link_description: str) -> \
            Dict[str, Any]:
        """
        Configures the private_endpoint_connections property of a Key Vault .

        Args:
            private_endpoint_connection_id(str): Private endpoint connection ID.
            private_endpoint_connection_etag (str): Modified whenever there is a change in the state of private endpoint.
            provisioning_state (str): Provisioning state of the private endpoint connection.
            private_endpoint_id(str): Full identifier of the private endpoint resource.
            private_link_status (str): private link status.
            private_link_actions_required (str): Required actions message.
            private_link_description (str) The reason for approval or rejection.

        Returns:
            Dict[str,Any]: Private endpoint connections property.
        """

        private_endpoint_connections = {}

        if private_endpoint_connections:
            private_endpoint_connections['id'] = private_endpoint_connection_id
        if private_endpoint_connection_etag:
            private_endpoint_connections['etag'] = private_endpoint_connection_etag
        if provisioning_state:
            private_endpoint_connections['properties'] = {
                'provisioningState': provisioning_state,
                'privateEndpoint': {
                    'id': private_endpoint_id
                },
                'privateLinkServiceConnectionState': {
                    'status': private_link_status,
                    'actionsRequired': private_link_actions_required,
                    'description': private_link_description
                }
            }
        return private_endpoint_connections

    def config_vault_properties(self, object_id: str, tenant_id: str, enabled_for_deployment: bool,
                                enabled_for_disk_encryption: bool,
                                enabled_for_template_deployment: bool, sku_name: str,
                                permissions: Dict[str, Any], network_acls: Dict[str, Any],
                                private_endpoint_connections: Dict[str, Any]):

        """
        Configures the properties of a vault on create or update command.

        Args:
            object_id (str): The object ID of a user, service principal or security group in the Azure Active Directory.
            tenant_id (str):An identity that have access to the key vault.
            enabled_for_deployment (bool): permission for Azure VM to retrieve certificates stored as secrets.
            enabled_for_disk_encryption (bool): permission for Azure Disk Encryption to retrieve secrets.
            enabled_for_template_deployment (bool): permission for Azure Resource Manager to retrieve secrets.
            sku_name (str):Sku name.
            permissions (Dict[str,Any]): Key Vault access policy property.
            network_acls (Dict[str,Any]): Key Vault network acls property.
            private_endpoint_connections (Dict[str,Any]): Key Vault private endpoint connections property.

        Returns:
            Dict[str,Any]: Key Vault properties.
        """
        properties = {"accessPolicies": [
            {"objectId": object_id, "permissions": permissions,
             "tenantId": tenant_id}],
            "enabledForDeployment": enabled_for_deployment,
            "enabledForDiskEncryption": enabled_for_disk_encryption,
            "enabledForTemplateDeployment": enabled_for_template_deployment,
            "sku": {"family": "A", "name": sku_name}, "tenantId": tenant_id}

        if network_acls:
            properties["networkAcls"] = network_acls
        if private_endpoint_connections:
            properties["privateEndpointConnections"] = [private_endpoint_connections]
        return properties

    def get_entities_independent_of_pages(self, first_page: Dict[str, Any], limit: int, offset: int,
                                          resource=MANAGEMENT_RESOURCE) -> List[dict]:
        """
        List the entities independent of azure's page size.

        Args:
            first_page (Dict[str, Any]): The first list of entities which returned by the first API call.
            limit (int): limit on the number of entities to retrieve to the user.
            offset (int): first index to return from.
            resource (str): Azure resource. Default is MANAGEMENT_RESOURCE.

        Returns:
            List[Dict,Any]: List of Key Vaults/Keys/Secrets/Certificates.
        """
        entities = first_page.get('value')
        next_page_url = first_page.get('nextLink')
        # more entities to get
        while next_page_url and len(entities) < offset + limit:
            next_page_url = next_page_url.replace('api-version', 'api')
            response = self.http_request(
                'GET', full_url=next_page_url, resource=resource)

            entities = entities + response.get('value', [])
            next_page_url = response.get('nextLink')
        if offset > len(entities):
            return []
        return entities[offset:limit + offset]


''' INTEGRATIONS COMMANDS'''


def create_or_update_key_vault_command(client: KeyVaultClient, args: Dict[str, Any]) -> CommandResults:
    """
    Create or update key vault command.

    Args:
        client (KeyVaultClient):Azure Key Vault API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    vault_name = args.get('vault_name')
    location = args.get('location', 'westus')
    sku_name = args.get('sku_name', 'standard')
    object_id = args.get('object_id')

    # access policy arguments
    keys = argToList(args.get('keys', ['get', 'list', 'update', 'create','import', 'delete', 'recover', 'backup',
                                       'restore']))

    secrets = argToList(args.get('secrets', ['get', 'list','set', 'delete', 'recover', 'backup', 'restore']))
    certificates = argToList(
        args.get('certificates', ['get', 'list', 'update', 'create', 'import', 'delete', 'recover', 'backup', 'restore',
                                  'managecontacts',
                                  'manageissuers', 'getissuers', 'listissuers', 'setissuers', 'deleteissuers']))
    storage = argToList(args.get('storage', []))
    enabled_for_deployment = argToBoolean(
        args.get('enabled_for_deployment', True))
    enabled_for_disk_encryption = argToBoolean(
        args.get('enabled_for_disk_encryption', True))
    enabled_for_template_deployment = argToBoolean(args.get(
        'enabled_for_template_deployment', True))

    # network acl arguments
    default_action = args.get('default_action')
    bypass = args.get('bypass')
    vnet_subnet_id = args.get('vnet_subnet_id')
    ignore_missing_vnet_service_endpoint = argToBoolean(
        args.get('ignore_missing_vnet_service_endpoint', True))
    ip_rules = argToList(args.get('ip_rules'))

    # private endpoint connection arguments
    private_endpoint_connection_id = args.get('private_endpoint_connection_id')
    private_endpoint_connection_etag = args.get(
        'private_endpoint_connection_etag')
    private_link_status = args.get('private_link_status')
    private_link_description = args.get('private_link_description')
    private_link_actions_required = args.get('private_link_actions_required')
    provisioning_state = args.get('provisioning_state')
    private_endpoint_id = args.get('private_endpoint_id')

    response = client.create_or_update_key_vault_request(vault_name, object_id, location, sku_name, keys,
                                                         secrets, certificates, storage, enabled_for_deployment,
                                                         enabled_for_disk_encryption, enabled_for_template_deployment,
                                                         default_action, bypass, vnet_subnet_id,
                                                         ignore_missing_vnet_service_endpoint, ip_rules,
                                                         private_endpoint_connection_id,
                                                         private_endpoint_connection_etag,
                                                         provisioning_state, private_endpoint_id, private_link_status,
                                                         private_link_actions_required, private_link_description)

    readable_output = tableToMarkdown(f'{vault_name} Information',
                                      response,
                                      ['id', 'name', 'type', 'location'], removeNull=True,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.KeyVault',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=readable_output,
        ignore_auto_extract=True
    )

    return command_results


def delete_key_vault_command(client: KeyVaultClient, args: Dict[str, Any]) -> CommandResults:
    """
    Delete the key vault by a specified name.

    Args:
        client (KeyVaultClient):Azure Key Vault API client.
        args (Dict[str, Any]): Command arguments from XSOAR.
    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    vault_name = args.get('vault_name')
    response = client.delete_key_vault_request(vault_name)
    message = ""
    if response.get('status_code') == 200:
        message = f'Deleted Key Vault {vault_name} successfully.'
    elif response.get('status_code') == 204:
        message = f'Key Vault {vault_name} does not exists.'

    command_results = CommandResults(
        readable_output=message
    )

    return command_results


def get_key_vault_command(client: KeyVaultClient, args: Dict[str, Any]) -> CommandResults:
    """
    Get the key vault by a specified name.

    Args:
        client (KeyVaultClient):Azure Key Vault API client.
        args (Dict[str, Any]): Command arguments from XSOAR.
    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    vault_name = args.get('vault_name')

    response = client.get_key_vault_request(vault_name)
    readable_output = tableToMarkdown(f'{vault_name} Information',
                                      response,
                                      ['id', 'name', 'type', 'location'], removeNull=True,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.KeyVault',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=readable_output,
        ignore_auto_extract=True
    )

    return command_results


def list_key_vaults_command(client: KeyVaultClient, args: Dict[str, Any]) -> CommandResults:
    """ List the vaults associated with the subscription.

    Args:
        client (KeyVaultClient):Azure Key Vault API client
        args (Dict[str, Any]): Command arguments from XSOAR.
    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    offset = arg_to_number(args.get('offset', DEFAULT_OFFSET))
    response = client.list_key_vaults_request(limit, offset)
    readable_output = tableToMarkdown(
        f'Key Vaults List\n Current page size: {limit}\n Showing page 1 out others that may exist',
        response,
        ['id', 'name', 'type', 'location'], removeNull=True,
        headerTransform=string_to_table_header)

    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.KeyVault',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=readable_output,
        ignore_auto_extract=True)

    return command_results


def update_access_policy_command(client: KeyVaultClient, args: Dict[str, Any]) -> CommandResults:
    """
    Updates access policy of a key vault in the specified subscription.

    Args:
        client (KeyVaultClient):Azure Key Vault API client
        args (Dict[str, Any]): Command arguments from XSOAR.
    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    vault_name = args.get('vault_name')
    operation_kind = args.get('operation_kind')
    object_id = args.get('object_id')
    keys = argToList(args.get('keys'))
    secrets = argToList(args.get('secrets'))
    certificates = argToList(args.get('certificates'))
    storage_accounts = argToList(args.get('storage', []))

    response = client.update_access_policy_request(
        vault_name, operation_kind, object_id, keys, secrets, certificates, storage_accounts)

    readable_output = tableToMarkdown(f'{vault_name} Updated Access Policy',
                                      response,
                                      ['id', 'name', 'type', 'location'], removeNull=True,
                                      headerTransform=string_to_table_header)

    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.VaultAccessPolicy',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=readable_output,
        ignore_auto_extract=True
    )

    return command_results


def get_key_command(client: KeyVaultClient, args: Dict[str, Any]) -> CommandResults:
    """ Get the public part of a stored key.

    Args:
        client (KeyVaultClient): Azure Key Vault API client
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    vault_name = args.get('vault_name')
    key_name = args.get('key_name')
    key_version = args.get('key_version')

    response = client.get_key_request(vault_name, key_name, key_version)
    cloned_response = copy.deepcopy(response)
    output_key_info = convert_key_info_to_readable(cloned_response['key'])
    output_attrib = convert_attributes_to_readable(cloned_response['attributes'])

    outputs = {**output_key_info, **output_attrib}
    response['key_vault_name'] = vault_name
    readable_output = tableToMarkdown(f'{key_name} Information',
                                      outputs,
                                      ['key_id', 'json_web_key_type', 'key_operations', 'create_time', 'update_time',
                                       'expiry_time', 'enabled'],
                                      removeNull=True,
                                      headerTransform=string_to_table_header)

    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.Key',
        outputs_key_field='',
        outputs=response,
        raw_response=response,
        readable_output=readable_output,
        ignore_auto_extract=True
    )

    return command_results


def list_keys_command(client: KeyVaultClient, args: Dict[str, Any]) -> CommandResults:
    """
    List keys in the specified vault, in XSOAR's format, according to limit and offset arguments.

    Args:
        client (KeyVaultClient): Azure Key Vault API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    vault_name = args.get('vault_name')
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    offset = arg_to_number(args.get('offset', DEFAULT_OFFSET))
    response = client.list_keys_request(vault_name, limit, offset)
    readable_response = []
    for key in response:
        readable_response.append({
            'key_id': key.get('kid'), 'managed': key.get('managed'),
            **convert_attributes_to_readable(key.get('attributes')),
        })
        key[VAULT_NAME_CONTEXT_FIELD] = vault_name

    readable_output = tableToMarkdown(
        f'{vault_name} Keys List\n Current page size: {limit}\n Showing page 1 out others that may exist',
        readable_response,
        ['key_id', 'managed', 'create_time', 'update_time', 'expiry_time'],
        removeNull=True,
        headerTransform=string_to_table_header)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.Key',
        outputs_key_field='kid',
        outputs=response,
        raw_response=response,
        readable_output=readable_output,
        ignore_auto_extract=True
    )

    return command_results


def delete_key_command(client: KeyVaultClient, args: Dict[str, Any]) -> CommandResults:
    """
    Delete a key of any type from storage in Azure Key vault.

    Args:
        client (KeyVaultClient): Azure Key Vault API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    vault_name = args.get('vault_name')
    key_name = args.get('key_name')
    response = client.delete_key_request(vault_name, key_name)
    readable_response = response.copy()

    readable_response['recovery_id'] = readable_response['recoveryId']
    readable_response['deleted_date'] = convert_timestamp_to_readable_date(
        readable_response['deletedDate'])
    readable_response['scheduled_purge_date'] = convert_timestamp_to_readable_date(
        readable_response['scheduledPurgeDate'])
    response[VAULT_NAME_CONTEXT_FIELD] = vault_name
    readable_output = tableToMarkdown(f'Delete {key_name}',
                                      {**readable_response, **convert_key_info_to_readable(readable_response['key'])},
                                      ['key_id', 'recovery_id', 'deleted_date',
                                       'scheduled_purge_date'],
                                      removeNull=True,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.Key',
        outputs_key_field='recoveryId',
        outputs=response,
        raw_response=response,
        readable_output=readable_output,
        ignore_auto_extract=True
    )

    return command_results


def get_secret_command(client: KeyVaultClient, args: Dict[str, Any]) -> CommandResults:
    """
    Get a specified secret from a given key vault

    Args:
        client (KeyVaultClient):  Azure Key Vault API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    vault_name = args.get('vault_name')
    secret_name = args.get('secret_name')
    secret_version = args.get('secret_version')
    response = client.get_secret_request(
        vault_name, secret_name, secret_version)

    readable_response = {'secret_id': response.get('id'), 'managed': response.get('managed'),
                         'key_id': response.get('kid'),
                         **convert_attributes_to_readable(response.get('attributes').copy())}
    response[VAULT_NAME_CONTEXT_FIELD]=vault_name
    readable_output = tableToMarkdown(f'{secret_name} Information',
                                      readable_response,
                                      ['secret_id', 'managed', 'create_time', 'update_time', 'expiry_time'],
                                      removeNull=True,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.Secret',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=readable_output,
        ignore_auto_extract=True
    )

    return command_results


def list_secrets_command(client: KeyVaultClient, args: Dict[str, Any]) -> CommandResults:
    """
    List secrets in a specified key vault.

    Args:
        client (KeyVaultClient): Azure Key Vault API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    vault_name = args.get('vault_name')
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    offset = arg_to_number(args.get('offset', DEFAULT_OFFSET))
    response = client.list_secrets_request(vault_name, limit, offset)
    readable_response = []

    for secret in response:
        readable_response.append({
            'secret_id': secret.get('id'), 'managed': secret.get('managed'),
            **convert_attributes_to_readable(secret.get('attributes'))
        })
        secret[VAULT_NAME_CONTEXT_FIELD] = vault_name

    readable_output = tableToMarkdown(
        f'{vault_name} Secrets List\n Current page size: {limit}\n Showing page 1 out others that may exist',
        readable_response,
        ['secret_id', 'managed', 'create_time', 'update_time', 'expiry_time'], removeNull=True,
        headerTransform=string_to_table_header)

    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.Secret',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=readable_output,
        ignore_auto_extract=True
    )

    return command_results


def delete_secret_command(client: KeyVaultClient, args: Dict[str, Any]) -> CommandResults:
    """
    Delete a secret from a specified key vault.
    Args:
        client (KeyVaultClient): Azure Key Vault API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    vault_name = args.get('vault_name')
    secret_name = args.get('secret_name')

    response = client.delete_secret_request(vault_name, secret_name)
    readable_response = response.copy()
    readable_response['recovery_id'] = readable_response['recoveryId']
    readable_response['deleted_date'] = convert_timestamp_to_readable_date(
        readable_response['deletedDate'])
    readable_response['scheduled_purge_date'] = convert_timestamp_to_readable_date(
        readable_response['scheduledPurgeDate'])
    response[VAULT_NAME_CONTEXT_FIELD] = vault_name
    readable_output = tableToMarkdown(f'Delete {secret_name}',
                                      readable_response,
                                      ['id', 'recovery_id', 'deleted_date', 'scheduled_purge_date'
                                       ], removeNull=True,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.Secret',
        outputs_key_field='recoveryId',
        outputs=response,
        raw_response=response,
        readable_output=readable_output,
        ignore_auto_extract=True
    )

    return command_results


def get_certificate_command(client: KeyVaultClient, args: Dict[str, Any]) -> CommandResults:
    """
    Get information about a certificate.

    Args:
        client (KeyVaultClient): Azure Key Vault API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    vault_name = args.get('vault_name')
    certificate_name = args.get('certificate_name')
    certificate_version = args.get('certificate_version')
    response = client.get_certificate_request(
        vault_name, certificate_name, certificate_version)

    readable_response = {'certificate_id': response.get(
        'id'), **convert_attributes_to_readable(response.get('attributes'))}
    response[VAULT_NAME_CONTEXT_FIELD] = vault_name
    readable_output = tableToMarkdown(f'{certificate_name} Information',
                                      readable_response,
                                      ['certificate_id', 'create_time', 'update_time', 'expiry_time'], removeNull=True,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.Certificate',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=readable_output,
        ignore_auto_extract=True
    )

    return command_results


def list_certificates_command(client: KeyVaultClient, args: Dict[str, Any]) -> CommandResults:
    """
    List certificates in a specified key vault.

    Args:
        client (KeyVaultClient): Azure Key Vault API client.
        args (Dict[str, Any]): Command arguments from XSOAR.


    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    vault_name = args.get('vault_name')
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    offset = arg_to_number(args.get('offset', DEFAULT_OFFSET))

    response = client.list_certificates_request(vault_name, limit, offset)

    readable_response = []
    for certificate in response:
        readable_response.append({
            'certificate_id': certificate.get('id'),
            **convert_attributes_to_readable(certificate.get('attributes'))
        })
        certificate[VAULT_NAME_CONTEXT_FIELD] = vault_name
    readable_output = tableToMarkdown(
        f'{vault_name} Certificates List\n Current page size: {limit}\n Showing page 1 out others that may exist',
        readable_response,
        ['certificate_id', 'managed', 'create_time', 'update_time', 'expiry_time'],
        removeNull=True,
        headerTransform=string_to_table_header)

    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.Certificate',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=readable_output,
        ignore_auto_extract=True
    )

    return command_results


def get_certificate_policy_command(client: KeyVaultClient, args: Dict[str, Any]) -> CommandResults:
    """
    List the policy for a certificate.

    Args:
        client (KeyVaultClient):  Azure Key Vault API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    vault_name = args.get('vault_name')
    certificate_name = args.get('certificate_name')
    response = client.get_certificate_policy_request(
        vault_name, certificate_name)

    response['CertificateName'] = certificate_name

    readable_output = tableToMarkdown(f'{certificate_name} Policy Information',
                                      response,
                                      ['id', 'key_props', 'secret_props', 'x509_props', 'issuer', 'attributes'],
                                      removeNull=True, headerTransform=string_to_table_header)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.CertificatePolicy',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=readable_output
    )

    return command_results


def test_module(client: KeyVaultClient) -> None:
    client.ms_client.get_access_token(resource=MANAGEMENT_RESOURCE)
    client.ms_client.get_access_token(resource=VAULT_RESOURCE)
    return_results('ok')


####helper functions####
def convert_attributes_to_readable(attributes: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert attributes fields to be readable for the user.

    Args:
        attributes (Dict[str, Any]): Object attributes field.

    Returns:
        Dict[str, Any] : Readable attributes.

    """
    attributes_fields_mapper = {'nbf': 'should_not_be_retrieved_Before',
                                'exp': 'expiry_time',
                                'created': 'create_time',
                                'updated': 'update_time',
                                'recoveryLevel': 'recovery_level'
                                }

    for key, value in attributes_fields_mapper.items():
        if key in attributes:
            if key != 'recoveryLevel':
                attributes[value] = convert_timestamp_to_readable_date(attributes.pop(key))
            else:
                attributes[value] = attributes.pop(key)
    return attributes


def convert_key_info_to_readable(key_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert key fields to be readable for the user.

    Args:
        key_info (Dict[str, Any]): key field of Key object.

    Returns:
        Dict[str, Any] : Readable key information.

    """
    key_fields = {'kid': 'key_id',
                  'kty': 'json_web_key_type',
                  'key_ops': 'key_operations',
                  'n': 'RSA_modulus',
                  'e': 'RSA_public_components',
                  }
    for key, value in key_fields.items():
        if key in key_info:
            key_info[value] = key_info.pop(key)

    return key_info


def convert_timestamp_to_readable_date(timestamp: int) -> str:
    """
    Convert timestamp number to readable date.
    Args:
        timestamp (Dict[str, Any]): timestamp as integer.

    Returns:
        str : Date in ISO 8601 format.
    """
    return datetime.fromtimestamp(timestamp).isoformat()


def main() -> None:
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        client: KeyVaultClient = KeyVaultClient(tenant_id=params.get('tenant_id', None),
                                                client_id=params.get(
                                                    'client_id', None),
                                                client_secret=params.get(
                                                    'client_secret', None),
                                                subscription_id=params.get(
                                                    'subscription_id', None),
                                                resource_group_name=params.get(
                                                    'resource_group_name', None),
                                                verify=verify_certificate,
                                                proxy=proxy)

        commands = {
            'azure-key-vault-key-vault-create-or-update': create_or_update_key_vault_command,
            'azure-key-vault-key-vault-delete': delete_key_vault_command,
            'azure-key-vault-key-vault-get': get_key_vault_command,
            'azure-key-vault-key-vault-list': list_key_vaults_command,
            'azure-key-vault-key-vault-access-policy-update': update_access_policy_command,
            'azure-key-vault-key-get': get_key_command,
            'azure-key-vault-key-list': list_keys_command,
            'azure-key-vault-key-delete': delete_key_command,
            'azure-key-vault-secret-get': get_secret_command,
            'azure-key-vault-secret-list': list_secrets_command,
            'azure-key-vault-secret-delete': delete_secret_command,
            'azure-key-vault-certificate-get': get_certificate_command,
            'azure-key-vault-certificate-list': list_certificates_command,
            'azure-key-vault-certificate-policy-get': get_certificate_policy_command
        }

        if command == 'test-module':
            test_module(client)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))





from MicrosoftApiModule import *  # noqa: E402

if __name__ in ["builtins", "__main__"]:
    main()