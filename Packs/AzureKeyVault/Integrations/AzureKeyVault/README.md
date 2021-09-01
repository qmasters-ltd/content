Use Key Vault to safeguard and manage cryptographic keys and secrets used by cloud applications and services
This integration was integrated and tested with version xx of AzureKeyVault

## Configure AzureKeyVault on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AzureKeyVault.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Client ID | True |
    | Client Secret | True |
    | Tenant ID | True |
    | Subscription ID | True |
    | Resource Group Name | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### azure-key-vault-key-vault-create-or-update
***
Create or update a key vault in the specified subscription.


#### Base Command

`azure-key-vault-key-vault-create-or-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | The name of the Key Vault to create or to update. | Required | 
| location | The supported Azure location where the key vault should be created.Defaults to westus. Possible values are: eastus, eastus2, southcentralus, westus2, australiaeast, southeastasia, northeurope, uksouth, westeurope, centralus, northcentralus, westus, southafricanorth, centralindia, eastasia, japaneast, jioindiawest, koreacentral, canadacentral, francecentral, germanywestcentral, norwayeast, switzerlandnorth, uaenorth, brazilsouth, centralusstage, eastusstage, eastus2stage, northcentralusstage, southcentralusstage, westusstage, westus2stage, asia, asiapacific, australia, brazil, canada, europe, global, india, japan, uk, unitedstates, eastasiastage, southeastasiastage, centraluseuap, eastus2euap, westcentralus, westus3, southafricawest, australiacentral, australiacentral2, australiasoutheast, japanwest, koreasouth, southindia, westindia, canadaeast, francesouth, germanynorth, norwaywest, switzerlandwest, ukwest, uaecentral, brazilsoutheast. | Optional | 
| sku_name | SKU name to specify whether the key vault is a standard vault or a premium vault.Defaults to standard. Possible values are: standard, premium. | Optional | 
| object_id | The object ID of a user, service principal or security group in the Azure Active Directory tenant for the vault. The object ID must be unique for the list of access policies. | Required | 
| keys | Permissions to keys.Defaults to:[get,list,create,update,import,delete,backup,restore,recover]. Possible values are: encrypt, decrypt, wrapKey, unwrapKey, sign, verify, get, list, create, update, import, delete, backup, restore, recover, purge. | Optional | 
| secrets | Permissions to secrets. Defaults to [get,list,set,delete,backup,restore,recover]. Possible values are: get, list, set, delete, backup, restore, recover, purge. | Optional | 
| certificates | Permissions to certificates. Defaults to [get,list,delete,create,import,update,managecontacts,getissuers,listissuers,setissuers,deleteissuers,manageissuers,recover]. Possible values are: get, list, delete, create, import, update, managecontacts, getissuers, listissuers, setissuers, deleteissuers, manageissuers, recover, purge. | Optional | 
| enabled_for_deployment | Property to specify whether Azure Virtual Machines are permitted to retrieve certificates stored as secrets from the key vault. Defaults to True. Possible values are: true, false. | Optional | 
| enabled_for_disk_encryption | Property to specify whether Azure Disk Encryption is permitted to retrieve secrets from the vault and unwrap keys. Defaults to True. Possible values are: true, false. | Optional | 
| enabled_for_template_deployment | Property to specify whether Azure Resource Manager is permitted to retrieve secrets from the key vault. Defaults to True. Possible values are: true, false. | Optional | 
| default_action | The default action when no rule from ipRules and from virtualNetworkRules match. This is only used after the bypass property has been evaluated.(Network acl property). Possible values are: Allow, Deny. | Optional | 
| bypass | Tells what traffic can bypass network rules. This can be 'AzureServices' or 'None'. If not specified the default is 'AzureServices'.(Network acl property). Possible values are: AzureServices. | Optional | 
| vnet_subnet_id | Full resource id of a vnet subnet, such as '/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/test-vnet/subnets/subnet1'.(Virtual network rule property of network acl). | Optional | 
| ignore_missing_vnet_service_endpoint | Property to specify whether NRP will ignore the check if parent subnet has serviceEndpoints configured.(Virtual network rule property of network acl). Possible values are: . Default is True. | Optional | 
| ip_rules | The list of IP address rules. each rule governing the accessibility of a vault from a specific ip address or ip range. for example:" 11.94.1.2/32". (Network acl property). | Optional | 
| storage | Permissions to storage accounts. | Optional | 
| private_endpoint_id | Full identifier of the private endpoint resource.(private endpoint connection property). | Optional | 
| provisioning_state | Provisioning state of the private endpoint connection.(private endpoint connection property). Possible values are: Creating, Deleting, Disconnected, Failed, Succeeded, Updating. | Optional | 
| private_link_actions_required | A message indicating if changes on the service provider require any updates on the consumer.(private endpoint connections property). | Optional | 
| private_link_description | The reason for approval or rejection.<br/>(private endpoint connections property. | Optional | 
| private_link_status | Indicates whether the connection has been approved, rejected or removed by the key vault owner. (private endpoint connections property. Possible values are: Approved, Disconnected, Pending, Rejected. | Optional | 
| private_endpoint_connection_etag | Modified whenever there is a change in the state of private endpoint connection.(private endpoint connection property). | Optional | 
| private_endpoint_connection_id | Id of private endpoint connection.(private endpoint connection property). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKeyVault.KeyVault.id | String | resource id | 
| AzureKeyVault.KeyVault.name | String | key vault name | 
| AzureKeyVault.KeyVault.type | String | resource type in Azure | 
| AzureKeyVault.KeyVault.location | String | Key Vault location | 
| AzureKeyVault.KeyVault.properties.sku.family | String | SKU family name. | 
| AzureKeyVault.KeyVault.properties.sku.name | String | SKU name to specify whether the key vault is a standard vault or a premium vault. | 
| AzureKeyVault.KeyVault.properties.tenantId | String | The Azure Active Directory tenant ID that should be used for authenticating requests to the key vault. | 
| AzureKeyVault.KeyVault.properties.accessPolicies.tenantId | String | The Azure Active Directory tenant ID that should be used for authenticating requests to the key vault. | 
| AzureKeyVault.KeyVault.properties.accessPolicies.objectId | String | The object ID of a user, service principal or security group in the Azure Active Directory tenant for the vault. The object ID must be unique for the list of access policies. | 
| AzureKeyVault.KeyVault.properties.accessPolicies.permissions.keys | Unknown | Permissions to keys | 
| AzureKeyVault.KeyVault.properties.accessPolicies.permissions.secrets | Unknown | Permissions to secrets | 
| AzureKeyVault.KeyVault.properties.accessPolicies.permissions.certificates | Unknown | Permissions to certificates | 
| AzureKeyVault.KeyVault.properties.enabledForDeployment | Boolean | Property to specify whether Azure Virtual Machines are permitted to retrieve certificates stored as secrets from the key vault. | 
| AzureKeyVault.KeyVault.properties.enabledForDiskEncryption | Boolean | Property to specify whether Azure Disk Encryption is permitted to retrieve secrets from the vault and unwrap keys. | 
| AzureKeyVault.KeyVault.properties.enabledForTemplateDeployment | Boolean | Property to specify whether Azure Resource Manager is permitted to retrieve secrets from the key vault. | 
| AzureKeyVault.KeyVault.properties.vaultUri | String | The URI of the vault for performing operations on keys and secrets. This property is readonly

 | 
| AzureKeyVault.KeyVault.properties.provisioningState | String | The current provisioning state..

 | 


#### Command Example
```!azure-key-vault-key-vault-create-or-update object_id=d2e31ea2-4d20-4288-9964-6be71766fba5 vault_name=xsoar-test-33 keys=create,decrypt```

#### Context Example
```json
{
    "AzureKeyVault": {
        "KeyVault": {
            "id": "/subscriptions/a213e459-7e7b-4d5d-b46a-26a8a71f6214/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-test-33",
            "location": "westus",
            "name": "xsoar-test-33",
            "properties": {
                "accessPolicies": [
                    {
                        "objectId": "d2e31ea2-4d20-4288-9964-6be71766fba5",
                        "permissions": {
                            "certificates": [
                                "get",
                                "list",
                                "delete",
                                "create",
                                "import",
                                "update",
                                "managecontacts",
                                "getissuers",
                                "listissuers",
                                "setissuers",
                                "deleteissuers",
                                "manageissuers",
                                "recover"
                            ],
                            "keys": [
                                "create",
                                "decrypt"
                            ],
                            "secrets": [
                                "get",
                                "list",
                                "set",
                                "delete",
                                "backup",
                                "restore",
                                "recover"
                            ]
                        },
                        "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd"
                    }
                ],
                "enableSoftDelete": true,
                "enabledForDeployment": true,
                "enabledForDiskEncryption": true,
                "enabledForTemplateDeployment": true,
                "networkAcls": {
                    "bypass": "AzureServices",
                    "defaultAction": "Deny",
                    "ipRules": [
                        {
                            "value": "11.94.1.2/32"
                        }
                    ],
                    "virtualNetworkRules": [
                        {
                            "id": "/subscriptions/a213e459-7e7b-4d5d-b46a-26a8a71f6214/resourcegroups/test-group/providers/microsoft.network/virtualnetworks/key-vault-vn/subnets/test-subnet",
                            "ignoreMissingVnetServiceEndpoint": true
                        }
                    ]
                },
                "provisioningState": "Succeeded",
                "sku": {
                    "family": "A",
                    "name": "standard"
                },
                "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd",
                "vaultUri": "https://xsoar-test-33.vault.azure.net/"
            },
            "tags": {},
            "type": "Microsoft.KeyVault/vaults"
        }
    }
}
```

#### Human Readable Output

>### xsoar-test-33 Information
>|Id|Name|Type|Location|Properties|
>|---|---|---|---|---|
>| /subscriptions/a213e459-7e7b-4d5d-b46a-26a8a71f6214/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-test-33 | xsoar-test-33 | Microsoft.KeyVault/vaults | westus | sku: {"family": "A", "name": "standard"}<br/>tenantId: 0dd6c060-d39a-4e06-873c-48a43c2e24dd<br/>networkAcls: {"bypass": "AzureServices", "defaultAction": "Deny", "ipRules": [{"value": "11.94.1.2/32"}], "virtualNetworkRules": [{"id": "/subscriptions/a213e459-7e7b-4d5d-b46a-26a8a71f6214/resourcegroups/test-group/providers/microsoft.network/virtualnetworks/key-vault-vn/subnets/test-subnet", "ignoreMissingVnetServiceEndpoint": true}]}<br/>accessPolicies: {'tenantId': '0dd6c060-d39a-4e06-873c-48a43c2e24dd', 'objectId': 'd2e31ea2-4d20-4288-9964-6be71766fba5', 'permissions': {'keys': ['create', 'decrypt'], 'secrets': ['get', 'list', 'set', 'delete', 'backup', 'restore', 'recover'], 'certificates': ['get', 'list', 'delete', 'create', 'import', 'update', 'managecontacts', 'getissuers', 'listissuers', 'setissuers', 'deleteissuers', 'manageissuers', 'recover']}}<br/>enabledForDeployment: true<br/>enabledForDiskEncryption: true<br/>enabledForTemplateDeployment: true<br/>enableSoftDelete: true<br/>vaultUri: https://xsoar-test-33.vault.azure.net/<br/>provisioningState: Succeeded |


### azure-key-vault-key-vault-delete
***
Deletes the specified key vault


#### Base Command

`azure-key-vault-key-vault-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | The name of the vault to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-key-vault-key-vault-delete vault_name=xsoar-readme-test```

#### Context Example
```json
{
    "AzureKeyVault": {
        "KeyVault": {
            "status_code": 200
        }
    }
}
```

#### Human Readable Output

>### Delete xsoar-readme-test
>|Message|
>|---|
>| Deleted xsoar-readme-test successfully. |


### azure-key-vault-key-vault-get
***
Gets the specified key vault.


#### Base Command

`azure-key-vault-key-vault-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | key vault's name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKeyVault.KeyVault.id | String | resource id. | 
| AzureKeyVault.KeyVault.name | String | key vault name. | 
| AzureKeyVault.KeyVault.type | String | resource type in Azure. | 
| AzureKeyVault.KeyVault.location | String | Key Vault location. | 
| AzureKeyVault.KeyVault.properties.sku.family | String | SKU family name. | 
| AzureKeyVault.KeyVault.properties.sku.name | String | SKU name to specify whether the key vault is a standard vault or a premium vault. | 
| AzureKeyVault.KeyVault.properties.tenantId | String | The Azure Active Directory tenant ID that should be used for authenticating requests to the key vault. | 
| AzureKeyVault.KeyVault.properties.accessPolicies.tenantId | String | The Azure Active Directory tenant ID that should be used for authenticating requests to the key vault | 
| AzureKeyVault.KeyVault.properties.accessPolicies.objectId | String | The object ID of a user, service principal or security group in the Azure Active Directory tenant for the vault. The object ID must be unique for the list of access policies. | 
| AzureKeyVault.KeyVault.properties.accessPolicies.permissions.keys | Unknown | Permissions to keys | 
| AzureKeyVault.KeyVault.properties.accessPolicies.permissions.secrets | Unknown | Permissions to secrets | 
| AzureKeyVault.KeyVault.properties.accessPolicies.permissions.certificates | Unknown | Permissions to certificates | 
| AzureKeyVault.KeyVault.properties.enabledForDeployment | Boolean | Property to specify whether Azure Virtual Machines are permitted to retrieve certificates stored as secrets from the key vault. | 
| AzureKeyVault.KeyVault.properties.enabledForDiskEncryption | Boolean | Property to specify whether Azure Disk Encryption is permitted to retrieve secrets from the vault and unwrap keys. | 
| AzureKeyVault.KeyVault.properties.enabledForTemplateDeployment | Boolean | Property to specify whether Azure Resource Manager is permitted to retrieve secrets from the key vault. | 
| AzureKeyVault.KeyVault.properties.enableSoftDelete | Boolean | Property to specify whether the 'soft delete' functionality is enabled for this key vault. If it's not set to any value\(true or false\) when creating new key vault, it will be set to true by default. Once set to true, it cannot be reverted to false. | 
| AzureKeyVault.KeyVault.properties.vaultUri | String | The URI of the vault for performing operations on keys and secrets. This property is readonly | 


#### Command Example
```!azure-key-vault-key-vault-get vault_name=xsoar-test-vault```

#### Context Example
```json
{
    "AzureKeyVault": {
        "KeyVault": {
            "id": "/subscriptions/a213e459-7e7b-4d5d-b46a-26a8a71f6214/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-test-vault",
            "location": "eastus",
            "name": "xsoar-test-vault",
            "properties": {
                "accessPolicies": [
                    {
                        "applicationId": "55f9764e-300a-474a-a2bb-549cece85439",
                        "objectId": "29a0b3b6-e8ea-4586-ae25-bc39cace0e67",
                        "permissions": {
                            "certificates": [
                                "Get",
                                "List",
                                "Update",
                                "Create",
                                "Import",
                                "Delete",
                                "Recover",
                                "Backup",
                                "Restore",
                                "ManageContacts",
                                "ManageIssuers",
                                "GetIssuers",
                                "ListIssuers",
                                "SetIssuers",
                                "DeleteIssuers"
                            ],
                            "keys": [
                                "Get",
                                "List",
                                "Update",
                                "Create",
                                "Import",
                                "Delete",
                                "Recover",
                                "Backup",
                                "Restore"
                            ],
                            "secrets": [
                                "Get",
                                "List",
                                "Set",
                                "Delete",
                                "Recover",
                                "Backup",
                                "Restore"
                            ]
                        },
                        "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd"
                    },
                    {
                        "objectId": "29a0b3b6-e8ea-4586-ae25-bc39cace0e67",
                        "permissions": {
                            "certificates": [
                                "Get",
                                "List",
                                "Update",
                                "Create",
                                "Import",
                                "Delete",
                                "Recover",
                                "Backup",
                                "Restore",
                                "ManageContacts",
                                "ManageIssuers",
                                "GetIssuers",
                                "ListIssuers",
                                "SetIssuers",
                                "DeleteIssuers"
                            ],
                            "keys": [
                                "Get",
                                "List",
                                "Update",
                                "Create",
                                "Import",
                                "Delete",
                                "Recover",
                                "Backup",
                                "Restore"
                            ],
                            "secrets": [
                                "Get",
                                "List",
                                "Set",
                                "Delete",
                                "Recover",
                                "Backup",
                                "Restore"
                            ]
                        },
                        "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd"
                    },
                    {
                        "objectId": "d2e31ea2-4d20-4288-9964-6be71766fba5",
                        "permissions": {
                            "certificates": [
                                "Get",
                                "List",
                                "Update",
                                "Create",
                                "Import",
                                "Delete",
                                "Recover",
                                "Backup",
                                "Restore",
                                "ManageContacts",
                                "ManageIssuers",
                                "GetIssuers",
                                "ListIssuers",
                                "SetIssuers",
                                "DeleteIssuers",
                                "Purge"
                            ],
                            "keys": [
                                "Get",
                                "List",
                                "Update",
                                "Create",
                                "Import",
                                "Delete",
                                "Recover",
                                "Backup",
                                "Restore",
                                "Decrypt",
                                "Encrypt",
                                "UnwrapKey",
                                "WrapKey",
                                "Verify",
                                "Sign",
                                "Purge"
                            ],
                            "secrets": [
                                "Get",
                                "List",
                                "Set",
                                "Delete",
                                "Recover",
                                "Backup",
                                "Restore",
                                "Purge"
                            ]
                        },
                        "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd"
                    },
                    {
                        "objectId": "a20e3391-8dba-4189-b8f4-23035e92a183",
                        "permissions": {
                            "certificates": [
                                "Get",
                                "List",
                                "Update",
                                "Create",
                                "Import",
                                "Delete",
                                "Recover",
                                "Backup",
                                "Restore",
                                "ManageContacts",
                                "ManageIssuers",
                                "GetIssuers",
                                "ListIssuers",
                                "SetIssuers",
                                "DeleteIssuers"
                            ],
                            "keys": [
                                "Get",
                                "List",
                                "Update",
                                "Create",
                                "Import",
                                "Delete",
                                "Recover",
                                "Backup",
                                "Restore"
                            ],
                            "secrets": [
                                "Get",
                                "List",
                                "Set",
                                "Delete",
                                "Recover",
                                "Backup",
                                "Restore"
                            ]
                        },
                        "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd"
                    }
                ],
                "enableRbacAuthorization": false,
                "enableSoftDelete": true,
                "enabledForDeployment": false,
                "enabledForDiskEncryption": false,
                "enabledForTemplateDeployment": false,
                "provisioningState": "Succeeded",
                "sku": {
                    "family": "A",
                    "name": "Standard"
                },
                "softDeleteRetentionInDays": 90,
                "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd",
                "vaultUri": "https://xsoar-test-vault.vault.azure.net/"
            },
            "tags": {},
            "type": "Microsoft.KeyVault/vaults"
        }
    },
    "AzureRiskyUsers": {
        "RiskyUsers": [
            {
                "id": "64bff056-fd02-48a4-b7de-abc8ee054c0a",
                "riskLastUpdatedDateTime": "2021-08-09T11:47:58.5581222Z",
                "riskLevel": "none",
                "riskState": "dismissed",
                "userDisplayName": "Or Cohen",
                "userPrincipalName": "orc@qmasters.co"
            },
            {
                "id": "890cfb37-0ab1-49d1-8670-ad7fd8898775",
                "riskLastUpdatedDateTime": "2020-11-05T18:35:39.2628939Z",
                "riskLevel": "none",
                "riskState": "remediated",
                "userDisplayName": "Eugene  Lednev",
                "userPrincipalName": "Eugene.Lednev@qmasters.co"
            },
            {
                "id": "b8ce4d4f-6624-4934-9630-3815873e8771",
                "riskLastUpdatedDateTime": "2021-02-08T15:21:43.1677221Z",
                "riskLevel": "none",
                "riskState": "dismissed",
                "userDisplayName": "Aleksandr Semenov",
                "userPrincipalName": "aleksandr.semenov@qfortress.ai"
            },
            {
                "id": "d4b2bbe1-f57d-4789-8318-5ec3a9fa18fb",
                "riskLastUpdatedDateTime": "2020-10-05T12:12:17.2115592Z",
                "riskLevel": "none",
                "riskState": "remediated",
                "userDisplayName": "Yossi Firouz",
                "userPrincipalName": "yossif@qmasters.co"
            },
            {
                "id": "923e7a82-8eeb-4107-84a3-49fea5ac6017",
                "riskLastUpdatedDateTime": "2021-02-08T15:21:43.2614658Z",
                "riskLevel": "none",
                "riskState": "dismissed",
                "userDisplayName": "On-Premises Directory Synchronization Service Account",
                "userPrincipalName": "Sync_QDC-01_b3eb0fb7f6ec@Qmasters.onmicrosoft.com"
            },
            {
                "id": "531d7c15-2290-41cb-98c8-0007ef569cf5",
                "riskLastUpdatedDateTime": "2021-02-08T15:21:43.3083545Z",
                "riskLevel": "none",
                "riskState": "dismissed",
                "userDisplayName": "On-Premises Directory Synchronization Service Account",
                "userPrincipalName": "Sync_QDC-02_1e73bf805b3b@Qmasters.onmicrosoft.com"
            },
            {
                "id": "ee626e96-0c73-4942-af84-bd078950d337",
                "riskLastUpdatedDateTime": "2021-07-20T07:14:41.8747065Z",
                "riskLevel": "none",
                "riskState": "remediated",
                "userDisplayName": "Raz Omry",
                "userPrincipalName": "Raz@qmasters.co"
            },
            {
                "id": "6ab1806d-182d-46bd-b283-dd1eb1f176ee",
                "riskLastUpdatedDateTime": "2021-06-20T17:03:46.8040028Z",
                "riskLevel": "none",
                "riskState": "remediated",
                "userDisplayName": "Alon Shiri",
                "userPrincipalName": "alons@qmasters.co"
            },
            {
                "id": "3703c0dd-150a-4b14-95e4-76e7ee4d362c",
                "riskLastUpdatedDateTime": "2021-05-28T18:03:26.0419673Z",
                "riskLevel": "none",
                "riskState": "dismissed",
                "userDisplayName": "Ran Dvash",
                "userPrincipalName": "RanD@qmasters.co"
            },
            {
                "id": "5a10d3b0-8c64-43d6-adba-702a41cf95f1",
                "riskLastUpdatedDateTime": "2021-08-08T09:15:09.6130224Z",
                "riskLevel": "none",
                "riskState": "remediated",
                "userDisplayName": "Shalev Agarwarker",
                "userPrincipalName": "ShalevA@qmasters.co"
            },
            {
                "id": "e79c7a64-06fb-4ee6-a214-0175b0001231",
                "riskLastUpdatedDateTime": "2021-07-12T16:36:57.6538118Z",
                "riskLevel": "none",
                "riskState": "dismissed",
                "userDisplayName": "Maksym Logvyniuk",
                "userPrincipalName": "Maksym.Logvyniuk@qfortress.ai"
            },
            {
                "id": "0f396c3a-1f31-46ae-8f84-f893a6aee6ca",
                "riskLastUpdatedDateTime": "2021-05-12T13:24:13.3546345Z",
                "riskLevel": "none",
                "riskState": "remediated",
                "userDisplayName": "Suf Dafna",
                "userPrincipalName": "Sufd@qmasters.co"
            },
            {
                "id": "a3ffa0fb-cd0d-425a-907b-46b19d0e63ad",
                "riskLastUpdatedDateTime": "2021-06-27T06:03:43.2667541Z",
                "riskLevel": "none",
                "riskState": "remediated",
                "userDisplayName": "Maor Shefi",
                "userPrincipalName": "maorsh@qmasters.co"
            },
            {
                "id": "430bec15-6788-41d4-9707-abea8db95a20",
                "riskLastUpdatedDateTime": "2021-04-04T14:09:41.7194239Z",
                "riskLevel": "none",
                "riskState": "remediated",
                "userDisplayName": "Netanel Yitzhak",
                "userPrincipalName": "Netanely@qmasters.co"
            },
            {
                "id": "6e69ec76-7097-44a4-b2de-de59a567b572",
                "riskLastUpdatedDateTime": "2021-02-08T15:22:26.4263339Z",
                "riskLevel": "none",
                "riskState": "dismissed",
                "userDisplayName": "Qradar",
                "userPrincipalName": "Qradar@qmasters.co"
            },
            {
                "id": "0b134675-4c72-4442-b91d-ef93893835d9",
                "riskLastUpdatedDateTime": "2021-03-02T12:22:54.0975747Z",
                "riskLevel": "none",
                "riskState": "remediated",
                "userDisplayName": "maxim petrichenko",
                "userPrincipalName": "maxim.petrichenko@qmasters.co"
            },
            {
                "id": "7e5e4c08-1c7c-4102-9dbc-32253b7f5165",
                "riskLastUpdatedDateTime": "2021-02-19T18:46:24.5679454Z",
                "riskLevel": "none",
                "riskState": "dismissed",
                "userDisplayName": "Michelle Duec",
                "userPrincipalName": "Michelled@qmasters.co"
            },
            {
                "id": "01c307d3-902e-424e-a895-5e025c047baa",
                "riskLastUpdatedDateTime": "2021-03-20T22:13:09.5060293Z",
                "riskLevel": "low",
                "riskState": "atRisk",
                "userDisplayName": "Alexander  Zavgorodnii",
                "userPrincipalName": "AlexanderZ@qfortress.ai"
            },
            {
                "id": "ca1d6840-6750-4900-b780-e18280aceaec",
                "riskLastUpdatedDateTime": "2021-05-12T14:24:51.7083891Z",
                "riskLevel": "none",
                "riskState": "dismissed",
                "userDisplayName": "Lukasz Kuciel",
                "userPrincipalName": "LukaszKuciel@qmasters.co"
            },
            {
                "id": "ebcf793a-9581-44c5-9bc1-9d50c773f9d0",
                "riskLastUpdatedDateTime": "2021-06-10T16:36:18.6553483Z",
                "riskLevel": "none",
                "riskState": "dismissed",
                "userDisplayName": "Svetlana Popovych",
                "userPrincipalName": "SvetlanaP@qfortress.ai"
            }
        ]
    }
}
```

#### Human Readable Output

>### xsoar-test-vault Information
>|Id|Name|Type|Location|
>|---|---|---|---|
>| /subscriptions/a213e459-7e7b-4d5d-b46a-26a8a71f6214/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-test-vault | xsoar-test-vault | Microsoft.KeyVault/vaults | eastus |


### azure-key-vault-key-vault-list
***
The List operation gets information about the vaults associated with the subscription


#### Base Command

`azure-key-vault-key-vault-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Limit on the number of keys vaults to return. Default is 50. | Optional | 
| offset | First index to retrieve from. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKeyVault.KeyVault.id | String | resource id. | 
| AzureKeyVault.KeyVault.name | String | key vault name. | 
| AzureKeyVault.KeyVault.type | String | resource type in Azure. | 
| AzureKeyVault.KeyVault.location | String | Key Vault location. | 
| AzureKeyVault.KeyVault.properties.sku.family | String | SKU family name. | 
| AzureKeyVault.KeyVault.properties.sku.name | String | SKU name to specify whether the key vault is a standard vault or a premium vault. | 
| AzureKeyVault.KeyVault.properties.tenantId | String | The Azure Active Directory tenant ID that should be used for authenticating requests to the key vault. | 
| AzureKeyVault.KeyVault.properties.accessPolicies.tenantId | String | The Azure Active Directory tenant ID that should be used for authenticating requests to the key vault | 
| AzureKeyVault.KeyVault.properties.accessPolicies.objectId | String | The object ID of a user, service principal or security group in the Azure Active Directory tenant for the vault. The object ID must be unique for the list of access policies. | 
| AzureKeyVault.KeyVault.properties.accessPolicies.permissions.keys | Unknown | Permissions to keys | 
| AzureKeyVault.KeyVault.properties.accessPolicies.permissions.secrets | Unknown | Permissions to secrets | 
| AzureKeyVault.KeyVault.properties.accessPolicies.permissions.certificates | Unknown | Permissions to certificates | 
| AzureKeyVault.KeyVault.properties.enabledForDeployment | Boolean | Property to specify whether Azure Virtual Machines are permitted to retrieve certificates stored as secrets from the key vault. | 
| AzureKeyVault.KeyVault.properties.enabledForDiskEncryption | Boolean | Property to specify whether Azure Disk Encryption is permitted to retrieve secrets from the vault and unwrap keys. | 
| AzureKeyVault.KeyVault.properties.enabledForTemplateDeployment | Boolean | Property to specify whether Azure Resource Manager is permitted to retrieve secrets from the key vault. | 
| AzureKeyVault.KeyVault.properties.enableSoftDelete | Boolean | Property to specify whether the 'soft delete' functionality is enabled for this key vault. If it's not set to any value\(true or false\) when creating new key vault, it will be set to true by default. Once set to true, it cannot be reverted to false. | 
| AzureKeyVault.KeyVault.properties.vaultUri | String | The URI of the vault for performing operations on keys and secrets. This property is readonly | 


#### Command Example
```!azure-key-vault-key-vault-list```

#### Context Example
```json
{
    "AzureKeyVault": {
        "KeyVault": [
            {
                "id": "/subscriptions/a213e459-7e7b-4d5d-b46a-26a8a71f6214/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-ofek-test",
                "location": "westus",
                "name": "xsoar-ofek-test",
                "properties": {
                    "accessPolicies": [
                        {
                            "objectId": "a20e3391-8dba-4189-b8f4-23035e92a183",
                            "permissions": {
                                "certificates": [
                                    "get",
                                    "list",
                                    "delete",
                                    "create",
                                    "import",
                                    "update",
                                    "managecontacts",
                                    "getissuers",
                                    "listissuers",
                                    "setissuers",
                                    "deleteissuers",
                                    "manageissuers",
                                    "recover"
                                ],
                                "keys": [
                                    "get",
                                    "list",
                                    "create",
                                    "update",
                                    "import",
                                    "delete",
                                    "backup",
                                    "restore",
                                    "recover",
                                    "purge"
                                ],
                                "secrets": [
                                    "get",
                                    "list",
                                    "set",
                                    "delete",
                                    "backup",
                                    "restore",
                                    "recover"
                                ]
                            },
                            "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd"
                        }
                    ],
                    "enableSoftDelete": true,
                    "enabledForDeployment": true,
                    "enabledForDiskEncryption": true,
                    "enabledForTemplateDeployment": true,
                    "provisioningState": "Succeeded",
                    "sku": {
                        "family": "A",
                        "name": "standard"
                    },
                    "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd",
                    "vaultUri": "https://xsoar-ofek-test.vault.azure.net/"
                },
                "tags": {},
                "type": "Microsoft.KeyVault/vaults"
            },
            {
                "id": "/subscriptions/a213e459-7e7b-4d5d-b46a-26a8a71f6214/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-test-33",
                "location": "westus",
                "name": "xsoar-test-33",
                "properties": {
                    "accessPolicies": [
                        {
                            "objectId": "d2e31ea2-4d20-4288-9964-6be71766fba5",
                            "permissions": {
                                "certificates": [
                                    "get",
                                    "list",
                                    "delete",
                                    "create",
                                    "import",
                                    "update",
                                    "managecontacts",
                                    "getissuers",
                                    "listissuers",
                                    "setissuers",
                                    "deleteissuers",
                                    "manageissuers",
                                    "recover"
                                ],
                                "keys": [
                                    "create",
                                    "decrypt"
                                ],
                                "secrets": [
                                    "get",
                                    "list",
                                    "set",
                                    "delete",
                                    "backup",
                                    "restore",
                                    "recover"
                                ]
                            },
                            "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd"
                        }
                    ],
                    "enableSoftDelete": true,
                    "enabledForDeployment": true,
                    "enabledForDiskEncryption": true,
                    "enabledForTemplateDeployment": true,
                    "networkAcls": {
                        "bypass": "AzureServices",
                        "defaultAction": "Deny",
                        "ipRules": [
                            {
                                "value": "11.94.1.2/32"
                            }
                        ],
                        "virtualNetworkRules": [
                            {
                                "id": "/subscriptions/a213e459-7e7b-4d5d-b46a-26a8a71f6214/resourcegroups/test-group/providers/microsoft.network/virtualnetworks/key-vault-vn/subnets/test-subnet",
                                "ignoreMissingVnetServiceEndpoint": true
                            }
                        ]
                    },
                    "provisioningState": "Succeeded",
                    "sku": {
                        "family": "A",
                        "name": "standard"
                    },
                    "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd",
                    "vaultUri": "https://xsoar-test-33.vault.azure.net/"
                },
                "tags": {},
                "type": "Microsoft.KeyVault/vaults"
            },
            {
                "id": "/subscriptions/a213e459-7e7b-4d5d-b46a-26a8a71f6214/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-test-35",
                "location": "westus",
                "name": "xsoar-test-35",
                "properties": {
                    "accessPolicies": [
                        {
                            "objectId": "d2e31ea2-4d20-4288-9964-6be71766fba5",
                            "permissions": {
                                "certificates": [
                                    "get",
                                    "list",
                                    "delete",
                                    "create",
                                    "import",
                                    "update",
                                    "managecontacts",
                                    "getissuers",
                                    "listissuers",
                                    "setissuers",
                                    "deleteissuers",
                                    "manageissuers",
                                    "recover"
                                ],
                                "keys": [
                                    "get",
                                    "list",
                                    "create",
                                    "update",
                                    "import",
                                    "delete",
                                    "backup",
                                    "restore",
                                    "recover"
                                ],
                                "secrets": [
                                    "get",
                                    "list",
                                    "set",
                                    "delete",
                                    "backup",
                                    "restore",
                                    "recover"
                                ]
                            },
                            "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd"
                        }
                    ],
                    "enableSoftDelete": true,
                    "enabledForDeployment": true,
                    "enabledForDiskEncryption": true,
                    "enabledForTemplateDeployment": true,
                    "provisioningState": "Succeeded",
                    "sku": {
                        "family": "A",
                        "name": "standard"
                    },
                    "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd",
                    "vaultUri": "https://xsoar-test-35.vault.azure.net/"
                },
                "tags": {},
                "type": "Microsoft.KeyVault/vaults"
            },
            {
                "id": "/subscriptions/a213e459-7e7b-4d5d-b46a-26a8a71f6214/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-readme-test",
                "location": "eastus",
                "name": "xsoar-readme-test",
                "properties": {
                    "accessPolicies": [
                        {
                            "objectId": "a20e3391-8dba-4189-b8f4-23035e92a183",
                            "permissions": {
                                "certificates": [
                                    "Get",
                                    "List",
                                    "Update",
                                    "Create",
                                    "Import",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore",
                                    "ManageContacts",
                                    "ManageIssuers",
                                    "GetIssuers",
                                    "ListIssuers",
                                    "SetIssuers",
                                    "DeleteIssuers"
                                ],
                                "keys": [
                                    "Get",
                                    "List",
                                    "Update",
                                    "Create",
                                    "Import",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore"
                                ],
                                "secrets": [
                                    "Get",
                                    "List",
                                    "Set",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore"
                                ]
                            },
                            "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd"
                        }
                    ],
                    "enableRbacAuthorization": false,
                    "enableSoftDelete": true,
                    "enabledForDeployment": false,
                    "enabledForDiskEncryption": false,
                    "enabledForTemplateDeployment": false,
                    "provisioningState": "Succeeded",
                    "sku": {
                        "family": "A",
                        "name": "Standard"
                    },
                    "softDeleteRetentionInDays": 90,
                    "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd",
                    "vaultUri": "https://xsoar-readme-test.vault.azure.net/"
                },
                "tags": {},
                "type": "Microsoft.KeyVault/vaults"
            },
            {
                "id": "/subscriptions/a213e459-7e7b-4d5d-b46a-26a8a71f6214/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-test-31",
                "location": "eastus",
                "name": "xsoar-test-31",
                "properties": {
                    "accessPolicies": [
                        {
                            "objectId": "d2e31ea2-4d20-4288-9964-6be71766fba5",
                            "permissions": {
                                "certificates": [
                                    "get",
                                    "list",
                                    "delete",
                                    "create",
                                    "import",
                                    "update",
                                    "managecontacts",
                                    "getissuers",
                                    "listissuers",
                                    "setissuers",
                                    "deleteissuers",
                                    "manageissuers",
                                    "recover"
                                ],
                                "keys": [
                                    "get",
                                    "list",
                                    "create",
                                    "update",
                                    "import",
                                    "delete",
                                    "backup",
                                    "restore",
                                    "recover"
                                ],
                                "secrets": [
                                    "get",
                                    "list",
                                    "set",
                                    "delete",
                                    "backup",
                                    "restore",
                                    "recover"
                                ]
                            },
                            "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd"
                        }
                    ],
                    "enableSoftDelete": true,
                    "enabledForDeployment": true,
                    "enabledForDiskEncryption": true,
                    "enabledForTemplateDeployment": true,
                    "provisioningState": "Succeeded",
                    "sku": {
                        "family": "A",
                        "name": "standard"
                    },
                    "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd",
                    "vaultUri": "https://xsoar-test-31.vault.azure.net/"
                },
                "tags": {},
                "type": "Microsoft.KeyVault/vaults"
            },
            {
                "id": "/subscriptions/a213e459-7e7b-4d5d-b46a-26a8a71f6214/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-test-vault",
                "location": "eastus",
                "name": "xsoar-test-vault",
                "properties": {
                    "accessPolicies": [
                        {
                            "applicationId": "55f9764e-300a-474a-a2bb-549cece85439",
                            "objectId": "29a0b3b6-e8ea-4586-ae25-bc39cace0e67",
                            "permissions": {
                                "certificates": [
                                    "Get",
                                    "List",
                                    "Update",
                                    "Create",
                                    "Import",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore",
                                    "ManageContacts",
                                    "ManageIssuers",
                                    "GetIssuers",
                                    "ListIssuers",
                                    "SetIssuers",
                                    "DeleteIssuers"
                                ],
                                "keys": [
                                    "Get",
                                    "List",
                                    "Update",
                                    "Create",
                                    "Import",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore"
                                ],
                                "secrets": [
                                    "Get",
                                    "List",
                                    "Set",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore"
                                ]
                            },
                            "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd"
                        },
                        {
                            "objectId": "29a0b3b6-e8ea-4586-ae25-bc39cace0e67",
                            "permissions": {
                                "certificates": [
                                    "Get",
                                    "List",
                                    "Update",
                                    "Create",
                                    "Import",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore",
                                    "ManageContacts",
                                    "ManageIssuers",
                                    "GetIssuers",
                                    "ListIssuers",
                                    "SetIssuers",
                                    "DeleteIssuers"
                                ],
                                "keys": [
                                    "Get",
                                    "List",
                                    "Update",
                                    "Create",
                                    "Import",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore"
                                ],
                                "secrets": [
                                    "Get",
                                    "List",
                                    "Set",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore"
                                ]
                            },
                            "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd"
                        },
                        {
                            "objectId": "d2e31ea2-4d20-4288-9964-6be71766fba5",
                            "permissions": {
                                "certificates": [
                                    "Get",
                                    "List",
                                    "Update",
                                    "Create",
                                    "Import",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore",
                                    "ManageContacts",
                                    "ManageIssuers",
                                    "GetIssuers",
                                    "ListIssuers",
                                    "SetIssuers",
                                    "DeleteIssuers",
                                    "Purge"
                                ],
                                "keys": [
                                    "Get",
                                    "List",
                                    "Update",
                                    "Create",
                                    "Import",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore",
                                    "Decrypt",
                                    "Encrypt",
                                    "UnwrapKey",
                                    "WrapKey",
                                    "Verify",
                                    "Sign",
                                    "Purge"
                                ],
                                "secrets": [
                                    "Get",
                                    "List",
                                    "Set",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore",
                                    "Purge"
                                ]
                            },
                            "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd"
                        },
                        {
                            "objectId": "a20e3391-8dba-4189-b8f4-23035e92a183",
                            "permissions": {
                                "certificates": [
                                    "Get",
                                    "List",
                                    "Update",
                                    "Create",
                                    "Import",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore",
                                    "ManageContacts",
                                    "ManageIssuers",
                                    "GetIssuers",
                                    "ListIssuers",
                                    "SetIssuers",
                                    "DeleteIssuers"
                                ],
                                "keys": [
                                    "Get",
                                    "List",
                                    "Update",
                                    "Create",
                                    "Import",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore"
                                ],
                                "secrets": [
                                    "Get",
                                    "List",
                                    "Set",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore"
                                ]
                            },
                            "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd"
                        }
                    ],
                    "enableRbacAuthorization": false,
                    "enableSoftDelete": true,
                    "enabledForDeployment": false,
                    "enabledForDiskEncryption": false,
                    "enabledForTemplateDeployment": false,
                    "provisioningState": "Succeeded",
                    "sku": {
                        "family": "A",
                        "name": "Standard"
                    },
                    "softDeleteRetentionInDays": 90,
                    "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd",
                    "vaultUri": "https://xsoar-test-vault.vault.azure.net/"
                },
                "tags": {},
                "type": "Microsoft.KeyVault/vaults"
            },
            {
                "id": "/subscriptions/a213e459-7e7b-4d5d-b46a-26a8a71f6214/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/yehuda-test",
                "location": "eastus",
                "name": "yehuda-test",
                "properties": {
                    "accessPolicies": [
                        {
                            "objectId": "d2e31ea2-4d20-4288-9964-6be71766fba5",
                            "permissions": {
                                "certificates": [
                                    "Get",
                                    "List",
                                    "Update",
                                    "Create",
                                    "Import",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore",
                                    "ManageContacts",
                                    "ManageIssuers",
                                    "GetIssuers",
                                    "ListIssuers",
                                    "SetIssuers",
                                    "DeleteIssuers"
                                ],
                                "keys": [
                                    "Get",
                                    "List",
                                    "Update",
                                    "Create",
                                    "Import",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore",
                                    "Decrypt",
                                    "Encrypt",
                                    "UnwrapKey",
                                    "WrapKey",
                                    "Verify",
                                    "Sign",
                                    "Purge"
                                ],
                                "secrets": [
                                    "Get",
                                    "List",
                                    "Set",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore"
                                ]
                            },
                            "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd"
                        },
                        {
                            "objectId": "77092f9c-a83d-4f87-a0a5-14a7f4a30816",
                            "permissions": {
                                "certificates": [
                                    "Get",
                                    "List",
                                    "Update",
                                    "Create",
                                    "Import",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore",
                                    "ManageContacts",
                                    "ManageIssuers",
                                    "GetIssuers",
                                    "ListIssuers",
                                    "SetIssuers",
                                    "DeleteIssuers",
                                    "Purge"
                                ],
                                "keys": [
                                    "Get",
                                    "List",
                                    "Update",
                                    "Create",
                                    "Import",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore",
                                    "Purge",
                                    "Sign",
                                    "Verify",
                                    "WrapKey",
                                    "UnwrapKey",
                                    "Encrypt",
                                    "Decrypt"
                                ],
                                "secrets": [
                                    "Get",
                                    "List",
                                    "Set",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore",
                                    "Purge"
                                ]
                            },
                            "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd"
                        },
                        {
                            "objectId": "944882d4-f2cb-4d58-a421-1218308701ff",
                            "permissions": {
                                "certificates": [
                                    "Get",
                                    "List",
                                    "Update",
                                    "Create",
                                    "Import",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore",
                                    "ManageContacts",
                                    "ManageIssuers",
                                    "GetIssuers",
                                    "ListIssuers",
                                    "SetIssuers",
                                    "DeleteIssuers"
                                ],
                                "keys": [
                                    "Get",
                                    "List",
                                    "Update",
                                    "Create",
                                    "Import",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore"
                                ],
                                "secrets": [
                                    "Get",
                                    "List",
                                    "Set",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore"
                                ]
                            },
                            "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd"
                        },
                        {
                            "objectId": "a20e3391-8dba-4189-b8f4-23035e92a183",
                            "permissions": {
                                "certificates": [
                                    "Get",
                                    "List",
                                    "Update",
                                    "Create",
                                    "Import",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore",
                                    "ManageContacts",
                                    "ManageIssuers",
                                    "GetIssuers",
                                    "ListIssuers",
                                    "SetIssuers",
                                    "DeleteIssuers",
                                    "Purge"
                                ],
                                "keys": [
                                    "Get",
                                    "List",
                                    "Update",
                                    "Create",
                                    "Import",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore",
                                    "Decrypt",
                                    "Encrypt",
                                    "UnwrapKey",
                                    "WrapKey",
                                    "Verify",
                                    "Sign",
                                    "Purge"
                                ],
                                "secrets": [
                                    "Get",
                                    "List",
                                    "Set",
                                    "Delete",
                                    "Recover",
                                    "Backup",
                                    "Restore",
                                    "Purge"
                                ]
                            },
                            "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd"
                        }
                    ],
                    "enableRbacAuthorization": false,
                    "enableSoftDelete": true,
                    "enabledForDeployment": true,
                    "enabledForDiskEncryption": true,
                    "enabledForTemplateDeployment": true,
                    "provisioningState": "Succeeded",
                    "sku": {
                        "family": "A",
                        "name": "Standard"
                    },
                    "softDeleteRetentionInDays": 90,
                    "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd",
                    "vaultUri": "https://yehuda-test.vault.azure.net/"
                },
                "tags": {},
                "type": "Microsoft.KeyVault/vaults"
            },
            {
                "id": "/subscriptions/a213e459-7e7b-4d5d-b46a-26a8a71f6214/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-test5",
                "location": "westus",
                "name": "xsoar-test5",
                "properties": {
                    "accessPolicies": [
                        {
                            "objectId": "522b4a4e-d3fd-4b0e-a1b8-5745b03d9dea",
                            "permissions": {
                                "certificates": [
                                    "get",
                                    "list",
                                    "delete",
                                    "create",
                                    "import",
                                    "update",
                                    "managecontacts",
                                    "getissuers",
                                    "listissuers",
                                    "setissuers",
                                    "deleteissuers",
                                    "manageissuers",
                                    "recover",
                                    "purge"
                                ],
                                "keys": [
                                    "encrypt",
                                    "decrypt",
                                    "wrapKey",
                                    "unwrapKey",
                                    "sign",
                                    "verify",
                                    "get",
                                    "list",
                                    "create",
                                    "update",
                                    "import",
                                    "delete",
                                    "backup",
                                    "restore",
                                    "recover",
                                    "purge"
                                ],
                                "secrets": [
                                    "get",
                                    "list",
                                    "set",
                                    "delete",
                                    "backup",
                                    "restore",
                                    "recover",
                                    "purge"
                                ]
                            },
                            "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd"
                        }
                    ],
                    "enableSoftDelete": true,
                    "enabledForDeployment": false,
                    "enabledForDiskEncryption": true,
                    "enabledForTemplateDeployment": true,
                    "networkAcls": {
                        "bypass": "AzureServices",
                        "defaultAction": "Deny",
                        "ipRules": [
                            {
                                "value": "11.94.1.2/32"
                            }
                        ],
                        "virtualNetworkRules": [
                            {
                                "id": "/subscriptions/a213e459-7e7b-4d5d-b46a-26a8a71f6214/resourcegroups/test-group/providers/microsoft.network/virtualnetworks/key-vault-vn/subnets/test-subnet"
                            }
                        ]
                    },
                    "provisioningState": "Succeeded",
                    "sku": {
                        "family": "A",
                        "name": "standard"
                    },
                    "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd",
                    "vaultUri": "https://xsoar-test5.vault.azure.net/"
                },
                "tags": {},
                "type": "Microsoft.KeyVault/vaults"
            }
        ]
    }
}
```

#### Human Readable Output

>### Key Vaults List
> Current page size: 50
> Showing page 1 out others that may exist
>|Id|Name|Type|Location|
>|---|---|---|---|
>| /subscriptions/a213e459-7e7b-4d5d-b46a-26a8a71f6214/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-ofek-test | xsoar-ofek-test | Microsoft.KeyVault/vaults | westus |
>| /subscriptions/a213e459-7e7b-4d5d-b46a-26a8a71f6214/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-test-33 | xsoar-test-33 | Microsoft.KeyVault/vaults | westus |
>| /subscriptions/a213e459-7e7b-4d5d-b46a-26a8a71f6214/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-test-35 | xsoar-test-35 | Microsoft.KeyVault/vaults | westus |
>| /subscriptions/a213e459-7e7b-4d5d-b46a-26a8a71f6214/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-readme-test | xsoar-readme-test | Microsoft.KeyVault/vaults | eastus |
>| /subscriptions/a213e459-7e7b-4d5d-b46a-26a8a71f6214/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-test-31 | xsoar-test-31 | Microsoft.KeyVault/vaults | eastus |
>| /subscriptions/a213e459-7e7b-4d5d-b46a-26a8a71f6214/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-test-vault | xsoar-test-vault | Microsoft.KeyVault/vaults | eastus |
>| /subscriptions/a213e459-7e7b-4d5d-b46a-26a8a71f6214/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/yehuda-test | yehuda-test | Microsoft.KeyVault/vaults | eastus |
>| /subscriptions/a213e459-7e7b-4d5d-b46a-26a8a71f6214/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-test5 | xsoar-test5 | Microsoft.KeyVault/vaults | westus |


### azure-key-vault-key-vault-access-policy-update
***
Updates access policies in a key vault in the specified subscription.


#### Base Command

`azure-key-vault-key-vault-access-policy-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | Name of the vault to update it's access policy. | Required | 
| operation_kind | The name of the operation to do on the vault's access policy. <br/>Supports three operations: add,remove,replace. Possible values are: add, remove, replace. | Required | 
| object_id | The object ID of a user, service principal or security group in the Azure Active Directory tenant for the vault. The object ID must be unique for the list of access policies. | Required | 
| keys | Permissions to keys. Possible values are: encrypt, decrypt, wrapKey, unwrapKey, sign, verify, get, list, create, update, import, delete, backup, restore, recover, purge. | Optional | 
| secrets | Permissions to secrets. Possible values are: get, list, set, delete, backup, restore, recover, purge. | Optional | 
| certificates | Permissions to certificates. Possible values are: get, list, delete, create, import, update, managecontacts, getissuers, listissuers, setissuers, deleteissuers, manageissuers, recover, purge. | Optional | 
| storage | Permissions to storage accounts. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKeyVault.VaultAccessPolicy.id | String | resource id | 
| AzureKeyVault.VaultAccessPolicy.type | String | resource type in Azure | 
| AzureKeyVault.VaultAccessPolicy.properties.accessPolicies.tenantId | String | The Azure Active Directory tenant ID that should be used for authenticating requests to the key vault. | 
| AzureKeyVault.VaultAccessPolicy.properties.accessPolicies.objectId | String | The object ID of a user, service principal or security group in the Azure Active Directory tenant for the vault. The object ID must be unique for the list of access policies. | 
| AzureKeyVault.VaultAccessPolicy.properties.accessPolicies.permissions.keys | Unknown | Permissions to keys | 
| AzureKeyVault.VaultAccessPolicy.properties.accessPolicies.permissions.secrets | Unknown | Permissions to secrets | 
| AzureKeyVault.VaultAccessPolicy.properties.accessPolicies.permissions.certificates | Unknown | Permissions to certificates | 


#### Command Example
```!azure-key-vault-key-vault-access-policy-update object_id=d2e31ea2-4d20-4288-9964-6be71766fba5 operation_kind=add vault_name=xsoar-test-33 keys=import,list```

#### Context Example
```json
{
    "AzureKeyVault": {
        "VaultAccessPolicy": {
            "id": "/subscriptions/a213e459-7e7b-4d5d-b46a-26a8a71f6214/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-test-33/accessPolicies/",
            "properties": {
                "accessPolicies": [
                    {
                        "objectId": "d2e31ea2-4d20-4288-9964-6be71766fba5",
                        "permissions": {
                            "certificates": [
                                "get",
                                "list",
                                "delete",
                                "create",
                                "import",
                                "update",
                                "managecontacts",
                                "getissuers",
                                "listissuers",
                                "setissuers",
                                "deleteissuers",
                                "manageissuers",
                                "recover"
                            ],
                            "keys": [
                                "create",
                                "decrypt",
                                "import",
                                "list"
                            ],
                            "secrets": [
                                "get",
                                "list",
                                "set",
                                "delete",
                                "backup",
                                "restore",
                                "recover"
                            ]
                        },
                        "tenantId": "0dd6c060-d39a-4e06-873c-48a43c2e24dd"
                    }
                ]
            },
            "type": "Microsoft.KeyVault/vaults/accessPolicies"
        }
    }
}
```

#### Human Readable Output

>### xsoar-test-33 Updated Access Policy
>|Id|Type|Properties|
>|---|---|---|
>| /subscriptions/a213e459-7e7b-4d5d-b46a-26a8a71f6214/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-test-33/accessPolicies/ | Microsoft.KeyVault/vaults/accessPolicies | accessPolicies: {'tenantId': '0dd6c060-d39a-4e06-873c-48a43c2e24dd', 'objectId': 'd2e31ea2-4d20-4288-9964-6be71766fba5', 'permissions': {'keys': ['create', 'decrypt', 'import', 'list'], 'secrets': ['get', 'list', 'set', 'delete', 'backup', 'restore', 'recover'], 'certificates': ['get', 'list', 'delete', 'create', 'import', 'update', 'managecontacts', 'getissuers', 'listissuers', 'setissuers', 'deleteissuers', 'manageissuers', 'recover']}} |


### azure-key-vault-key-get
***
Gets the public part of a stored key


#### Base Command

`azure-key-vault-key-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | The vault name. | Required | 
| key_name | The name of the key to get. | Required | 
| key_version | Adding the version parameter retrieves a specific version of a key. This URI fragment is optional. If not specified, the latest version of the key is returned. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKeyVault.Key.key.kid | String | Key identifier | 
| AzureKeyVault.Key.key.kty | String | JsonWebKey Key Type \(kty\) | 
| AzureKeyVault.Key.key.key_ops | Unknown | Supported key operations. | 
| AzureKeyVault.Key.key.n | String | RSA modulus. | 
| AzureKeyVault.Key.key.e | String | RSA public exponent | 
| AzureKeyVault.Key.attributes.enabled | Boolean | Determines whether the object is enabled.
 | 
| AzureKeyVault.Key.attributes.created | Date | Creation time in UTC.
 | 
| AzureKeyVault.Key.attributes.updated | Date | Last updated time in UTC. | 
| AzureKeyVault.Key.attributes.recoveryLevel | Unknown | Reflects the deletion recovery level currently in effect for keys in the current vault. If it contains 'Purgeable' the key can be permanently deleted by a privileged user; otherwise, only the system can purge the key, at the end of the retention interval. | 


#### Command Example
```!azure-key-vault-key-get key_name=test-key-1 vault_name=xsoar-test-vault```

#### Context Example
```json
{
    "AzureKeyVault": {
        "Key": {
            "attributes": {
                "created": 1628683396,
                "enabled": true,
                "recoverableDays": 90,
                "recoveryLevel": "Recoverable+Purgeable",
                "updated": 1628683396
            },
            "key": {
                "e": "AQAB",
                "key_ops": [
                    "sign",
                    "verify",
                    "wrapKey",
                    "unwrapKey",
                    "encrypt",
                    "decrypt"
                ],
                "kid": "https://xsoar-test-vault.vault.azure.net/keys/test-key-1/ecb2971b800842e2bda59cc9b8532d2b",
                "kty": "RSA",
                "n": "9JbwOZjuopMrpkGciWW5GKUUJ6HsQEFFX8tu46hZ1N5C1ii6VvCFhDKEBELaVBr_YsZOIvZbNMmhBI4PHmiiKFOqv84Cy_YXXtk5KsA2BkuoFJJJiAZh8U6txcl-32ZomaNKBIJbI8RpY__dEmGVlPvG5w9c64E6lyGTYhk0xvOmrFlsWh9YicZn5DTXTqCAi55BNvBhoC90O2bY2EWo3SOP9vPcrNkknHSLmd7HRBpvmvfCMh2nWAwOv1iXMfeDMAnW7BTAPJWIHWdP9SnqvSgbw8r_n5Rkq7EwkNeTwGDxGdr3FniB6ByfGi54DXpJt0q7gLVdJJnNww-xGRNrWQ"
            },
            "tags": {}
        }
    }
}
```

#### Human Readable Output

>### test-key-1 Information
>|Key Id|Json Web Key Type|Key Operations|Create Time|Update Time|Enabled|
>|---|---|---|---|---|---|
>| https://xsoar-test-vault.vault.azure.net/keys/test-key-1/ecb2971b800842e2bda59cc9b8532d2b | RSA | sign,<br/>verify,<br/>wrapKey,<br/>unwrapKey,<br/>encrypt,<br/>decrypt | 2021-08-11T12:03:16Z | 2021-08-11T12:03:16Z | true |


### azure-key-vault-key-list
***
Lists keys in the specified vault


#### Base Command

`azure-key-vault-key-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | The vault name. | Required | 
| limit | Limit on the number of keys to return. Default is 50. | Optional | 
| offset | First index to retrieve from. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKeyVault.Key.kid | String | Key identifier | 
| AzureKeyVault.Key.attributes.enabled | Boolean | Determines whether the object is enabled | 
| AzureKeyVault.Key.attributes.create_time | Date | Creation time in UTC. | 
| AzureKeyVault.Key.attributes.update_time | Date | Last updated time in UTC | 
| AzureKeyVault.Key.attributes.recoveryLevel | String | Reflects the deletion recovery level currently in effect for keys in the current vault. If it contains 'Purgeable' the key can be permanently deleted by a privileged user; otherwise, only the system can purge the key, at the end of the retention interval. | 
| AzureKeyVault.Key.attributes.recoverableDays | Number | softDelete data retention days. Value should be &gt;=7 and &lt;=90 when softDelete enabled, otherwise 0. | 


#### Command Example
```!azure-key-vault-key-list vault_name=xsoar-test-vault```

#### Context Example
```json
{
    "AzureKeyVault": {
        "Key": [
            {
                "attributes": {
                    "create_time": "2021-08-11T12:05:48Z",
                    "enabled": true,
                    "expiry_time": "2022-08-11T12:05:48Z",
                    "recoverableDays": 90,
                    "recoveryLevel": "Recoverable+Purgeable",
                    "should_not_be_retrieved_Before": 1628682948,
                    "update_time": "2021-08-11T12:05:48Z"
                },
                "kid": "https://xsoar-test-vault.vault.azure.net/keys/test-cer-1",
                "managed": true,
                "tags": {}
            },
            {
                "attributes": {
                    "create_time": "2021-08-11T12:06:00Z",
                    "enabled": true,
                    "expiry_time": "2022-08-11T12:06:00Z",
                    "recoverableDays": 90,
                    "recoveryLevel": "Recoverable+Purgeable",
                    "should_not_be_retrieved_Before": 1628682960,
                    "update_time": "2021-08-11T12:06:00Z"
                },
                "kid": "https://xsoar-test-vault.vault.azure.net/keys/test-cer-2",
                "managed": true,
                "tags": {}
            },
            {
                "attributes": {
                    "create_time": "2021-08-11T12:06:24Z",
                    "enabled": true,
                    "expiry_time": "2022-08-11T12:06:24Z",
                    "recoverableDays": 90,
                    "recoveryLevel": "Recoverable+Purgeable",
                    "should_not_be_retrieved_Before": 1628682984,
                    "update_time": "2021-08-11T12:06:24Z"
                },
                "kid": "https://xsoar-test-vault.vault.azure.net/keys/test-cer-3",
                "managed": true,
                "tags": {}
            },
            {
                "attributes": {
                    "create_time": "2021-08-18T06:41:38Z",
                    "enabled": true,
                    "expiry_time": "2022-08-18T06:41:38Z",
                    "recoverableDays": 90,
                    "recoveryLevel": "Recoverable+Purgeable",
                    "should_not_be_retrieved_Before": 1629268298,
                    "update_time": "2021-08-18T06:41:38Z"
                },
                "kid": "https://xsoar-test-vault.vault.azure.net/keys/test-cer-5",
                "managed": true,
                "tags": {}
            },
            {
                "attributes": {
                    "create_time": "2021-08-18T06:41:51Z",
                    "enabled": true,
                    "expiry_time": "2022-08-18T06:41:50Z",
                    "recoverableDays": 90,
                    "recoveryLevel": "Recoverable+Purgeable",
                    "should_not_be_retrieved_Before": 1629268310,
                    "update_time": "2021-08-18T06:41:51Z"
                },
                "kid": "https://xsoar-test-vault.vault.azure.net/keys/test-cer-6",
                "managed": true,
                "tags": {}
            },
            {
                "attributes": {
                    "create_time": "2021-08-11T12:03:16Z",
                    "enabled": true,
                    "recoverableDays": 90,
                    "recoveryLevel": "Recoverable+Purgeable",
                    "update_time": "2021-08-11T12:03:16Z"
                },
                "kid": "https://xsoar-test-vault.vault.azure.net/keys/test-key-1",
                "tags": {}
            },
            {
                "attributes": {
                    "create_time": "2021-08-11T12:03:25Z",
                    "enabled": true,
                    "recoverableDays": 90,
                    "recoveryLevel": "Recoverable+Purgeable",
                    "update_time": "2021-08-11T12:03:25Z"
                },
                "kid": "https://xsoar-test-vault.vault.azure.net/keys/test-key-2",
                "tags": {}
            },
            {
                "attributes": {
                    "create_time": "2021-08-25T09:31:46Z",
                    "enabled": true,
                    "recoverableDays": 90,
                    "recoveryLevel": "Recoverable+Purgeable",
                    "update_time": "2021-08-25T09:31:46Z"
                },
                "kid": "https://xsoar-test-vault.vault.azure.net/keys/xsoar-readme-test",
                "tags": {}
            },
            {
                "attributes": {
                    "create_time": "2021-08-25T09:32:32Z",
                    "enabled": true,
                    "expiry_time": "2022-08-25T09:32:32Z",
                    "recoverableDays": 90,
                    "recoveryLevel": "Recoverable+Purgeable",
                    "should_not_be_retrieved_Before": 1629883352,
                    "update_time": "2021-08-25T09:32:32Z"
                },
                "kid": "https://xsoar-test-vault.vault.azure.net/keys/xsoar-readme-test-2",
                "managed": true,
                "tags": {}
            }
        ]
    }
}
```

#### Human Readable Output

>### xsoar-test-vault Keys List
> Current page size: 50
> Showing page 1 out others that may exist
>|Key Id|Managed|Create Time|Update Time|Expiry Time|
>|---|---|---|---|---|
>| https://xsoar-test-vault.vault.azure.net/keys/test-cer-1 | true | 2021-08-11T12:05:48Z | 2021-08-11T12:05:48Z | 2022-08-11T12:05:48Z |
>| https://xsoar-test-vault.vault.azure.net/keys/test-cer-2 | true | 2021-08-11T12:06:00Z | 2021-08-11T12:06:00Z | 2022-08-11T12:06:00Z |
>| https://xsoar-test-vault.vault.azure.net/keys/test-cer-3 | true | 2021-08-11T12:06:24Z | 2021-08-11T12:06:24Z | 2022-08-11T12:06:24Z |
>| https://xsoar-test-vault.vault.azure.net/keys/test-cer-5 | true | 2021-08-18T06:41:38Z | 2021-08-18T06:41:38Z | 2022-08-18T06:41:38Z |
>| https://xsoar-test-vault.vault.azure.net/keys/test-cer-6 | true | 2021-08-18T06:41:51Z | 2021-08-18T06:41:51Z | 2022-08-18T06:41:50Z |
>| https://xsoar-test-vault.vault.azure.net/keys/test-key-1 |  | 2021-08-11T12:03:16Z | 2021-08-11T12:03:16Z |  |
>| https://xsoar-test-vault.vault.azure.net/keys/test-key-2 |  | 2021-08-11T12:03:25Z | 2021-08-11T12:03:25Z |  |
>| https://xsoar-test-vault.vault.azure.net/keys/xsoar-readme-test |  | 2021-08-25T09:31:46Z | 2021-08-25T09:31:46Z |  |
>| https://xsoar-test-vault.vault.azure.net/keys/xsoar-readme-test-2 | true | 2021-08-25T09:32:32Z | 2021-08-25T09:32:32Z | 2022-08-25T09:32:32Z |


### azure-key-vault-key-delete
***
Deletes a key of any type from storage in Azure Key vault.


#### Base Command

`azure-key-vault-key-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | The vault name. | Required | 
| key_name | The name of the key to delete. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKeyVault.Key.recoveryId | String | The url of the recovery object, used to identify and recover the deleted key. | 
| AzureKeyVault.Key.deletedDate | Date | The time when the key was deleted, in UTC | 
| AzureKeyVault.Key.key.kid | String | Key identifier | 
| AzureKeyVault.Key.key.kty | String | JsonWebKey Key Type \(kty\) | 
| AzureKeyVault.Key.key.key_ops | Unknown | Supported key operations. | 
| AzureKeyVault.Key.key.n | String | RSA modulus. | 
| AzureKeyVault.Key.key.e | String | RSA public exponent | 
| AzureKeyVault.Key.attributes.enabled | Boolean | Determines whether the object is enabled.
 | 
| AzureKeyVault.Key.attributes.created | Number | Creation time in UTC | 
| AzureKeyVault.Key.attributes.updated | Number | Last updated time in UTC. | 
| AzureKeyVault.Key.attributes.recoveryLevel | String | Reflects the deletion recovery level currently in effect for keys in the current vault. If it contains 'Purgeable' the key can be permanently deleted by a privileged user; otherwise, only the system can purge the key, at the end of the retention interval. | 


#### Command Example
```!azure-key-vault-key-delete key_name=xsoar-readme-test vault_name=xsoar-test-vault```

#### Context Example
```json
{
    "AzureKeyVault": {
        "Key": {
            "attributes": {
                "created": 1629883906,
                "enabled": true,
                "recoverableDays": 90,
                "recoveryLevel": "Recoverable+Purgeable",
                "updated": 1629883906
            },
            "deletedDate": 1629884334,
            "key": {
                "RSA_modulus": "zcmRzBcEuRt_hg6BTKY_TuKquNrseaPYVi4pZqkVTgYxdYHxt2BWWOz7XGA0_KQtFbNTgbV5e2xPnDsAvcmNVv52nll77nFhL27ojrVR9dB-lkiVp9DEShi_qSnClwHyJ9VHJwpBYJgwpoD6kcooT2dkOigc-f44_D7reFL2dsY66WI051dzF0LgDnyn-kz_QG33zQueCpTkq5of-_5G1ybn0X80kA4BqpwtMlRK3_UrMpFD4wVV_SXNo869IXVAkcsArqhsOWkLFUjmejDKNT7gSZxAVi51CrVRLAoSurBi9i1nBxfU23Xp93DMukporcDV-rbR3U_-3a_ndYKyiQ",
                "RSA_public_components": "AQAB",
                "json_web_key_type": "RSA",
                "key_id": "https://xsoar-test-vault.vault.azure.net/keys/xsoar-readme-test/9bcf34e04a7e460ab23b2fe2c6107bf2",
                "key_operations": [
                    "sign",
                    "verify",
                    "wrapKey",
                    "unwrapKey",
                    "encrypt",
                    "decrypt"
                ]
            },
            "recoveryId": "https://xsoar-test-vault.vault.azure.net/deletedkeys/xsoar-readme-test",
            "scheduledPurgeDate": 1637660334,
            "tags": {}
        }
    }
}
```

#### Human Readable Output

>### Delete xsoar-readme-test
>|Key Id|Recovery Id|Deleted Date|Scheduled Purge Date|
>|---|---|---|---|
>| https://xsoar-test-vault.vault.azure.net/keys/xsoar-readme-test/9bcf34e04a7e460ab23b2fe2c6107bf2 | https://xsoar-test-vault.vault.azure.net/deletedkeys/xsoar-readme-test | 2021-08-25T09:38:54Z | 2021-11-23T09:38:54Z |


### azure-key-vault-secret-get
***
Get a specified secret from a given key vault.
The GET operation is applicable to any secret stored in Azure Key Vault. This operation requires the secrets/get permission.


#### Base Command

`azure-key-vault-secret-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | The vault name. | Required | 
| secret_name | The name of the secret to get. | Required | 
| secret_version | The version of the secret. This URI fragment is optional. If not specified, the latest version of the secret is returned. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKeyVault.Secret.value | String | secret's value | 
| AzureKeyVault.Secret.id | String | secret's id | 
| AzureKeyVault.Secret.attributes.enabled | Bolean | Determines whether the object is enabled.
 | 
| AzureKeyVault.Secret.attributes.created | Date | Creation time in UTC. | 
| AzureKeyVault.Secret.attributes.updated | Date | Last updated time in UTC. | 
| AzureKeyVault.Secret.attributes.recoveryLevel | String | Reflects the deletion recovery level currently in effect for secrets in the current vault. If it contains 'Purgeable', the secret can be permanently deleted by a privileged user; otherwise, only the system can purge the secret, at the end of the retention interval. | 


#### Command Example
```!azure-key-vault-secret-get secret_name=test-sec-1 vault_name=xsoar-test-vault```

#### Context Example
```json
{
    "AzureKeyVault": {
        "Secret": {
            "attributes": {
                "created": 1628683452,
                "enabled": true,
                "exp": 1691755446,
                "nbf": 1628683446,
                "recoverableDays": 90,
                "recoveryLevel": "Recoverable+Purgeable",
                "updated": 1629217377
            },
            "contentType": "text",
            "id": "https://xsoar-test-vault.vault.azure.net/secrets/test-sec-1/88b8c4e1dc3a4443b5847de9edb1b4a4",
            "tags": {},
            "value": "test"
        }
    }
}
```

#### Human Readable Output

>### test-sec-1 Information
>|Secret Id|Create Time|Update Time|Expiry Time|
>|---|---|---|---|
>| https://xsoar-test-vault.vault.azure.net/secrets/test-sec-1/88b8c4e1dc3a4443b5847de9edb1b4a4 | 2021-08-11T12:04:12Z | 2021-08-17T16:22:57Z | 2023-08-11T12:04:06Z |


### azure-key-vault-secret-list
***
List secrets in a specified key vault.


#### Base Command

`azure-key-vault-secret-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | The vault name. | Required | 
| limit | Limit on the number of secrets to return. Default is 50. | Optional | 
| offset | First index to retrieve from. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKeyVault.Secret.id | String | secret's id | 
| AzureKeyVault.Secret.attributes.enabled | Bolean | Determines whether the object is enabled.
| 
| AzureKeyVault.Secret.attributes.nbf | Date | Not before date in UTC. | 
| AzureKeyVault.Secret.attributes.exp | Date | Expiry date in UTC. | 
| AzureKeyVault.Secret.attributes.created | Date | Creation time in UTC. | 
| AzureKeyVault.Secret.attributes.updated | Date | Last updated time in UTC. | 
| AzureKeyVault.Secret.attributes.recoveryLevel | String | Reflects the deletion recovery level currently in effect for secrets in the current vault. If it contains 'Purgeable', the secret can be permanently deleted by a privileged user; otherwise, only the system can purge the secret, at the end of the retention interval. | 
| AzureKeyVault.Secret.attributes.recoverableDays | Number | softDelete data retention days. Value should be &gt;=7 and &lt;=90 when softDelete enabled, otherwise 0. | 


#### Command Example
```!azure-key-vault-secret-list vault_name=xsoar-test-vault```

#### Context Example
```json
{
    "AzureKeyVault": {
        "Secret": [
            {
                "attributes": {
                    "create_time": "2021-08-11T12:05:48Z",
                    "enabled": true,
                    "expiry_time": "2022-08-11T12:05:48Z",
                    "recoverableDays": 90,
                    "recoveryLevel": "Recoverable+Purgeable",
                    "should_not_be_retrieved_Before": 1628682948,
                    "update_time": "2021-08-11T12:05:48Z"
                },
                "contentType": "application/x-pkcs12",
                "id": "https://xsoar-test-vault.vault.azure.net/secrets/test-cer-1",
                "managed": true,
                "tags": {}
            },
            {
                "attributes": {
                    "create_time": "2021-08-11T12:06:00Z",
                    "enabled": true,
                    "expiry_time": "2022-08-11T12:06:00Z",
                    "recoverableDays": 90,
                    "recoveryLevel": "Recoverable+Purgeable",
                    "should_not_be_retrieved_Before": 1628682960,
                    "update_time": "2021-08-11T12:06:00Z"
                },
                "contentType": "application/x-pkcs12",
                "id": "https://xsoar-test-vault.vault.azure.net/secrets/test-cer-2",
                "managed": true,
                "tags": {}
            },
            {
                "attributes": {
                    "create_time": "2021-08-11T12:06:24Z",
                    "enabled": true,
                    "expiry_time": "2022-08-11T12:06:24Z",
                    "recoverableDays": 90,
                    "recoveryLevel": "Recoverable+Purgeable",
                    "should_not_be_retrieved_Before": 1628682984,
                    "update_time": "2021-08-11T12:06:24Z"
                },
                "contentType": "application/x-pkcs12",
                "id": "https://xsoar-test-vault.vault.azure.net/secrets/test-cer-3",
                "managed": true,
                "tags": {}
            },
            {
                "attributes": {
                    "create_time": "2021-08-18T06:41:38Z",
                    "enabled": true,
                    "expiry_time": "2022-08-18T06:41:38Z",
                    "recoverableDays": 90,
                    "recoveryLevel": "Recoverable+Purgeable",
                    "should_not_be_retrieved_Before": 1629268298,
                    "update_time": "2021-08-18T06:41:38Z"
                },
                "contentType": "application/x-pkcs12",
                "id": "https://xsoar-test-vault.vault.azure.net/secrets/test-cer-5",
                "managed": true,
                "tags": {}
            },
            {
                "attributes": {
                    "create_time": "2021-08-18T06:41:51Z",
                    "enabled": true,
                    "expiry_time": "2022-08-18T06:41:50Z",
                    "recoverableDays": 90,
                    "recoveryLevel": "Recoverable+Purgeable",
                    "should_not_be_retrieved_Before": 1629268310,
                    "update_time": "2021-08-18T06:41:51Z"
                },
                "contentType": "application/x-pkcs12",
                "id": "https://xsoar-test-vault.vault.azure.net/secrets/test-cer-6",
                "managed": true,
                "tags": {}
            },
            {
                "attributes": {
                    "create_time": "2021-08-11T12:04:12Z",
                    "enabled": true,
                    "expiry_time": "2023-08-11T12:04:06Z",
                    "recoverableDays": 90,
                    "recoveryLevel": "Recoverable+Purgeable",
                    "should_not_be_retrieved_Before": 1628683446,
                    "update_time": "2021-08-17T16:22:57Z"
                },
                "contentType": "text",
                "id": "https://xsoar-test-vault.vault.azure.net/secrets/test-sec-1",
                "tags": {}
            },
            {
                "attributes": {
                    "create_time": "2021-08-11T12:04:26Z",
                    "enabled": true,
                    "recoverableDays": 90,
                    "recoveryLevel": "Recoverable+Purgeable",
                    "update_time": "2021-08-11T12:04:26Z"
                },
                "contentType": "test",
                "id": "https://xsoar-test-vault.vault.azure.net/secrets/test-sec-2",
                "tags": {}
            },
            {
                "attributes": {
                    "create_time": "2021-08-18T07:07:56Z",
                    "enabled": true,
                    "expiry_time": "2023-08-18T07:07:44Z",
                    "recoverableDays": 90,
                    "recoveryLevel": "Recoverable+Purgeable",
                    "should_not_be_retrieved_Before": 1629270464,
                    "update_time": "2021-08-18T07:07:56Z"
                },
                "contentType": "aa",
                "id": "https://xsoar-test-vault.vault.azure.net/secrets/test-sec-9",
                "tags": {}
            },
            {
                "attributes": {
                    "create_time": "2021-08-11T12:04:43Z",
                    "enabled": true,
                    "recoverableDays": 90,
                    "recoveryLevel": "Recoverable+Purgeable",
                    "update_time": "2021-08-11T12:04:43Z"
                },
                "contentType": "text",
                "id": "https://xsoar-test-vault.vault.azure.net/secrets/testsec-3",
                "tags": {}
            },
            {
                "attributes": {
                    "create_time": "2021-08-25T09:31:56Z",
                    "enabled": true,
                    "recoverableDays": 90,
                    "recoveryLevel": "Recoverable+Purgeable",
                    "update_time": "2021-08-25T09:31:56Z"
                },
                "contentType": "aa",
                "id": "https://xsoar-test-vault.vault.azure.net/secrets/xsoar-readme-test",
                "tags": {}
            },
            {
                "attributes": {
                    "create_time": "2021-08-25T09:32:32Z",
                    "enabled": true,
                    "expiry_time": "2022-08-25T09:32:32Z",
                    "recoverableDays": 90,
                    "recoveryLevel": "Recoverable+Purgeable",
                    "should_not_be_retrieved_Before": 1629883352,
                    "update_time": "2021-08-25T09:32:32Z"
                },
                "contentType": "application/x-pkcs12",
                "id": "https://xsoar-test-vault.vault.azure.net/secrets/xsoar-readme-test-2",
                "managed": true,
                "tags": {}
            }
        ]
    }
}
```

#### Human Readable Output

### xsoar-test-vault Secrets List
Current page size: 50
Showing page 1 out others that may exist

|Secret Id|Managed|Create Time|Update Time|Expiry Time|
|---|---|---|---|---|
| https://xsoar-test-vault.vault.azure.net/secrets/test-cer-1 | true | 2021-08-11T12:05:48Z | 2021-08-11T12:05:48Z | 2022-08-11T12:05:48Z |
| https://xsoar-test-vault.vault.azure.net/secrets/test-cer-2 | true | 2021-08-11T12:06:00Z | 2021-08-11T12:06:00Z | 2022-08-11T12:06:00Z |
| https://xsoar-test-vault.vault.azure.net/secrets/test-cer-3 | true | 2021-08-11T12:06:24Z | 2021-08-11T12:06:24Z | 2022-08-11T12:06:24Z |
| https://xsoar-test-vault.vault.azure.net/secrets/test-cer-5 | true | 2021-08-18T06:41:38Z | 2021-08-18T06:41:38Z | 2022-08-18T06:41:38Z |
| https://xsoar-test-vault.vault.azure.net/secrets/test-cer-6 | true | 2021-08-18T06:41:51Z | 2021-08-18T06:41:51Z | 2022-08-18T06:41:50Z |
| https://xsoar-test-vault.vault.azure.net/secrets/test-sec-1 |  | 2021-08-11T12:04:12Z | 2021-08-17T16:22:57Z | 2023-08-11T12:04:06Z |
| https://xsoar-test-vault.vault.azure.net/secrets/test-sec-2 |  | 2021-08-11T12:04:26Z | 2021-08-11T12:04:26Z |  |
| https://xsoar-test-vault.vault.azure.net/secrets/test-sec-9 |  | 2021-08-18T07:07:56Z | 2021-08-18T07:07:56Z | 2023-08-18T07:07:44Z |
| https://xsoar-test-vault.vault.azure.net/secrets/testsec-3 |  | 2021-08-11T12:04:43Z | 2021-08-11T12:04:43Z |  |
| https://xsoar-test-vault.vault.azure.net/secrets/xsoar-readme-test |  | 2021-08-25T09:31:56Z | 2021-08-25T09:31:56Z |  |
| https://xsoar-test-vault.vault.azure.net/secrets/xsoar-readme-test-2 | true | 2021-08-25T09:32:32Z | 2021-08-25T09:32:32Z | 2022-08-25T09:32:32Z |


### azure-key-vault-secret-delete
***
Deletes a secret from a specified key vault.


#### Base Command

`azure-key-vault-secret-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | The vault name. | Required | 
| secret_name | The name of the secret to delete. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKeyVault.Secret.recoveryId | String | 	
The url of the recovery object, used to identify and recover the deleted secret. | 
| AzureKeyVault.Secret.deletedDate | Date | 	
The time when the secret was deleted, in UTC | 
| AzureKeyVault.Secret.scheduledPurgeDate | Date | The time when the secret is scheduled to be purged, in UTC | 
| AzureKeyVault.Secret.id | String | id of the deleted secret | 
| AzureKeyVault.Secret.attributes.enabled | Boolean | Determines whether the object is enabled.
 | 
| AzureKeyVault.Secret.attributes.created | Date | 	
Creation time in UTC. | 
| AzureKeyVault.Secret.attributes.updated | Date | Last updated time in UTC. | 
| AzureKeyVault.Secret.attributes.recoveryLevel | String | Reflects the deletion recovery level currently in effect for secrets in the current vault | 


#### Command Example
```!azure-key-vault-secret-delete secret_name=xsoar-readme-test vault_name=xsoar-test-vault```

#### Context Example
```json
{
    "AzureKeyVault": {
        "Secret": {
            "attributes": {
                "created": 1629883916,
                "enabled": true,
                "recoverableDays": 90,
                "recoveryLevel": "Recoverable+Purgeable",
                "updated": 1629883916
            },
            "contentType": "aa",
            "deletedDate": 1629884342,
            "id": "https://xsoar-test-vault.vault.azure.net/secrets/xsoar-readme-test/ee4e856e35d3498bbeb2a5fcb4812d01",
            "recoveryId": "https://xsoar-test-vault.vault.azure.net/deletedsecrets/xsoar-readme-test",
            "scheduledPurgeDate": 1637660342,
            "tags": {}
        }
    }
}
```

#### Human Readable Output

### Delete xsoar-readme-test
|Id|Recovery Id|Deleted Date|Scheduled Purge Date|
|---|---|---|---|
| https://xsoar-test-vault.vault.azure.net/secrets/xsoar-readme-test/ee4e856e35d3498bbeb2a5fcb4812d01 | https://xsoar-test-vault.vault.azure.net/deletedsecrets/xsoar-readme-test | 2021-08-25T09:39:02Z | 2021-11-23T09:39:02Z |


### azure-key-vault-certificate-get
***
Gets information about a certificate.
Gets information about a specific certificate. This operation requires the certificates/get permission.


#### Base Command

`azure-key-vault-certificate-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | The vault name. | Required | 
| certificate_name | The name of the certificate to get. | Required | 
| certificate_version | The version of the certificate. This URI fragment is optional. If not specified, the latest version of the certificate is returned. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKeyVault.Certificate.id | String | The certificate id.
 | 
| AzureKeyVault.Certificate.kid | String | The key id. | 
| AzureKeyVault.Certificate.sid | String | The secret id. | 
| AzureKeyVault.Certificate.x5t | String | Thumbprint of the certificate. | 
| AzureKeyVault.Certificate.cer | String | 	
CER contents of x509 certificate. | 
| AzureKeyVault.Certificate.attributes.enabled | Boolean | Determines whether the object is enabled.
 | 
| AzureKeyVault.Certificate.attributes.expiry_time | Date | Expiry date in UTC.
 | 
| AzureKeyVault.Certificate.attributes.create_time | Date | Creation time in UTC.
 | 
| AzureKeyVault.Certificate.attributes.update_time | Date | Last updated time in UTC.
 | 
| AzureKeyVault.Certificate.attributes.recoveryLevel | String | Reflects the deletion recovery level currently in effect for certificates in the current vault. If it contains 'Purgeable', the certificate can be permanently deleted by a privileged user; otherwise, only the system can purge the certificate, at the end of the retention interval. | 
| AzureKeyVault.Certificate.policy | Unknown | The management policy.

 | 


#### Command Example
```!azure-key-vault-certificate-get certificate_name=test-cer-1 vault_name=xsoar-test-vault```

#### Context Example
```json
{
    "AzureKeyVault": {
        "Certificate": {
            "attributes": {
                "create_time": "2021-08-11T12:05:48Z",
                "enabled": true,
                "expiry_time": "2022-08-11T12:05:48Z",
                "recoverableDays": 90,
                "recoveryLevel": "Recoverable+Purgeable",
                "should_not_be_retrieved_Before": 1628682948,
                "update_time": "2021-08-11T12:05:48Z"
            },
            "cer": "MIIDJDCCAgygAwIBAgIQdH4YmvSvSYSuIwZ9BVSvzDANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDEwR0ZXN0MB4XDTIxMDgxMTExNTU0OFoXDTIyMDgxMTEyMDU0OFowDzENMAsGA1UEAxMEdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANQ1pdBcYbXYR6NsiX2IAL1fYpgf5RVkJ0cIEx/K77Uvv9srt5tqpdqAtygL7RTiXCGsIfTuyFbsHcQeihekKUMwoAgjkbF6Qw7y+q3h00Q5OLe8+gK+S0F7+DIrE97Yde7ETa1dUmvdOWe4ioaVkToS8h5r+DrJsK1v5rE6kkfJm2HEAQDyN5KBqD75IDn099O1739ZjL31rlVJu0wmoz2N545rZxZIN0a/L8NwNk/3jgUPjRSQiiOKHUpIkkE2d20SFo4fnS2YmExtElr6f6gOD4wreebIPeAnKGsw7gukbRsmBhqVCZs35Q0F15UrehdRCXU2Wk06gGdQVzsIszkCAwEAAaN8MHowDgYDVR0PAQH/BAQDAgWgMAkGA1UdEwQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB8GA1UdIwQYMBaAFLJxh/k981tky3s7whrYPNCUzRs1MB0GA1UdDgQWBBSycYf5PfNbZMt7O8Ia2DzQlM0bNTANBgkqhkiG9w0BAQsFAAOCAQEAjbgJhP4PPp1HopnHi6Vgk+jTzd/LAMm4Im+6XkjlGIOHmmUstvHyBrFju4oyzkzp0ULnRZZLnsnxWxNnJYn23+RxklJhmc3fiy43dBdlTI1I3EzoFV31Or1khzelE8EjicyLJuFCNKWKS9947A7d8g7CbuRVFc9/rYB19uAaxv3xfA8GiIvlrnBVGMs10Baew2yLNooGNDLEiK1I85ygLeT6yVE0yDuocFFLvNiUxgntmI8cD6av9P3QE9U44UwPBmrldw3GFBgIZv0C6j1wN6EwqDUpTdyYO/D+Em9mmVXabcIz1uzFyFfqF6TDmTBTuGyf7PcIsLSxuX6922anHA==",
            "id": "https://xsoar-test-vault.vault.azure.net/certificates/test-cer-1/0102ad8275574b9c8e25b5a6608d5504",
            "kid": "https://xsoar-test-vault.vault.azure.net/keys/test-cer-1/0102ad8275574b9c8e25b5a6608d5504",
            "pending": {
                "id": "https://xsoar-test-vault.vault.azure.net/certificates/test-cer-1/pending"
            },
            "policy": {
                "attributes": {
                    "created": 1628683531,
                    "enabled": true,
                    "updated": 1628683531
                },
                "id": "https://xsoar-test-vault.vault.azure.net/certificates/test-cer-1/policy",
                "issuer": {
                    "name": "Self"
                },
                "key_props": {
                    "exportable": true,
                    "key_size": 2048,
                    "kty": "RSA",
                    "reuse_key": false
                },
                "lifetime_actions": [
                    {
                        "action": {
                            "action_type": "AutoRenew"
                        },
                        "trigger": {
                            "lifetime_percentage": 80
                        }
                    }
                ],
                "secret_props": {
                    "contentType": "application/x-pkcs12"
                },
                "x509_props": {
                    "basic_constraints": {
                        "ca": false
                    },
                    "ekus": [
                        "1.3.6.1.5.5.7.3.1",
                        "1.3.6.1.5.5.7.3.2"
                    ],
                    "key_usage": [
                        "digitalSignature",
                        "keyEncipherment"
                    ],
                    "sans": {
                        "dns_names": []
                    },
                    "subject": "CN=test",
                    "validity_months": 12
                }
            },
            "sid": "https://xsoar-test-vault.vault.azure.net/secrets/test-cer-1/0102ad8275574b9c8e25b5a6608d5504",
            "tags": {},
            "x5t": "g3E8NEflcwlsQmT-JDgO7IWuH4w"
        }
    }
}
```

#### Human Readable Output

### test-cer-1 Information
|Certificate Id|Create Time|Update Time|Expiry Time|
|---|---|---|---|
| https://xsoar-test-vault.vault.azure.net/certificates/test-cer-1/0102ad8275574b9c8e25b5a6608d5504 | 2021-08-11T12:05:48Z | 2021-08-11T12:05:48Z | 2022-08-11T12:05:48Z |


### azure-key-vault-certificate-list
***
List certificates in a specified key vault


#### Base Command

`azure-key-vault-certificate-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | The vault name. | Required | 
| limit | Limit on the number of certificates to return. Default is 50. | Optional | 
| offset | First index to retrieve from. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKeyVault.Certificate.id | String | certificate's id | 
| AzureKeyVault.Certificate.x5t | String | Thumbprint of the certificate. | 
| AzureKeyVault.Certificate.attributes.enabled | Boolean | Determines whether the object is enabled.
 | 
| AzureKeyVault.Certificate.attributes.create_time | Date | Creation time in UTC
 | 
| AzureKeyVault.Certificate.attributes.update_time | Date | Last updated time in UTC.
 | 


#### Command Example
```!azure-key-vault-certificate-list vault_name=xsoar-test-vault```

#### Context Example
```json
{
    "AzureKeyVault": {
        "Certificate": [
            {
                "attributes": {
                    "create_time": "2021-08-11T12:05:48Z",
                    "enabled": true,
                    "expiry_time": "2022-08-11T12:05:48Z",
                    "should_not_be_retrieved_Before": 1628682948,
                    "update_time": "2021-08-11T12:05:48Z"
                },
                "id": "https://xsoar-test-vault.vault.azure.net/certificates/test-cer-1",
                "subject": "",
                "tags": {},
                "x5t": "g3E8NEflcwlsQmT-JDgO7IWuH4w"
            },
            {
                "attributes": {
                    "create_time": "2021-08-11T12:06:00Z",
                    "enabled": true,
                    "expiry_time": "2022-08-11T12:06:00Z",
                    "should_not_be_retrieved_Before": 1628682960,
                    "update_time": "2021-08-11T12:06:00Z"
                },
                "id": "https://xsoar-test-vault.vault.azure.net/certificates/test-cer-2",
                "subject": "",
                "tags": {},
                "x5t": "z288yPQPe1N5eyZ5tCrpyZGjMv8"
            },
            {
                "attributes": {
                    "create_time": "2021-08-11T12:06:24Z",
                    "enabled": true,
                    "expiry_time": "2022-08-11T12:06:24Z",
                    "should_not_be_retrieved_Before": 1628682984,
                    "update_time": "2021-08-11T12:06:24Z"
                },
                "id": "https://xsoar-test-vault.vault.azure.net/certificates/test-cer-3",
                "subject": "",
                "tags": {},
                "x5t": "GvQ4ujs6GsaS1d8odRTej2N6wqo"
            },
            {
                "attributes": {
                    "create_time": "2021-08-18T06:41:38Z",
                    "enabled": true,
                    "expiry_time": "2022-08-18T06:41:38Z",
                    "should_not_be_retrieved_Before": 1629268298,
                    "update_time": "2021-08-18T06:41:38Z"
                },
                "id": "https://xsoar-test-vault.vault.azure.net/certificates/test-cer-5",
                "subject": "",
                "tags": {},
                "x5t": "_D9vXzNEPptHu7Ct8D4E2oYu_4E"
            },
            {
                "attributes": {
                    "create_time": "2021-08-18T06:41:51Z",
                    "enabled": true,
                    "expiry_time": "2022-08-18T06:41:50Z",
                    "should_not_be_retrieved_Before": 1629268310,
                    "update_time": "2021-08-18T06:41:51Z"
                },
                "id": "https://xsoar-test-vault.vault.azure.net/certificates/test-cer-6",
                "subject": "",
                "tags": {},
                "x5t": "25GCjdlaQpjkWm1-jLtAeDNhYtQ"
            },
            {
                "attributes": {
                    "create_time": "2021-08-25T09:32:32Z",
                    "enabled": true,
                    "expiry_time": "2022-08-25T09:32:32Z",
                    "should_not_be_retrieved_Before": 1629883352,
                    "update_time": "2021-08-25T09:32:32Z"
                },
                "id": "https://xsoar-test-vault.vault.azure.net/certificates/xsoar-readme-test-2",
                "subject": "",
                "tags": {},
                "x5t": "ivWchLJipg6jZPl-aZLxukJGMLU"
            }
        ]
    }
}
```

#### Human Readable Output

### xsoar-test-vault Certificates List
 Current page size: 50
 Showing page 1 out others that may exist

|Certificate Id|Create Time|Update Time|Expiry Time|
|---|---|---|---|
| https://xsoar-test-vault.vault.azure.net/certificates/test-cer-1 | 2021-08-11T12:05:48Z | 2021-08-11T12:05:48Z | 2022-08-11T12:05:48Z |
| https://xsoar-test-vault.vault.azure.net/certificates/test-cer-2 | 2021-08-11T12:06:00Z | 2021-08-11T12:06:00Z | 2022-08-11T12:06:00Z |
| https://xsoar-test-vault.vault.azure.net/certificates/test-cer-3 | 2021-08-11T12:06:24Z | 2021-08-11T12:06:24Z | 2022-08-11T12:06:24Z |
| https://xsoar-test-vault.vault.azure.net/certificates/test-cer-5 | 2021-08-18T06:41:38Z | 2021-08-18T06:41:38Z | 2022-08-18T06:41:38Z |
| https://xsoar-test-vault.vault.azure.net/certificates/test-cer-6 | 2021-08-18T06:41:51Z | 2021-08-18T06:41:51Z | 2022-08-18T06:41:50Z |
| https://xsoar-test-vault.vault.azure.net/certificates/xsoar-readme-test-2 | 2021-08-25T09:32:32Z | 2021-08-25T09:32:32Z | 2022-08-25T09:32:32Z |


### azure-key-vault-certificate-policy-get
***
Lists the policy for a certificate


#### Base Command

`azure-key-vault-certificate-policy-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | The vault name. | Required | 
| certificate_name | The name of the certificate to retrieve the policy from. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKeyVault.CertificatePolicy.id | String | policy's id | 
| AzureKeyVault.CertificatePolicy.key_props | Unknown | Properties of the key backing a certificate.
 | 
| AzureKeyVault.CertificatePolicy.x509_props | Unknown | Properties of the X509 component of a certificate | 
| AzureKeyVault.CertificatePolicy.lifetime_actions | Unknown | Actions that will be performed by Key Vault over the lifetime of a certificate. | 
| AzureKeyVault.CertificatePolicy.issuer | Unknown | Parameters for the issuer of the X509 component of a certificate. | 
| AzureKeyVault.CertificatePolicy.attributes.enabled | Boolean | Determines whether the object is enabled.
 | 
| AzureKeyVault.CertificatePolicy.attributes.created | Date | Creation time in UTC. | 
| AzureKeyVault.CertificatePolicy.attributes.updated | Date | Last updated time in UTC | 


#### Command Example
```!azure-key-vault-certificate-policy-get certificate_name=xsoar-readme-test-2 vault_name=xsoar-test-vault```

#### Context Example
```json
{
    "AzureKeyVault": {
        "CertificatePolicy": {
            "attributes": {
                "created": 1629883945,
                "enabled": true,
                "updated": 1629883945
            },
            "id": "https://xsoar-test-vault.vault.azure.net/certificates/xsoar-readme-test-2/policy",
            "issuer": {
                "name": "Self"
            },
            "key_props": {
                "exportable": true,
                "key_size": 2048,
                "kty": "RSA",
                "reuse_key": false
            },
            "lifetime_actions": [
                {
                    "action": {
                        "action_type": "AutoRenew"
                    },
                    "trigger": {
                        "lifetime_percentage": 80
                    }
                }
            ],
            "secret_props": {
                "contentType": "application/x-pkcs12"
            },
            "x509_props": {
                "basic_constraints": {
                    "ca": false
                },
                "ekus": [
                    "1.3.6.1.5.5.7.3.1",
                    "1.3.6.1.5.5.7.3.2"
                ],
                "key_usage": [
                    "digitalSignature",
                    "keyEncipherment"
                ],
                "sans": {
                    "dns_names": []
                },
                "subject": "CN=aa",
                "validity_months": 12
            }
        }
    }
}
```

#### Human Readable Output

### xsoar-readme-test-2 Policy Information
|Id|Key Props|Secret Props|
|---|---|---|
| https://xsoar-test-vault.vault.azure.net/certificates/xsoar-readme-test-2/policy | exportable: true<br/>kty: RSA<br/>key_size: 2048<br/>reuse_key: false | contentType: application/x-pkcs12 |

