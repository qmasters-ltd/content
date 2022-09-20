Alerts service
This integration was integrated and tested with version xx of qmastersonboarding

## Configure QMastersOnboarding on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for QMastersOnboarding.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Endpoint |  | True |
    | API username and password |  | True |
    | Password |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | First fetch time | First alert created date to fetch. e.g., "1 min ago","2 weeks ago","3 months ago" | False |
    | Maximum incidents for one fetch. | Maximum number of incidents per fetch. Default is 50. The maximum is 100. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### qmastersonboarding-alert-list
***
Retrieve alerts IDs.


#### Base Command

`qmastersonboarding-alert-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_created_date | Start date to fetch from in Unix Millisecond Timestamp. Default is 0. | Optional | 
| alert_type | A comma-separated list of Alert's type. Possible values are: ApplicationStores, BlackMarkets, HackingForums, SocialMedia, PasteSites, AttackIndication, ExploitableData, BrandSecurity, Phishing, DataLeakage, Others. | Optional | 
| severity | A comma-separated list of Alert's severity. Possible values are: Low, Medium, High. | Optional | 
| is_closed | Show closed/open alerts. | Optional | 
| page | Page number. Default is 1. | Optional | 
| size | Size number. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| qmastersonboarding.Alert.items | String | List of alerts. | 
| qmastersonboarding.Alert.total | Number | Number of alerts. | 
| qmastersonboarding.Alert.page | Number | Page number. | 
| qmastersonboarding.Alert.size | Number | Size number. | 

#### Command example
```!qmastersonboarding-alert-list```
#### Context Example
```json
{
    "qmastersonboarding": {
        "Alert": {
            "items": [
                "59490d48e57c281391e11c8d",
                "59490d50e57c281391e11c93",
                "59490d54e57c281391e11c97",
                "59490d6ce57c281391e11cae",
                "59490d6ee57c281391e11cb0",
                "59490d74e57c281391e11cb4",
                "59490d76e57c281391e11cb6",
                "59490d78e57c281391e11cb8",
                "59490d7ae57c281391e11cba",
                "59490d7ae57c281391e11cbb",
                "59490d7be57c281391e11cbd",
                "59490d7de57c281391e11cbf",
                "59490d7fe57c281391e11cc1",
                "59490d81e57c281391e11cc3",
                "59490d84e57c281391e11cc5",
                "59490d86e57c281391e11cc7",
                "59490d88e57c281391e11cc9",
                "59490d8ae57c281391e11ccb",
                "59490d8ce57c281391e11ccd",
                "59490d8ee57c281391e11ccf",
                "59490d91e57c281391e11cd1",
                "59490d93e57c281391e11cd3",
                "59490d95e57c281391e11cd5",
                "59490d96e57c281391e11cd7",
                "59490d98e57c281391e11cd9",
                "59490d9be57c281391e11cdb",
                "59490d9de57c281391e11cdd",
                "59490d9ee57c281391e11cdf",
                "59490da8e57c281391e11ce9",
                "59490dabe57c281391e11ceb",
                "59490db0e57c281391e11cf0",
                "5f3961e69d01b2000783c17e",
                "5fe4df67ad065100077b0639",
                "6043d51a13e3b600073f5185",
                "60472f1cb0bf210007df508c",
                "60472fa8e5723400082dff6c",
                "604734b0b0bf210007df5093",
                "6047373f08d6cb0007928c6a",
                "60473852119a5000070bf6e0",
                "604738a9119a5000070bf6e3",
                "6047b9f240a1d60007564a9f",
                "6047ba72e3103c0007ab9391",
                "604878af08d6cb0007928d9c",
                "604886514710230008cebcc4",
                "6048b23971b5c10007313d9e",
                "6048b28cb6045200073aba39",
                "6049de7ae693950007e1dfc6",
                "6049df1723fc630008cde43c",
                "6049e00392bc2e0007592147",
                "604a127d0c50130007a5185e"
            ],
            "page": 1,
            "size": 50,
            "total": 155
        }
    }
}
```

#### Human Readable Output

>### Alerts list
>|Alerts List|
>|---|
>| 59490d48e57c281391e11c8d |
>| 59490d50e57c281391e11c93 |
>| 59490d54e57c281391e11c97 |
>| 59490d6ce57c281391e11cae |
>| 59490d6ee57c281391e11cb0 |
>| 59490d74e57c281391e11cb4 |
>| 59490d76e57c281391e11cb6 |
>| 59490d78e57c281391e11cb8 |
>| 59490d7ae57c281391e11cba |
>| 59490d7ae57c281391e11cbb |
>| 59490d7be57c281391e11cbd |
>| 59490d7de57c281391e11cbf |
>| 59490d7fe57c281391e11cc1 |
>| 59490d81e57c281391e11cc3 |
>| 59490d84e57c281391e11cc5 |
>| 59490d86e57c281391e11cc7 |
>| 59490d88e57c281391e11cc9 |
>| 59490d8ae57c281391e11ccb |
>| 59490d8ce57c281391e11ccd |
>| 59490d8ee57c281391e11ccf |
>| 59490d91e57c281391e11cd1 |
>| 59490d93e57c281391e11cd3 |
>| 59490d95e57c281391e11cd5 |
>| 59490d96e57c281391e11cd7 |
>| 59490d98e57c281391e11cd9 |
>| 59490d9be57c281391e11cdb |
>| 59490d9de57c281391e11cdd |
>| 59490d9ee57c281391e11cdf |
>| 59490da8e57c281391e11ce9 |
>| 59490dabe57c281391e11ceb |
>| 59490db0e57c281391e11cf0 |
>| 5f3961e69d01b2000783c17e |
>| 5fe4df67ad065100077b0639 |
>| 6043d51a13e3b600073f5185 |
>| 60472f1cb0bf210007df508c |
>| 60472fa8e5723400082dff6c |
>| 604734b0b0bf210007df5093 |
>| 6047373f08d6cb0007928c6a |
>| 60473852119a5000070bf6e0 |
>| 604738a9119a5000070bf6e3 |
>| 6047b9f240a1d60007564a9f |
>| 6047ba72e3103c0007ab9391 |
>| 604878af08d6cb0007928d9c |
>| 604886514710230008cebcc4 |
>| 6048b23971b5c10007313d9e |
>| 6048b28cb6045200073aba39 |
>| 6049de7ae693950007e1dfc6 |
>| 6049df1723fc630008cde43c |
>| 6049e00392bc2e0007592147 |
>| 604a127d0c50130007a5185e |


### qmastersonboarding-alert-create
***
Create a new alert.


#### Base Command

`qmastersonboarding-alert-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sevirity | Alert's severity. | Required | 
| alert_type | Type of the alert. | Required | 
| is_closed | Is the alert open/closed?. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!qmastersonboarding-alert-create alert_type="ApplicationStores" sevirity="Low" is_closed=true```
#### Context Example
```json
{
    "qmastersonboarding": {
        "Alert": "GAIQ6C5QmWUjAmwutE3V4Mdw"
    }
}
```

#### Human Readable Output

>### Succesfuly created!
>|Alert Id|
>|---|
>| GAIQ6C5QmWUjAmwutE3V4Mdw |


### qmastersonboarding-alert-get
***
Retrieve alert information by ID.


#### Base Command

`qmastersonboarding-alert-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| qmastersonboarding.Alert.Severity | String | Alert's severity. | 
| qmastersonboarding.Alert.AlertType | String | Type of the alert. | 
| qmastersonboarding.Alert.IsClosed | Boolean | Alert close/open | 
| qmastersonboarding.Alert.AlertId | String | Alert's Id. | 
| qmastersonboarding.Alert.CreatedDate | Date | Alert's created date | 
| qmastersonboarding.Alert.AlertReporter | String | The alert reporter name. | 
| qmastersonboarding.Alert.State | String | Alert status state. | 
| qmastersonboarding.Alert.LastUpdateTime | Date | Last update date. | 

#### Command example
```!qmastersonboarding-alert-get alert_id=59490d48e57c281391e11c8d```
#### Context Example
```json
{
    "qmastersonboarding": {
        "Alert": {
            "AlertId": "59490d48e57c281391e11c8d",
            "AlertReporter": "System",
            "AlertType": "AttackIndication",
            "CreatedDate": "2022-03-21T09:59:17.667000",
            "IsClosed": false,
            "LastUpdateTime": "2022-03-21T09:59:17.667000",
            "Severity": "High",
            "State": "Completed"
        }
    }
}
```

#### Human Readable Output

>### Alert details
>|Alertid|Alertreporter|Alerttype|Createddate|Isclosed|Lastupdatetime|Severity|State|
>|---|---|---|---|---|---|---|---|
>| 59490d48e57c281391e11c8d | System | AttackIndication | 2022-03-21T09:59:17.667000 | false | 2022-03-21T09:59:17.667000 | High | Completed |

