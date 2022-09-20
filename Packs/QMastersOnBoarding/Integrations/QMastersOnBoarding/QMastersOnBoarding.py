from typing import Any, Dict, Tuple, List
import json
import demistomock as demisto
import dateutil.parser as dp
from CommonServerPython import *


class Client(BaseClient):

    def __init__(self, server_url: str, password: str, username: str, verify: bool = False, proxy: bool = False):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, auth=(username, password))

    def alert_list_request(self, from_created_date=0, page=1, size=50) -> Dict[str, Any]:
        """Gets list of alerts from created date and by size and page.

        Args:
            from_created_date (int): Seconds timestamp number. Defaults to "0".
            page (int): Page number. Defaults to "1".
            size (int): Size of list number. Defaults to "50".

        Returns:
            Dict[str, Any]: API response from QMastersOnBoarding.
        """
        res = self._http_request(method='GET',
                                 url_suffix=f'alerts/?from_created_date={from_created_date}&page={page}&size={size}')
        return res

    def alert_create_request(self, severity: str, alert_type: str, is_closed: bool) -> str:
        """Create new alert.

        Args:
            severity (str): Alert severity.
            alert_type (str): Alert type.
            is_closed (bool): Is alert closed?

        Returns:
            str: API response from QMastersOnBoarding.
        """
        data = {"AlertDetails": {"Severity": severity, "AlertType": alert_type}, "IsClosed": is_closed}
        res = self._http_request(method='PUT', url_suffix='alerts', json_data=data, resp_type='text')
        return res

    def alert_get_request(self, alert_id: str) -> Dict[str, Any]:
        """Gets alert information.

        Args:
            alert_id (str): Alert id.

        Returns:
            Dict[str, Any]:  API response from QMastersOnBoarding.
        """
        res = self._http_request(method='GET', url_suffix=f'alerts/{alert_id}')
        return res


def alert_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ Lists alerts from created date by size, page.

    Args:
        client (Client): QMastersOnBoarding API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    from_created_date = arg_to_number(args.get('from_created_date'))
    page = arg_to_number(args.get('page'))
    size = arg_to_number(args.get('size'))
    response = client.alert_list_request(from_created_date, page, size)
    alerts_dict = {"Alerts list": response['items']}
    readable_output = tableToMarkdown("Alerts list", alerts_dict, headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='qmastersonboarding.Alert',
                                     outputs_key_field='AlertId',
                                     outputs=response,
                                     raw_response=response)
    return command_results


def alert_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Creates new alert.

    Args:
        client (Client): QMastersOnBoarding API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    severity = str(args.get('sevirity'))
    alert_type = str(args.get('alert_type'))
    is_closed = argToBoolean(args.get('is_closed'))
    response = client.alert_create_request(severity, alert_type, is_closed)
    alert_dict = {"Alert Id": response}
    readable_output = tableToMarkdown("Succesfuly created!", alert_dict, headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='qmastersonboarding.Alert',
                                     outputs_key_field='AlertId',
                                     outputs=response,
                                     raw_response=response)

    return command_results


def alert_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Gets alert information.

    Args:
        client (Client): QMastersOnBoarding API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    alert_id = args['alert_id']
    response = client.alert_get_request(alert_id)
    details_dict = {
        'Severity': dict_safe_get(response, ['AlertDetails', 'Severity']),
        'AlertType': dict_safe_get(response, ['AlertDetails', 'AlertType']),
        'AlertId': dict_safe_get(response, ['AlertId']),
        'AlertReporter': dict_safe_get(response, ['AlertReporter']),
        'State': dict_safe_get(response, ['AlertStatus', 'State']),
        'LastUpdateTime': dict_safe_get(response, ['AlertStatus', 'LastUpdateTime']),
        'CreatedDate': dict_safe_get(response, ['CreatedDate']),
        'IsClosed': dict_safe_get(response, ['IsClosed']),
    }
    readable_output = tableToMarkdown("Alert details", details_dict, headerTransform=string_to_table_header)
    command_results = CommandResults(readable_output=readable_output,
                                     outputs_prefix='qmastersonboarding.Alert',
                                     outputs_key_field='AlertId',
                                     outputs=details_dict,
                                     raw_response=response)
    return command_results


def convert_to_demisto_severity(severity: str) -> int:
    """
    Maps QMasterOnBoarding severity to Cortex XSOAR severity.
    Converts the HelloWorld alert severity level ('Low', 'Medium', 'High', 'Critical') to Cortex XSOAR incident
    severity (1 to 4).
    Args:
        severity (str): severity as returned from the HelloWorld API.
        first_fetch_time (int): The first fetch time as configured in the integration params.
    Returns:
        int: Cortex XSOAR Severity (1 to 4)
    """
    return {
        'Low': IncidentSeverity.LOW,
        'Medium': IncidentSeverity.MEDIUM,
        'High': IncidentSeverity.HIGH,
        'Critical': IncidentSeverity.CRITICAL
    }[severity]


def parse_incident(alert_data: dict) -> dict:
    """
    Parse alert to XSOAR Incident.
    Args:
        alert (dict): alert item.
    Returns:
        dict: XSOAR Incident.
    """

    alert_date = datetime.strptime(alert_data['CreatedDate'], '%Y-%m-%dT%H:%M:%S.%f')  # type: ignore
    iso_time = FormatIso8601(alert_date) + 'Z'
    incident = {
        'name': alert_data['AlertId'],
        # 'type': alert_data['AlertDetails']['AlertType'],
        'severity': convert_to_demisto_severity(alert_data['AlertDetails']['Severity']),
        # 'status': alert_data['AlertStatus']['State'],
        'owner': alert_data['AlertReporter'],
        'occurred': iso_time,
        'rawJSON': json.dumps(alert_data)
    }
    return incident


def fetch_incidents(client: Client, args: dict) -> Tuple[Dict[str, int], List[dict]]:
    """
    This function retrieves new alerts every interval (default is 1 minute).
    It has to implement the logic of making sure that incidents are fetched only onces and no incidents are missed.
    By default it's invoked by XSOAR every minute. It will use last_run to save the timestamp of the last incident it
    processed. If last_run is not provided, it should use the integration parameter first_fetch_time to determine when
    to start fetching the first time.


    Args:
        client (Client): QMastersOnBoarding client to use.
        args (dict): The args for fetch: alert types, alert severities, alert status,
                     max fetch and first fetch.

    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of incidents that will be created in XSOAR.
    """
    last_run = demisto.getLastRun()
    last_run_id = last_run.get('id')
    last_run_time = last_run.get('time', 0)
    max_fetch = arg_to_number(args['max_fetch'])
    if not last_run:
        first_fetch = args.get('first_fetch', '3 days')
        last_run_time = int(dp.parse(str(arg_to_datetime(first_fetch))).timestamp())

    alert_list = client.alert_list_request(from_created_date=last_run_time, size=max_fetch)
    incidents = []

    for alert in alert_list['items']:
        if alert != last_run_id:
            alert_data = client.alert_get_request(alert)
            incidents.append(parse_incident(alert_data))

    if incidents:
        last_run_time = int(dp.parse(alert_data['CreatedDate']).timestamp())
        last_run_id = alert_data['AlertId']
    next_run = {'time': last_run_time, 'id': last_run_id}
    return next_run, incidents


def test_module(client: Client) -> str:
    """
    Returning 'ok' indicates that the integration works like it suppose to. Connection to the service is successful.

    Args:
        client: QMastersOnBoarding client

    Returns:
        'ok' if test passed, anything else will fail the test
    """

    result = client.alert_list_request()
    if len(result['items']) == 50:
        return 'ok'
    else:
        return 'Test failed.'


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')
    server_url = params.get('api_endpoint')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    commands = {
        'qmastersonboarding-alert-list': alert_list_command,
        'qmastersonboarding-alert-create': alert_create_command,
        'qmastersonboarding-alert-get': alert_get_command,
    }
    demisto.debug(f'Command being called is {command}')
    try:
        client: Client = Client(server_url=server_url,
                                password=password,
                                username=username,
                                verify=verify_certificate,
                                proxy=proxy)
        if command == 'test-module':
            return_results(test_module(client))
        if command == 'fetch-incidents':
            next_run, incidents = fetch_incidents(client, params)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')  # Log exceptions and return errors
    except Exception:
        pass


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
