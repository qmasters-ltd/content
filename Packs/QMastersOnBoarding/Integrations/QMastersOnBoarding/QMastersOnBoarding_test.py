import json
import os
import pytest
from QMastersOnBoarding import Client, alert_list_command, alert_get_command, fetch_incidents

SERVER_URL = 'http://192.168.30.170:8000/'
PASSWORD = 'sdfs'
USERNAME = 'cvbcb'
BASE_URL = SERVER_URL


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """

    with open(os.path.join('test_data', file_name), mode='r', encoding='utf-8') as mock_file:
        return json.loads(mock_file.read())


@pytest.fixture(autouse=True)
def mock_client():
    return Client(server_url=SERVER_URL, password=PASSWORD, username=USERNAME, proxy=False, verify=True)


def test_alert_list_command(requests_mock, mock_client):

    mock_response = load_mock_response('alert_list_respone.json')
    # params = {'from_created_date': '1', 'page': '1', 'size': '50'}

    url = f'{BASE_URL}alerts/?from_created_date=1&page=1&size=50'
    requests_mock.get(url=url, json=mock_response)

    result = alert_list_command(mock_client, {'from_created_date': '1', 'page': '1', 'size': '50'})

    assert result.outputs_prefix == 'qmastersonboarding.Alert'
    # assert len(result.outputs[0]) == 15
    # assert result.outputs[0]['id'] == 'id'


def test_alert_get_command(requests_mock, mock_client):
    alert_id = 'blabla'
    mock_response = load_mock_response('alert_details_respone.json')
    url = f'{BASE_URL}alerts/{alert_id}'

    requests_mock.get(url=url, json=mock_response)

    result = alert_get_command(mock_client, {'alert_id': 'blabla'})
    assert result.outputs_prefix == 'qmastersonboarding.Alert'
    # assert len(result.outputs[0]) == 15
    # assert result.outputs[0]['id'] == 'id'


def test_fetch_incidents(requests_mock, mock_client):
    list_response = load_mock_response('alert_list_respone.json')
    alert_data = [
        load_mock_response('alert_get_1.json'),
        load_mock_response('alert_get_2.json'),
        load_mock_response('alert_get_3.json')
    ]

    from_created_date = 0
    page = 1
    size = 3
    url = f'{BASE_URL}alerts/?from_created_date={from_created_date}&page={page}&size={size}'
    requests_mock.get(url=url, json=list_response)

    url = f'{BASE_URL}alerts/59490d48e57c281391e11c8d'
    requests_mock.get(url=url, json=alert_data[0])
    url = f'{BASE_URL}alerts/59490d50e57c281391e11c93'
    requests_mock.get(url=url, json=alert_data[1])
    url = f'{BASE_URL}alerts/59490d54e57c281391e11c97'
    requests_mock.get(url=url, json=alert_data[2])

    next_run, incidents = fetch_incidents(mock_client, {'max_fetch': 3})

    assert len(incidents) == 3
    assert set(['id', 'time']).issubset(next_run.keys())
