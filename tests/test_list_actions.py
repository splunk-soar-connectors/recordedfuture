# Copyright (c) 2025-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import json

from pytest_splunk_soar_connectors.models import InputJSON


BASE_URL = "http://localhost:8089/phantom"
JSON_HEADERS = {"Content-Type": "application/json"}


def test_list_create_success(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "list create",
        "identifier": "list_create",
        "config": {},
        "parameters": [{"list_name": "My New List", "entity_types": "ip"}],
        "environment_variables": {},
    }

    requests_mock.post(
        f"{BASE_URL}/list/create",
        json={"id": "new123", "name": "My New List", "type": "ip"},
        headers=JSON_HEADERS,
        additional_matcher=lambda req: req.json() == {"name": "My New List", "type": "ip"},
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True


def test_list_create_api_error(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "list create",
        "identifier": "list_create",
        "config": {},
        "parameters": [{"list_name": "Bad List", "entity_types": "ip"}],
        "environment_variables": {},
    }

    requests_mock.post(f"{BASE_URL}/list/create", status_code=500, json={"message": "Server Error"})

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is False


def test_list_entities_success(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "list entities",
        "identifier": "list_entities",
        "config": {},
        "parameters": [{"list_id": "abc123"}],
        "environment_variables": {},
    }

    requests_mock.get(
        f"{BASE_URL}/list/abc123/entities",
        json={"entities": [{"id": "e1", "name": "1.2.3.4"}]},
        headers=JSON_HEADERS,
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True


def test_list_status_success(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "list status",
        "identifier": "list_status",
        "config": {},
        "parameters": [{"list_id": "abc123"}],
        "environment_variables": {},
    }

    requests_mock.get(
        f"{BASE_URL}/list/abc123/status",
        json={"status": "active", "count": 10},
        headers=JSON_HEADERS,
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True


def test_list_add_entity_success(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "list add entity",
        "identifier": "list_add-entity",
        "config": {},
        "parameters": [{"list_id": "abc123", "entity_id": "ip:1.2.3.4", "entity_name": "1.2.3.4", "entity_type": "ip"}],
        "environment_variables": {},
    }

    requests_mock.post(
        f"{BASE_URL}/list/abc123/entity/add",
        json={"status": "added"},
        headers=JSON_HEADERS,
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True


def test_list_remove_entity_success(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "list remove entity",
        "identifier": "list_remove-entity",
        "config": {},
        "parameters": [{"list_id": "abc123", "entity_id": "ip:1.2.3.4"}],
        "environment_variables": {},
    }

    requests_mock.post(
        f"{BASE_URL}/list/abc123/entity/remove",
        json={"status": "removed"},
        headers=JSON_HEADERS,
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True


def test_list_add_entity_api_error(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "list add entity",
        "identifier": "list_add-entity",
        "config": {},
        "parameters": [{"list_id": "abc123", "entity_id": "ip:1.2.3.4"}],
        "environment_variables": {},
    }

    requests_mock.post(f"{BASE_URL}/list/abc123/entity/add", status_code=403, json={"message": "Forbidden"})

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is False
