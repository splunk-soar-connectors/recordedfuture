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


def test_playbook_alerts_search_success(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "playbook alerts search",
        "identifier": "playbook_alerts_search",
        "config": {},
        "parameters": [{"category": "domain_abuse", "status": "New", "limit": 10}],
        "environment_variables": {},
    }

    requests_mock.post(
        f"{BASE_URL}/playbook_alert/search",
        json={"alerts": [{"id": "pa001", "category": "domain_abuse"}]},
        headers=JSON_HEADERS,
        additional_matcher=lambda req: req.json().get("categories") == ["domain_abuse"] and req.json().get("statuses") == ["New"],
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True


def test_playbook_alerts_search_no_filters(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "playbook alerts search",
        "identifier": "playbook_alerts_search",
        "config": {},
        "parameters": [{}],
        "environment_variables": {},
    }

    requests_mock.post(
        f"{BASE_URL}/playbook_alert/search",
        json={"alerts": []},
        headers=JSON_HEADERS,
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True


def test_playbook_alerts_search_api_error(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "playbook alerts search",
        "identifier": "playbook_alerts_search",
        "config": {},
        "parameters": [{"category": "domain_abuse"}],
        "environment_variables": {},
    }

    requests_mock.post(f"{BASE_URL}/playbook_alert/search", status_code=500, json={"message": "Server Error"})

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is False


def test_playbook_alert_details_success(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "playbook alert details",
        "identifier": "playbook_alert_details",
        "config": {},
        "parameters": [{"alert_id": "pa001"}],
        "environment_variables": {},
    }

    requests_mock.get(
        f"{BASE_URL}/playbook_alert/pa001",
        json={"id": "pa001", "category": "domain_abuse", "status": "New"},
        headers=JSON_HEADERS,
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True


def test_playbook_alert_details_api_error(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "playbook alert details",
        "identifier": "playbook_alert_details",
        "config": {},
        "parameters": [{"alert_id": "nonexistent"}],
        "environment_variables": {},
    }

    requests_mock.get(f"{BASE_URL}/playbook_alert/nonexistent", status_code=404, json={"message": "Not Found"})

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is False


def test_update_playbook_alert_success(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "update playbook alert",
        "identifier": "update_playbook_alert",
        "config": {},
        "parameters": [{"alert_id": "pa001", "status": "In Progress", "priority": "High", "log_message": "Under investigation"}],
        "environment_variables": {},
    }

    requests_mock.put(
        f"{BASE_URL}/playbook_alert/pa001",
        json={"id": "pa001", "status": "InProgress"},
        headers=JSON_HEADERS,
        additional_matcher=lambda req: req.json().get("status") == "InProgress",
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True


def test_update_playbook_alert_api_error(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "update playbook alert",
        "identifier": "update_playbook_alert",
        "config": {},
        "parameters": [{"alert_id": "pa001", "status": "Resolved"}],
        "environment_variables": {},
    }

    requests_mock.put(f"{BASE_URL}/playbook_alert/pa001", status_code=403, json={"message": "Forbidden"})

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is False
