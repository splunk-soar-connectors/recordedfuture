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


def test_alert_search_no_results(rf_connector, requests_mock):
    """When no alerts match, action should succeed with a message."""
    in_json: InputJSON = {
        "action": "alert search",
        "identifier": "alert_search",
        "config": {},
        "parameters": [{"rule_id": "rule123", "timeframe": "-7d"}],
        "environment_variables": {},
    }

    requests_mock.get(
        f"{BASE_URL}/alert/rule/rule123",
        json={"counts": {"total": 0, "returned": 0}, "data": {"results": []}},
        headers=JSON_HEADERS,
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True
    assert result.get_summary()["total_number_of_alerts"] == 0


def test_alert_search_with_results(rf_connector, requests_mock):
    """When alerts exist, should also look up each alert by ID."""
    in_json: InputJSON = {
        "action": "alert search",
        "identifier": "alert_search",
        "config": {},
        "parameters": [{"rule_id": "rule123", "timeframe": "-7d"}],
        "environment_variables": {},
    }

    rule_response = {
        "counts": {"total": 1, "returned": 1},
        "data": {"results": [{"id": "alert001", "rule": {"id": "rule123", "name": "Test Rule"}}]},
    }
    alert_detail = {"id": "alert001", "title": "Alert One", "triggered": "2025-01-01T00:00:00Z"}

    requests_mock.get(f"{BASE_URL}/alert/rule/rule123", json=rule_response, headers=JSON_HEADERS)
    requests_mock.get(f"{BASE_URL}/alert/lookup/alert001", json=alert_detail, headers=JSON_HEADERS)

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True
    assert result.get_summary()["rule_name"] == "Test Rule"


def test_alert_search_api_error(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "alert search",
        "identifier": "alert_search",
        "config": {},
        "parameters": [{"rule_id": "rule123", "timeframe": "-7d"}],
        "environment_variables": {},
    }

    requests_mock.get(f"{BASE_URL}/alert/rule/rule123", status_code=500, json={"message": "Server Error"})

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is False


def test_alert_lookup_success(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "alert lookup",
        "identifier": "alert_lookup",
        "config": {},
        "parameters": [{"alert_id": "alert001"}],
        "environment_variables": {},
    }

    requests_mock.get(
        f"{BASE_URL}/alert/lookup/alert001",
        json={"id": "alert001", "title": "Phishing Campaign", "triggered": "2025-01-15T12:00:00Z"},
        headers=JSON_HEADERS,
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True
    summary = result.get_summary()
    assert summary["alert_title"] == "Phishing Campaign"
    assert summary["triggered"] == "2025-01-15T12:00:00Z"


def test_alert_lookup_api_error(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "alert lookup",
        "identifier": "alert_lookup",
        "config": {},
        "parameters": [{"alert_id": "nonexistent"}],
        "environment_variables": {},
    }

    requests_mock.get(f"{BASE_URL}/alert/lookup/nonexistent", status_code=404, json={"message": "Not Found"})

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is False


def test_alert_update_success(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "alert update",
        "identifier": "alert_update",
        "config": {},
        "parameters": [{"alert_id": "alert001", "alert_status": "Pending", "alert_note": "Investigating"}],
        "environment_variables": {},
    }

    requests_mock.post(
        f"{BASE_URL}/alert/update",
        json={"success": [{"id": "alert001", "status": "Pending"}]},
        headers=JSON_HEADERS,
        additional_matcher=lambda req: req.json() == [{"id": "alert001", "status": "Pending", "note": "Investigating"}],
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True
    assert result.get_summary()["update"] == "Successful"


def test_alert_update_api_error(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "alert update",
        "identifier": "alert_update",
        "config": {},
        "parameters": [{"alert_id": "alert001", "alert_status": "Pending", "alert_note": ""}],
        "environment_variables": {},
    }

    requests_mock.post(f"{BASE_URL}/alert/update", status_code=500, json={"message": "Server Error"})

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is False


def test_alert_rule_search_success(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "alert rule search",
        "identifier": "alert_rule_search",
        "config": {},
        "parameters": [{"rule_search": "phishing"}],
        "environment_variables": {},
    }

    requests_mock.get(
        f"{BASE_URL}/config/alert/rules",
        json={
            "counts": {"returned": 2, "total": 2},
            "data": {"results": [{"id": "r1", "title": "Phishing Rule"}, {"id": "r2", "title": "Phishing Advanced"}]},
        },
        headers=JSON_HEADERS,
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True
    summary = result.get_summary()
    assert summary["rules_returned"] == 2
    assert "r1" in summary["rule_id_list"]
    assert "r2" in summary["rule_id_list"]


def test_alert_rule_search_no_query(rf_connector, requests_mock):
    """When no rule_search param, should still call the endpoint with just limit."""
    in_json: InputJSON = {
        "action": "alert rule search",
        "identifier": "alert_rule_search",
        "config": {},
        "parameters": [{}],
        "environment_variables": {},
    }

    requests_mock.get(
        f"{BASE_URL}/config/alert/rules",
        json={"counts": {"returned": 0, "total": 0}, "data": {"results": []}},
        headers=JSON_HEADERS,
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True
    assert result.get_summary()["rules_returned"] == 0
