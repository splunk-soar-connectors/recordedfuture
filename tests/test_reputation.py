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

# Reputation response is a list; handler pops the first element
MOCKED_REPUTATION_RESPONSE = [{"id": "ip:1.2.3.4", "name": "1.2.3.4", "riskscore": 75, "rulecount": 3, "maxrules": 10}]


def test_ip_reputation_success(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "ip reputation",
        "identifier": "ip_reputation",
        "config": {},
        "parameters": [{"ip": "1.2.3.4"}],
        "environment_variables": {},
    }

    requests_mock.post(
        f"{BASE_URL}/lookup/reputation",
        json=MOCKED_REPUTATION_RESPONSE,
        headers=JSON_HEADERS,
        additional_matcher=lambda req: req.json() == {"ip": "1.2.3.4"},
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True
    summary = result.get_summary()
    assert summary["risk score"] == 75
    assert summary["risk summary"] == "3 rules triggered of 10"


def test_domain_reputation_success(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "domain reputation",
        "identifier": "domain_reputation",
        "config": {},
        "parameters": [{"domain": "evil.com"}],
        "environment_variables": {},
    }

    requests_mock.post(
        f"{BASE_URL}/lookup/reputation",
        json=[{"id": "domain:evil.com", "name": "evil.com", "riskscore": 90, "rulecount": 5, "maxrules": 10}],
        headers=JSON_HEADERS,
        additional_matcher=lambda req: req.json() == {"domain": "evil.com"},
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True


def test_url_reputation_success(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "url reputation",
        "identifier": "url_reputation",
        "config": {},
        "parameters": [{"url": "http://evil.com/malware"}],
        "environment_variables": {},
    }

    requests_mock.post(
        f"{BASE_URL}/lookup/reputation",
        json=[{"id": "url:http://evil.com/malware", "name": "http://evil.com/malware", "riskscore": 60, "rulecount": 2, "maxrules": 10}],
        headers=JSON_HEADERS,
        additional_matcher=lambda req: req.json() == {"url": "http://evil.com/malware"},
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True


def test_file_reputation_success(rf_connector, requests_mock):
    """File reputation uses 'hash' as both the param key and category."""
    in_json: InputJSON = {
        "action": "file reputation",
        "identifier": "file_reputation",
        "config": {},
        "parameters": [{"hash": "test-file-hash-xyz"}],
        "environment_variables": {},
    }

    requests_mock.post(
        f"{BASE_URL}/lookup/reputation",
        json=[{"id": "hash:test-file-hash-xyz", "name": "test-file-hash-xyz", "riskscore": 50, "rulecount": 1, "maxrules": 10}],
        headers=JSON_HEADERS,
        additional_matcher=lambda req: req.json() == {"hash": "test-file-hash-xyz"},
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True


def test_ip_reputation_no_data(rf_connector, requests_mock):
    """When entity has no id, summary shows 'No information available'."""
    in_json: InputJSON = {
        "action": "ip reputation",
        "identifier": "ip_reputation",
        "config": {},
        "parameters": [{"ip": "10.0.0.1"}],
        "environment_variables": {},
    }

    requests_mock.post(
        f"{BASE_URL}/lookup/reputation",
        json=[{}],  # empty entity — no 'id' key
        headers=JSON_HEADERS,
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True
    assert result.get_summary().get("riskscore") == "No information available."


def test_ip_reputation_api_error(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "ip reputation",
        "identifier": "ip_reputation",
        "config": {},
        "parameters": [{"ip": "1.2.3.4"}],
        "environment_variables": {},
    }

    requests_mock.post(f"{BASE_URL}/lookup/reputation", status_code=500, json={"message": "Server Error"})

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is False
