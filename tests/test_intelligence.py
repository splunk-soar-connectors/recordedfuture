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

MOCKED_INTELLIGENCE_RESPONSE = {
    "data": {
        "entity": {"id": "ip:1.2.3.4", "name": "1.2.3.4"},
        "risk": {"criticalityLabel": "High", "riskSummary": "3 of 10 rules triggered"},
        "timestamps": {"lastSeen": "2025-01-01T00:00:00Z"},
    }
}


def _make_intelligence_in_json(action_name, identifier, param_key, param_value):
    return {
        "action": action_name,
        "identifier": identifier,
        "config": {},
        "parameters": [{param_key: param_value}],
        "environment_variables": {},
    }


def test_ip_intelligence_success(rf_connector, requests_mock):
    in_json: InputJSON = _make_intelligence_in_json("ip intelligence", "ip_intelligence", "ip", "1.2.3.4")

    requests_mock.post(
        f"{BASE_URL}/lookup/intelligence",
        json=MOCKED_INTELLIGENCE_RESPONSE,
        headers=JSON_HEADERS,
        additional_matcher=lambda req: req.json() == {"entity_type": "ip", "ioc": "1.2.3.4"},
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True
    summary = result.get_summary()
    assert summary["criticalityLabel"] == "High"
    assert summary["riskSummary"] == "3 of 10 rules triggered"
    assert summary["lastSeen"] == "2025-01-01T00:00:00Z"


def test_domain_intelligence_success(rf_connector, requests_mock):
    in_json: InputJSON = _make_intelligence_in_json("domain intelligence", "domain_intelligence", "domain", "example.com")

    requests_mock.post(
        f"{BASE_URL}/lookup/intelligence",
        json={"data": {"entity": {"id": "domain:example.com"}, "risk": {}}},
        headers=JSON_HEADERS,
        additional_matcher=lambda req: req.json() == {"entity_type": "domain", "ioc": "example.com"},
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True


def test_file_intelligence_success(rf_connector, requests_mock):
    """File intelligence uses 'hash' as the parameter key."""
    in_json: InputJSON = _make_intelligence_in_json("file intelligence", "file_intelligence", "hash", "abc123hash")

    requests_mock.post(
        f"{BASE_URL}/lookup/intelligence",
        json={"data": {"entity": {"id": "hash:abc123hash"}, "risk": {}}},
        headers=JSON_HEADERS,
        additional_matcher=lambda req: req.json() == {"entity_type": "file", "ioc": "abc123hash"},
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True


def test_url_intelligence_success(rf_connector, requests_mock):
    in_json: InputJSON = _make_intelligence_in_json("url intelligence", "url_intelligence", "url", "http://evil.com")

    requests_mock.post(
        f"{BASE_URL}/lookup/intelligence",
        json={"data": {"entity": {"id": "url:http://evil.com"}, "risk": {}}},
        headers=JSON_HEADERS,
        additional_matcher=lambda req: req.json() == {"entity_type": "url", "ioc": "http://evil.com"},
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True


def test_vulnerability_intelligence_success(rf_connector, requests_mock):
    in_json: InputJSON = _make_intelligence_in_json(
        "vulnerability intelligence", "vulnerability_intelligence", "vulnerability", "CVE-2021-44228"
    )

    requests_mock.post(
        f"{BASE_URL}/lookup/intelligence",
        json={"data": {"entity": {"id": "vulnerability:CVE-2021-44228"}, "risk": {}}},
        headers=JSON_HEADERS,
        additional_matcher=lambda req: req.json() == {"entity_type": "vulnerability", "ioc": "CVE-2021-44228"},
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True


def test_ip_intelligence_api_error(rf_connector, requests_mock):
    in_json: InputJSON = _make_intelligence_in_json("ip intelligence", "ip_intelligence", "ip", "1.2.3.4")

    requests_mock.post(f"{BASE_URL}/lookup/intelligence", status_code=500, json={"message": "Internal Server Error"})

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is False
