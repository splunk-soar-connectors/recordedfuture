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


def test_test_connectivity_success(rf_connector, requests_mock):
    requests_mock.get(f"{BASE_URL}/helo", json={}, headers=JSON_HEADERS)
    requests_mock.get(f"{BASE_URL}/config/info", json={}, headers=JSON_HEADERS)

    in_json: InputJSON = {
        "action": "test connectivity",
        "identifier": "test_connectivity",
        "config": {},
        "parameters": [{}],
        "environment_variables": {},
    }

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True
    rf_connector.save_progress.assert_any_call("Connectivity and credentials test passed. You may now close this window")


def test_test_connectivity_failure(rf_connector, requests_mock):
    requests_mock.get(f"{BASE_URL}/helo", status_code=401, json={"message": "Unauthorized"})

    in_json: InputJSON = {
        "action": "test connectivity",
        "identifier": "test_connectivity",
        "config": {},
        "parameters": [{}],
        "environment_variables": {},
    }

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is False
    rf_connector.save_progress.assert_any_call("Connectivity test failed. API endpoint not reachable")


def test_list_contexts_success(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "list contexts",
        "identifier": "list_contexts",
        "config": {},
        "parameters": [{}],
        "environment_variables": {},
    }

    requests_mock.get(
        f"{BASE_URL}/config/triage/contexts",
        json={"malware": {"name": "Malware", "datagroup": "malware"}, "phishing": {"name": "Phishing", "datagroup": "phishing"}},
        headers=JSON_HEADERS,
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True
    assert "malware" in result.get_summary()["contexts_available_for_threat_assessment"]


def test_list_contexts_api_error(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "list contexts",
        "identifier": "list_contexts",
        "config": {},
        "parameters": [{}],
        "environment_variables": {},
    }

    requests_mock.get(f"{BASE_URL}/config/triage/contexts", status_code=500, json={"message": "Server Error"})

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is False


def test_threat_assessment_malicious(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "threat assessment",
        "identifier": "threat_assessment",
        "config": {},
        "parameters": [{"threat_context": "malware", "ip": "1.2.3.4"}],
        "environment_variables": {},
    }

    requests_mock.post(
        f"{BASE_URL}/lookup/triage/malware?&format=phantom",
        json={"verdict": True, "triage_riskscore": 85, "entities": [{"id": "ip:1.2.3.4"}]},
        headers=JSON_HEADERS,
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True
    assert result.get_summary()["assessment"] == "Suspected to be malicious"
    assert result.get_summary()["riskscore"] == 85


def test_threat_assessment_not_malicious(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "threat assessment",
        "identifier": "threat_assessment",
        "config": {},
        "parameters": [{"threat_context": "malware", "ip": "8.8.8.8"}],
        "environment_variables": {},
    }

    requests_mock.post(
        f"{BASE_URL}/lookup/triage/malware?&format=phantom",
        json={"verdict": False, "triage_riskscore": 5, "entities": [{"id": "ip:8.8.8.8"}]},
        headers=JSON_HEADERS,
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True
    assert result.get_summary()["assessment"] == "Not found to be malicious"


def test_entity_search_success(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "entity search",
        "identifier": "entity_search",
        "config": {},
        "parameters": [{"name": "Lazarus", "entity_type": "ThreatActor", "limit": 5}],
        "environment_variables": {},
    }

    requests_mock.post(
        f"{BASE_URL}/entity/search",
        json={"data": [{"id": "ta:Lazarus", "name": "Lazarus Group"}]},
        headers=JSON_HEADERS,
        additional_matcher=lambda req: req.json() == {"name": "Lazarus", "type": "ThreatActor", "limit": 5},
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True


def test_entity_search_api_error(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "entity search",
        "identifier": "entity_search",
        "config": {},
        "parameters": [{"name": "Lazarus"}],
        "environment_variables": {},
    }

    requests_mock.post(f"{BASE_URL}/entity/search", status_code=500, json={"message": "Server Error"})

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is False


def test_links_search_success(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "links search",
        "identifier": "links_search",
        "config": {},
        "parameters": [{"entity_id": "ip:1.2.3.4", "timeframe": "-30d"}],
        "environment_variables": {},
    }

    requests_mock.post(
        f"{BASE_URL}/links/search",
        json={"links": [{"source": "ip:1.2.3.4", "target": "malware:abc"}]},
        headers=JSON_HEADERS,
        additional_matcher=lambda req: req.json().get("entity_id") == "ip:1.2.3.4",
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True


def test_links_search_api_error(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "links search",
        "identifier": "links_search",
        "config": {},
        "parameters": [{"entity_id": "ip:1.2.3.4"}],
        "environment_variables": {},
    }

    requests_mock.post(f"{BASE_URL}/links/search", status_code=500, json={"message": "Server Error"})

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is False


def test_threat_map_success(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "threat map",
        "identifier": "threat_map",
        "config": {},
        "parameters": [{}],
        "environment_variables": {},
    }

    requests_mock.get(
        f"{BASE_URL}/threat/map",
        json={"actors": [{"id": "ta:Lazarus", "name": "Lazarus Group"}]},
        headers=JSON_HEADERS,
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True


def test_threat_actor_intelligence_success(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "threat actor intelligence",
        "identifier": "threat_actor_intelligence",
        "config": {},
        "parameters": [{"threat_actor": "Lazarus", "links": True}],
        "environment_variables": {},
    }

    requests_mock.post(
        f"{BASE_URL}/threat/map/actors",
        json={"actor": {"id": "ta:Lazarus", "name": "Lazarus Group"}, "links": []},
        headers=JSON_HEADERS,
        additional_matcher=lambda req: req.json() == {"threat_actor": "Lazarus", "links": True},
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True


def test_collective_insights_submit_success(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "collective insights submit",
        "identifier": "collective_insights_submit",
        "config": {},
        "parameters": [{"entity_name": "1.2.3.4", "entity_type": "ip", "event_type": "c2"}],
        "environment_variables": {},
    }

    requests_mock.post(
        f"{BASE_URL}/collective-insights/detections",
        json={"status": "accepted"},
        headers=JSON_HEADERS,
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True


def test_fetch_analyst_notes_success(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "fetch analyst notes",
        "identifier": "fetch_analyst_notes",
        "config": {},
        "parameters": [{"topic": "malware", "published": "-7d", "limit": 5}],
        "environment_variables": {},
    }

    mocked_notes = [
        {"id": "note1", "title": "Malware Analysis", "published": "2025-01-10"},
        {"id": "note2", "title": "Campaign Report", "published": "2025-01-09"},
    ]

    requests_mock.post(
        f"{BASE_URL}/analyst_note/fetch_notes",
        json=mocked_notes,
        headers=JSON_HEADERS,
        additional_matcher=lambda req: req.json().get("topic") == "malware" and req.json().get("limit") == 5,
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True
    assert result.get_summary()["total_notes"] == 2


def test_fetch_analyst_notes_api_error(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "fetch analyst notes",
        "identifier": "fetch_analyst_notes",
        "config": {},
        "parameters": [{"topic": "malware"}],
        "environment_variables": {},
    }

    requests_mock.post(f"{BASE_URL}/analyst_note/fetch_notes", status_code=500, json={"message": "Server Error"})

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is False
