# Copyright (c) 2025 Splunk Inc.
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


def test_identity_leaked_credentials_success(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "identity leaked credentials search",
        "identifier": "identity_leaked_credentials",
        "config": {},
        "parameters": [
            {
                "organization_id": "org1,org2",
                "domains": "example.com,example.org",
                "novel_only": True,
                "detection_type": "Workforce",
                "created_after": "2025-01-01T00:00:00Z",
                "created_before": "2025-02-01T00:00:00Z",
                "limit": 50,
            }
        ],
        "environment_variables": {},
    }

    expected_payload = {
        "organization_id": ["org1", "org2"],
        "include_enterprise_level": True,
        "filter": {
            "domains": ["example.com", "example.org"],
            "novel_only": True,
            "detection_type": "Workforce",
            "created": {
                "gte": "2025-01-01T00:00:00Z",
                "lt": "2025-02-01T00:00:00Z",
            },
        },
        "limit": 50,
    }

    mocked_response = {
        "detections": [
            {
                "id": "det_1",
                "organization_id": "org1",
                "subject": "user@example.com",
                "type": "Workforce",
                "novel": True,
                "created": "2025-01-15T12:00:00Z",
            }
        ]
    }

    requests_mock.post(
        "http://localhost:8089/phantom/identity/leaked-credentials",
        json=mocked_response,
        additional_matcher=lambda request: request.json() == expected_payload,
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    rf_connector.save_progress.assert_any_call("In action handler for: identity_leaked_credentials")


def test_identity_leaked_credentials_missing_domains(rf_connector):
    in_json: InputJSON = {
        "action": "identity leaked credentials search",
        "identifier": "identity_leaked_credentials",
        "config": {},
        "parameters": [
            {
                "organization_id": "org1",
                "domains": "",
            }
        ],
        "environment_variables": {},
    }

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]

    assert result.get_status() is False
    assert result.get_message() == "At least one domain must be provided"

    rf_connector.save_progress.assert_any_call("In action handler for: identity_leaked_credentials")


def test_identity_leaked_credentials_api_error(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "identity leaked credentials search",
        "identifier": "identity_leaked_credentials",
        "config": {},
        "parameters": [{"domains": "example.com"}],
        "environment_variables": {},
    }

    requests_mock.post("http://localhost:8089/phantom/identity/leaked-credentials", status_code=500, json={"message": "Internal Server Error"})

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]

    assert result.get_status() is False
    assert result.get_message() == "Error Connecting to server. Details: Error code: 500."

    rf_connector.save_progress.assert_any_call("In action handler for: identity_leaked_credentials")


def test_identity_leaked_credentials_invalid_detection_type(rf_connector, requests_mock):
    in_json: InputJSON = {
        "action": "identity leaked credentials search",
        "identifier": "identity_leaked_credentials",
        "config": {},
        "parameters": [
            {
                "domains": "example.com",
                "detection_type": "INVALID",  # Invalid enum
            }
        ],
        "environment_variables": {},
    }

    expected_payload = {
        "organization_id": None,
        "include_enterprise_level": True,
        "filter": {"domains": ["example.com"], "novel_only": True, "detection_type": "INVALID"},
        "limit": 100,
    }

    requests_mock.post(
        "http://localhost:8089/phantom/identity/leaked-credentials",
        status_code=400,
        json={"message": "Invalid detection_type"},
        additional_matcher=lambda req: req.json() == expected_payload,
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is False
    assert "Error Connecting to server" in result.get_message()
    assert "400" in result.get_message()
