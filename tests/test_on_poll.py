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
import unittest.mock as mock

import freezegun
import pytest
from pytest_splunk_soar_connectors.models import InputJSON

from recordedfuture_connector import RecordedfutureConnector


@freezegun.freeze_time("2025-06-16 12:05:01", tz_offset=0)
def test_on_poll_no_domains(rf_connector: RecordedfutureConnector):
    in_json: InputJSON = {
        "action": "on_poll",
        "identifier": "on_poll",
        "config": {},
        "parameters": [
            {
                "container_count": 5,
            }
        ],
        "environment_variables": {},
    }

    rf_connector._handle_action(json.dumps(in_json), None)

    rf_connector.save_container.assert_not_called()
    assert rf_connector.get_state() == {
        "last_leaked_credentials_fetch_time": "2025-06-16T12:05:01+00:00",
        "last_playbook_alerts_fetch_time": "2025-06-16T12:05:01",
    }
    rf_connector.save_progress.assert_has_calls(
        [
            mock.call("In action handler for: on_poll"),
            mock.call("Polling Leaked Credentials"),
            mock.call("No domains for leaked credentials have been specified for polling"),
            mock.call("Polling Playbook Alerts"),
            mock.call("No Playbook Alert Categories have been specified for polling"),
        ]
    )


def mk_match_payload(expected_payload: dict):
    def inner(request):
        return expected_payload == request.json()

    return inner


@freezegun.freeze_time("2025-06-16 12:05:01", tz_offset=0)
@pytest.mark.parametrize("consent_dict", [{}, {"leaked_creds_consent_given": False}])
def test_on_poll_leaked_creds_poll_now_no_container_count_no_detections_consent_not_given(
    consent_dict: dict, rf_connector: RecordedfutureConnector, requests_mock
):
    in_json: InputJSON = {
        "action": "on_poll",
        "identifier": "on_poll",
        "config": {},
        "parameters": [{}],
        "environment_variables": {},
    }
    rf_connector.config["on_poll_leaked_credentials_domains"] = "domain1,domain2"
    rf_connector.save_state(consent_dict)
    rf_connector.poll_now = True
    requests_mock.post(
        "http://localhost:8089/phantom/identity/on_poll",
        json={"detections": []},
        headers={"Content-Type": "application/json", "X-RFToken": "dummy_token"},
        additional_matcher=mk_match_payload({"filter": {"domains": ["domain1", "domain2"], "novel_only": None}, "limit": 100}),
    )
    requests_mock.post(
        "http://localhost:8089/phantom/identity/consent",
        status_code=204,
        headers={"Content-Type": "application/json", "X-RFToken": "dummy_token"},
        additional_matcher=mk_match_payload({"consent_given": True}),
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    rf_connector.save_container.assert_not_called()
    assert rf_connector.get_state() == {
        "last_leaked_credentials_fetch_time": "2025-06-16T12:05:01+00:00",
        "last_playbook_alerts_fetch_time": "2025-06-16T12:05:01",
        "leaked_creds_consent_given": True,
    }
    rf_connector.save_progress.assert_has_calls(
        [
            mock.call("In action handler for: on_poll"),
            mock.call("Polling Leaked Credentials"),
            mock.call("Polling Playbook Alerts"),
            mock.call("No Playbook Alert Categories have been specified for polling"),
        ]
    )


@freezegun.freeze_time("2025-06-16 12:05:01", tz_offset=0)
def test_on_poll_leaked_creds_poll_now_container_count_set_with_detections(rf_connector: RecordedfutureConnector, requests_mock):
    in_json: InputJSON = {
        "action": "on_poll",
        "identifier": "on_poll",
        "config": {},
        "parameters": [{"container_count": 5}],
        "environment_variables": {},
    }
    rf_connector.config["on_poll_leaked_credentials_domains"] = "domain1,domain2"
    rf_connector.config["on_poll_leaked_credentials_novel_only"] = True
    rf_connector.save_state({"leaked_creds_consent_given": True})
    rf_connector.poll_now = True
    requests_mock.post(
        "http://localhost:8089/phantom/identity/on_poll",
        json={"detections": [{"name": "container 1"}, {"name": "container 2"}]},
        headers={"Content-Type": "application/json", "X-RFToken": "dummy_token"},
        additional_matcher=mk_match_payload({"filter": {"domains": ["domain1", "domain2"], "novel_only": True}, "limit": 5}),
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    rf_connector.save_container.assert_has_calls(
        [
            mock.call({"name": "container 1"}),
            mock.call({"name": "container 2"}),
        ]
    )
    assert rf_connector.get_state() == {
        "last_leaked_credentials_fetch_time": "2025-06-16T12:05:01+00:00",
        "last_playbook_alerts_fetch_time": "2025-06-16T12:05:01",
        "leaked_creds_consent_given": True,
    }
    rf_connector.save_progress.assert_has_calls(
        [
            mock.call("In action handler for: on_poll"),
            mock.call("Polling Leaked Credentials"),
            mock.call("Polling Playbook Alerts"),
            mock.call("No Playbook Alert Categories have been specified for polling"),
        ]
    )


@freezegun.freeze_time("2025-06-16 12:05:01", tz_offset=0)
@pytest.mark.parametrize(
    "config,state,expected_payload",
    [
        (
            {"on_poll_leaked_credentials_domains": "domain1,domain2"},
            {"leaked_creds_consent_given": True},
            {"filter": {"created": {"gte": None}, "domains": ["domain1", "domain2"], "novel_only": None}, "limit": 100},
        ),
        (
            {
                "on_poll_leaked_credentials_domains": "domain1,domain2",
                "on_poll_leaked_credentials_novel_only": False,
                "on_poll_leaked_credentials_created_after": "2025-06-15T13:05:01+01:00",
                "first_max_count": 123,
            },
            {"first_run": True, "leaked_creds_consent_given": True},
            {"filter": {"created": {"gte": "2025-06-15T13:05:01+01:00"}, "domains": ["domain1", "domain2"], "novel_only": False}, "limit": 123},
        ),
    ],
)
def test_on_poll_leaked_creds_first_run_with_detections(
    config: dict, state: dict, expected_payload: dict, rf_connector: RecordedfutureConnector, requests_mock
):
    in_json: InputJSON = {
        "action": "on_poll",
        "identifier": "on_poll",
        "config": {},
        "parameters": [{"container_count": 5}],
        "environment_variables": {},
    }
    for key, value in config.items():
        rf_connector.config[key] = value

    rf_connector.save_state(state)
    conn_state_copy = state.copy()
    requests_mock.post(
        "http://localhost:8089/phantom/identity/on_poll",
        json={"detections": [{"name": "container 1"}, {"name": "container 2"}]},
        headers={"Content-Type": "application/json", "X-RFToken": "dummy_token"},
        additional_matcher=mk_match_payload(expected_payload),
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    rf_connector.save_container.assert_has_calls(
        [
            mock.call({"name": "container 1"}),
            mock.call({"name": "container 2"}),
        ]
    )
    conn_state_copy["last_leaked_credentials_fetch_time"] = "2025-06-16T12:05:01+00:00"
    conn_state_copy["last_playbook_alerts_fetch_time"] = "2025-06-16T12:05:01"
    conn_state_copy["first_run"] = False
    assert rf_connector.get_state() == conn_state_copy
    rf_connector.save_progress.assert_has_calls(
        [
            mock.call("In action handler for: on_poll"),
            mock.call("Polling Leaked Credentials"),
            mock.call("First time Ingestion detected."),
            mock.call("Polling Playbook Alerts"),
            mock.call("No Playbook Alert Categories have been specified for polling"),
        ]
    )


@freezegun.freeze_time("2025-06-16 12:05:01", tz_offset=0)
@pytest.mark.parametrize(
    "config,state,expected_payload",
    [
        (
            {"on_poll_leaked_credentials_domains": "domain1,domain2"},
            {"first_run": False, "leaked_creds_consent_given": True},
            {"filter": {"created": {"gte": None}, "domains": ["domain1", "domain2"], "novel_only": None}, "limit": 100},
        ),
        (
            {
                "on_poll_leaked_credentials_domains": "domain1,domain2",
                "on_poll_leaked_credentials_novel_only": True,
                "on_poll_leaked_credentials_created_after": "2025-06-15T13:05:01+01:00",
                "max_count": 234,
            },
            {"first_run": False, "last_leaked_credentials_fetch_time": "2025-06-16T13:05:01+00:00", "leaked_creds_consent_given": True},
            {
                "filter": {
                    "created": {"gte": "2025-06-16T13:05:01+00:00"},
                    "domains": ["domain1", "domain2"],
                    "novel_only": True,
                },
                "limit": 234,
            },
        ),
        (
            {
                "on_poll_leaked_credentials_domains": "domain1,domain2",
                "on_poll_leaked_credentials_novel_only": False,
                "on_poll_leaked_credentials_created_after": "2025-06-15T13:05:01+01:00",
                "max_count": 234,
            },
            {"first_run": False, "leaked_creds_consent_given": True},
            {
                "filter": {
                    "created": {"gte": "2025-06-15T13:05:01+01:00"},
                    "domains": ["domain1", "domain2"],
                    "novel_only": False,
                },
                "limit": 234,
            },
        ),
    ],
)
def test_on_poll_leaked_creds_not_first_run_with_detections(
    config: dict, state: dict, expected_payload: dict, rf_connector: RecordedfutureConnector, requests_mock
):
    in_json: InputJSON = {
        "action": "on_poll",
        "identifier": "on_poll",
        "config": {},
        "parameters": [{"container_count": 5}],
        "environment_variables": {},
    }
    for key, value in config.items():
        rf_connector.config[key] = value

    rf_connector.save_state(state)
    conn_state_copy = state.copy()
    requests_mock.post(
        "http://localhost:8089/phantom/identity/on_poll",
        json={"detections": [{"name": "container 1"}, {"name": "container 2"}]},
        headers={"Content-Type": "application/json", "X-RFToken": "dummy_token"},
        additional_matcher=mk_match_payload(expected_payload),
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    rf_connector.save_container.assert_has_calls(
        [
            mock.call({"name": "container 1"}),
            mock.call({"name": "container 2"}),
        ]
    )
    conn_state_copy["last_leaked_credentials_fetch_time"] = "2025-06-16T12:05:01+00:00"
    conn_state_copy["last_playbook_alerts_fetch_time"] = "2025-06-16T12:05:01"
    conn_state_copy["first_run"] = False
    assert rf_connector.get_state() == conn_state_copy
    rf_connector.save_progress.assert_has_calls(
        [
            mock.call("In action handler for: on_poll"),
            mock.call("Polling Leaked Credentials"),
            mock.call("Polling Playbook Alerts"),
            mock.call("No Playbook Alert Categories have been specified for polling"),
        ]
    )
