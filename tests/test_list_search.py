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

from recordedfuture_view import list_search_results


BASE_URL = "http://localhost:8089/phantom"
JSON_HEADERS = {"Content-Type": "application/json"}


MOCKED_LIST_INFO = {
    "id": "abc123",
    "name": "My List",
    "type": "ip",
}

MOCKED_LIST_SEARCH_RESPONSE = [
    {"id": "abc123", "name": "My List", "type": "ip"},
    {"id": "def456", "name": "Another List", "type": "domain"},
]


def test_list_search_by_list_id(rf_connector, requests_mock):
    """When list_id is provided, should GET /list/{list_id}/info."""
    in_json: InputJSON = {
        "action": "list search",
        "identifier": "list_search",
        "config": {},
        "parameters": [{"list_id": "abc123"}],
        "environment_variables": {},
    }

    requests_mock.get(
        f"{BASE_URL}/list/abc123/info",
        json=MOCKED_LIST_INFO,
        headers=JSON_HEADERS,
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True
    assert requests_mock.last_request.method == "GET"


def test_list_search_by_name(rf_connector, requests_mock):
    """When list_name is provided (no list_id), should POST /list/search with name filter."""
    in_json: InputJSON = {
        "action": "list search",
        "identifier": "list_search",
        "config": {},
        "parameters": [{"list_name": "My List", "limit": 10}],
        "environment_variables": {},
    }

    expected_payload = {"limit": 10, "name": "My List"}

    requests_mock.post(
        f"{BASE_URL}/list/search",
        json=MOCKED_LIST_SEARCH_RESPONSE,
        headers=JSON_HEADERS,
        additional_matcher=lambda req: req.json() == expected_payload,
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True


def test_list_search_by_entity_types(rf_connector, requests_mock):
    """When entity_types is provided (no list_id), should POST /list/search with type filter."""
    in_json: InputJSON = {
        "action": "list search",
        "identifier": "list_search",
        "config": {},
        "parameters": [{"entity_types": "ip", "limit": 5}],
        "environment_variables": {},
    }

    expected_payload = {"limit": 5, "type": "ip"}

    requests_mock.post(
        f"{BASE_URL}/list/search",
        json=MOCKED_LIST_SEARCH_RESPONSE,
        headers=JSON_HEADERS,
        additional_matcher=lambda req: req.json() == expected_payload,
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True


def test_list_search_no_filters_uses_default_limit(rf_connector, requests_mock):
    """When no filters provided, should POST /list/search with default limit of 25."""
    in_json: InputJSON = {
        "action": "list search",
        "identifier": "list_search",
        "config": {},
        "parameters": [{}],
        "environment_variables": {},
    }

    expected_payload = {"limit": 25}

    requests_mock.post(
        f"{BASE_URL}/list/search",
        json=MOCKED_LIST_SEARCH_RESPONSE,
        headers=JSON_HEADERS,
        additional_matcher=lambda req: req.json() == expected_payload,
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True


def test_list_search_by_list_id_api_error(rf_connector, requests_mock):
    """When list_id is provided but API returns error, action should fail."""
    in_json: InputJSON = {
        "action": "list search",
        "identifier": "list_search",
        "config": {},
        "parameters": [{"list_id": "nonexistent"}],
        "environment_variables": {},
    }

    requests_mock.get(
        f"{BASE_URL}/list/nonexistent/info",
        status_code=404,
        json={"message": "Not Found"},
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is False


def test_list_search_list_id_with_list_name_returns_error(rf_connector, requests_mock):
    """When both list_id and list_name are provided, action should fail with a validation error."""
    in_json: InputJSON = {
        "action": "list search",
        "identifier": "list_search",
        "config": {},
        "parameters": [{"list_id": "abc123", "list_name": "My List"}],
        "environment_variables": {},
    }

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is False
    assert requests_mock.call_count == 0


def test_list_search_list_id_with_entity_types_returns_error(rf_connector, requests_mock):
    """When both list_id and entity_types are provided, action should fail with a validation error."""
    in_json: InputJSON = {
        "action": "list search",
        "identifier": "list_search",
        "config": {},
        "parameters": [{"list_id": "abc123", "entity_types": "ip"}],
        "environment_variables": {},
    }

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is False
    assert requests_mock.call_count == 0


def test_list_details_deprecation_warning(rf_connector, requests_mock):
    """list details action should still work but emit a visible deprecation warning."""
    in_json: InputJSON = {
        "action": "list details",
        "identifier": "list_details",
        "config": {},
        "parameters": [{"list_id": "abc123"}],
        "environment_variables": {},
    }

    requests_mock.get(
        f"{BASE_URL}/list/abc123/info",
        json=MOCKED_LIST_INFO,
        headers=JSON_HEADERS,
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True
    rf_connector.save_progress.assert_any_call(
        "DEPRECATION WARNING: 'list details' action is deprecated and will be "
        "removed in a future release. Please use 'list search' with 'list_id' "
        "parameter instead."
    )


def test_list_search_view_renders_list_id_result(rf_connector, requests_mock):
    """RFPD-107086: searching by list_id returns a single object (GET /list/{id}/info),
    while the widget template iterates result.data. The view must normalize the single
    object into a list so the widget renders it instead of showing an empty table."""
    in_json: InputJSON = {
        "action": "list search",
        "identifier": "list_search",
        "config": {},
        "parameters": [{"list_id": "abc123"}],
        "environment_variables": {},
    }

    requests_mock.get(
        f"{BASE_URL}/list/abc123/info",
        json=MOCKED_LIST_INFO,
        headers=JSON_HEADERS,
    )

    rf_connector._handle_action(json.dumps(in_json), None)
    results = rf_connector.get_action_results()

    context = {}
    list_search_results(None, [(None, results)], context)

    rendered = context["results"][0]["data"]
    # Must be an iterable of list objects (not the raw dict) so the template's
    # `{% for el in result.data %}` yields data rows instead of dict keys.
    assert rendered == [MOCKED_LIST_INFO]
    assert rendered[0]["name"] == "My List"


def test_list_search_view_renders_name_search_result(rf_connector, requests_mock):
    """A name/type search returns an array (POST /list/search); the view must leave
    that array untouched so every matched list renders."""
    in_json: InputJSON = {
        "action": "list search",
        "identifier": "list_search",
        "config": {},
        "parameters": [{"list_name": "My List", "limit": 10}],
        "environment_variables": {},
    }

    requests_mock.post(
        f"{BASE_URL}/list/search",
        json=MOCKED_LIST_SEARCH_RESPONSE,
        headers=JSON_HEADERS,
    )

    rf_connector._handle_action(json.dumps(in_json), None)
    results = rf_connector.get_action_results()

    context = {}
    list_search_results(None, [(None, results)], context)

    rendered = context["results"][0]["data"]
    assert rendered == MOCKED_LIST_SEARCH_RESPONSE
    assert len(rendered) == 2
