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
from pathlib import Path

from pytest_splunk_soar_connectors.models import InputJSON

from recordedfuture_view import list_search_results


BASE_URL = "http://localhost:8089/phantom"
JSON_HEADERS = {"Content-Type": "application/json"}


MOCKED_LIST_INFO = {
    "id": "abc123",
    "name": "My List",
    "type": "ip",
}

MOCKED_LIST_INFO_WITH_OWNERSHIP = {
    "id": "report:Zza-KRu",
    "name": "Hackers",
    "type": "entity",
    "created": "2025-11-12T17:58:41.042Z",
    "updated": "2025-11-12T18:00:11.564Z",
    "owner_id": "uhash:thisisnotreal",
    "owner_name": "John Doe",
    "organisation_id": "uhash:thisorgisnotreal",
    "organisation_name": "Recorded Future",
    "owner_organisation_details": {
        "owner_id": "uhash:thisisnotreal",
        "owner_name": "John Doe",
        "organisations": [],
        "enterprise_id": "uhash:thisorgisnotreal",
        "enterprise_name": "Recorded Future",
    },
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


def test_list_search_by_list_id_preserves_all_response_fields(rf_connector, requests_mock):
    """The list-search action should preserve fields from the complete list-info response."""
    in_json: InputJSON = {
        "action": "list search",
        "identifier": "list_search",
        "config": {},
        "parameters": [{"list_id": MOCKED_LIST_INFO_WITH_OWNERSHIP["id"]}],
        "environment_variables": {},
    }
    requests_mock.get(
        f"{BASE_URL}/list/report%3AZza-KRu/info",
        json=MOCKED_LIST_INFO_WITH_OWNERSHIP,
        headers=JSON_HEADERS,
    )

    rf_connector._handle_action(json.dumps(in_json), None)

    result = rf_connector.get_action_results()[0]
    assert result.get_status() is True
    assert result.get_data() == [MOCKED_LIST_INFO_WITH_OWNERSHIP]


def test_list_search_output_schema_declares_all_scalar_response_fields():
    """The action output schema should expose all scalar fields from the list response."""
    manifest_path = Path(__file__).resolve().parents[1] / "recordedfuture.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    list_search_action = next(action for action in manifest["actions"] if action["identifier"] == "list_search")
    declared_paths = {field["data_path"] for field in list_search_action["output"]}
    expected_paths = {
        "action_result.data.*.id",
        "action_result.data.*.name",
        "action_result.data.*.type",
        "action_result.data.*.created",
        "action_result.data.*.updated",
        "action_result.data.*.owner_id",
        "action_result.data.*.owner_name",
        "action_result.data.*.organisation_id",
        "action_result.data.*.organisation_name",
    }

    assert expected_paths <= declared_paths


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


def test_list_search_by_list_id_url_encoding_matches_list_details(rf_connector, requests_mock):
    """A list_id containing ':' must be URL-encoded identically by list search and list details."""
    list_id = "report:Zaa-RuP"
    expected_url = f"{BASE_URL}/list/report%3AZaa-RuP/info"

    requests_mock.get(expected_url, json=MOCKED_LIST_INFO, headers=JSON_HEADERS)

    requested_urls = []
    for action_name, identifier in (("list search", "list_search"), ("list details", "list_details")):
        in_json: InputJSON = {
            "action": action_name,
            "identifier": identifier,
            "config": {},
            "parameters": [{"list_id": list_id}],
            "environment_variables": {},
        }
        rf_connector._handle_action(json.dumps(in_json), None)
        assert rf_connector.get_action_results()[-1].get_status() is True
        requested_urls.append(requests_mock.last_request.url)

    list_search_url, list_details_url = requested_urls
    assert list_search_url == expected_url
    assert list_search_url == list_details_url


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
