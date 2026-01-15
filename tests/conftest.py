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
import unittest.mock as mock

import pytest
from pytest_splunk_soar_connectors import configure_connector

from recordedfuture_connector import RecordedfutureConnector


# Load pytest-splunk-soar-connectors plugin
pytest_plugins = ["splunk-soar-connectors"]


@pytest.fixture(scope="function")
def rf_connector(monkeypatch):
    connector = configure_connector(
        RecordedfutureConnector, {"recordedfuture_base_url": "http://localhost:8089/phantom", "recordedfuture_api_token": "dummy_token"}
    )()

    # Mirroring the actual methods of the connector
    orig_save_container = connector.save_container
    orig_save_progress = connector.save_progress

    def mocked_save_container(*args, **kwargs):
        return orig_save_container(*args, **kwargs)

    def mocked_save_progress(*args, **kwargs):
        return orig_save_progress(*args, **kwargs)

    monkeypatch.setattr(connector, "save_container", mock.MagicMock(side_effect=mocked_save_container))
    monkeypatch.setattr(connector, "save_progress", mock.MagicMock(side_effect=mocked_save_progress))
    return connector
