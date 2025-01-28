# File: recordedfuture_connector.py
#
# Copyright (c) Recorded Future, Inc, 2019-2025
#
# This unpublished material is proprietary to Recorded Future. All
# rights reserved. The methods and techniques described herein are
# considered trade secrets and/or confidential. Reproduction or
# distribution, in whole or in part, is forbidden except by express
# written permission of Recorded Future.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Phantom App imports
import base64

# noinspection PyCompatibility
import ipaddress
import json

# Global imports
import os
import platform
import sys
import time
import uuid
from datetime import datetime
from html import escape
from math import ceil
from typing import Literal

# Phantom App imports
# noinspection PyUnresolvedReferences
import phantom.app as phantom

# noinspection PyUnresolvedReferences
import phantom.vault as vault
import requests

# noinspection PyUnresolvedReferences
from bs4 import BeautifulSoup, UnicodeDammit

# noinspection PyUnresolvedReferences
from phantom.action_result import ActionResult

# noinspection PyUnresolvedReferences
from phantom.base_connector import BaseConnector
from phantom_common import paths

# Usage of the consts file is recommended
from recordedfuture_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class RecordedfutureConnector(BaseConnector):
    """Implement a Connector towards Recorded Future's ConnectAPI."""

    def __init__(self):
        """Initialize."""
        # Call the BaseConnectors init first
        super().__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    @staticmethod
    def _process_empty_response(response, action_result):
        """Process an empty result."""
        if response.status_code == 200 or response.status_code == 204:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"),
            None,
        )

    @staticmethod
    def _process_html_response(response, action_result):
        """Process an HTML result."""
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except Exception as err:
            error_text = f"Cannot parse error details: {err}"

        error_text = UnicodeDammit(error_text).unicode_markup

        message = f"Please check the app configuration parameters. Status Code: {status_code}. Data from server:\n{error_text}\n"

        message = message.replace("{", "{{").replace("}", "}}")

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    @staticmethod
    def _create_empty_response(fields):
        """Create an empty response.

        This is typically used when the API return 404 (not found). Rather
        than to return this as an error an empty response is created.

        Depending on which fields were used (reputation/intelligence)
        the returned structure is more or less rich.
        """
        resp_json = {
            "data": {
                "entity": {"name": "", "type": None, "id": None},
                "timestamps": {"firstSeen": "never", "lastSeen": "never"},
                "risk": {
                    "criticalityLabel": None,
                    "rules": None,
                    "evidenceDetails": [],
                    "riskSummary": "No information available.",
                    "criticality": None,
                    "riskString": "",
                    "score": None,
                },
            }
        }
        if "intelCard" in fields:
            resp_json["data"]["intelCard"] = ""
        if "threatLists" in fields:
            resp_json["data"]["threatLists"] = []
        if "relatedEntities" in fields:
            resp_json["data"]["relatedEntities"] = []
        if "location" in fields:
            resp_json["data"]["location"] = {}
        if "metrics" in fields:
            resp_json["data"]["metrics"] = []
        return resp_json

    def _process_json_response(self, resp, action_result, **kwargs):
        """Process a JSON response."""
        # Try a json parse
        try:
            resp_json = resp.json()
        except Exception as err:
            error_code, error_message = self._get_error_message_from_exception(err)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    f"Unable to parse JSON response. Error code: {error_code}. Error message: {error_message}",
                ),
                None,
            )

        # Please specify the status codes here
        if 200 <= resp.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # If an IOC has no data in Recorded Future's API it returns 404.
        # While this is correct in REST semantics it's not what our app
        # needs. We will create an empty response instead.
        self.debug_print("_process_json_response kwargs: ", kwargs)
        if "fields" in kwargs.get("params", {}):
            fields = kwargs["params"]["fields"].split(",")
            self.debug_print("_process_json_response fields: ", fields)
            if resp.status_code == 404:
                resp_json = self._create_empty_response(fields)

                return RetVal(phantom.APP_SUCCESS, resp_json)

        msg = "No data found"

        if resp_json.get("message"):
            msg = resp_json.get("message")

        if resp_json.get("error").get("message"):
            if msg:
                msg = "{} and {}".format(msg, resp_json.get("error").get("message"))
            else:
                msg = resp_json.get("error").get("message")

        # You should process the error returned in the json
        message = f"Error from server. Status Code: {resp.status_code} Data from server: {UnicodeDammit(msg).unicode_markup}"

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, resp, action_result, **kwargs):
        """Process the response.

        The response handling is handled differently depending on whether
        it's text, HTML or JSON.
        """
        # store the r_text in debug data, it will get dumped in the logs if
        # the action fails
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": resp.status_code})
            action_result.add_debug_data({"r_text": resp.text})
            action_result.add_debug_data({"r_headers": resp.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if "json" in resp.headers.get("Content-Type", ""):
            return self._process_json_response(resp, action_result, **kwargs)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in resp.headers.get("Content-Type", ""):
            return self._process_html_response(resp, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not resp.text:
            return self._process_empty_response(resp, action_result)

        # everything else is actually an error at this point
        error_msg = UnicodeDammit(resp.text.replace("{", "{{").replace("}", "}}")).unicode_markup
        message = f"Can't process response from server. Status Code: {resp.status_code} Data from server: {error_msg}"

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _get_error_message_from_exception(self, e):
        """This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        error_code = "Error code unavailable"

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_msg = e.args[0]
            else:
                error_msg = "Unknown error occurred. Please check the asset configuration and|or action parameters."
        except Exception as err:
            error_msg = f"An error occurred. Cannot parse error details: {err}"

        try:
            error_msg = UnicodeDammit(error_msg).unicode_markup
        except TypeError:
            error_msg = "Error occurred while connecting to the server. Please check the asset configuration and|or the action parameters."
        except Exception as err:
            error_msg = f"An error occurred. Cannot parse error details: {err}"

        return error_code, error_msg

    def _make_rest_call(self, endpoint, action_result, params=None, method="get", **kwargs):
        """Make a REST call to Recorded Future's ConnectAPI.

        Parameters:
            endpoint:       the path_info (ex ip, alert/search)
            action_result:  the current action_result
            method:         whether to make a get or post call

        Keywords:
            fields:         the list of fields to fetch (see ConnectAPI docs)

        Return value:
            a RetVal:       see above.
        """
        # **kwargs can be any additional parameters that requests.request
        # accepts
        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, f"Invalid method: {method}"),
                resp_json,
            )

        # Create a URL to connect to
        base_url = UnicodeDammit(self._base_url).unicode_markup
        url = f"{base_url}{endpoint}"

        # Create a HTTP_USER_AGENT header
        # container_id is added to track actions associated with an event in
        # order to improve the app
        platform_id = f"Phantom_{self.get_product_version()}"

        pdict = dict(
            app_name=os.path.basename(__file__),
            container_id=self.get_container_id(),
            os_id=platform.platform(),
            pkg_name="phantom",
            pkg_version=version,
            requests_id=requests.__version__,
            platform_id=platform_id,
        )
        user_agent_tplt = "{app_name}/{container_id} ({os_id}) {pkg_name}/{pkg_version} python-requests/{requests_id} ({platform_id})"
        user_agent = user_agent_tplt.format(**pdict)
        # headers
        api_key = config.get("recordedfuture_api_token")
        my_headers = {"X-RFToken": api_key, "User-Agent": user_agent}

        # Ensure we log some useful data:
        # url:          shows if the url to ConnectAPI has been changed
        # kwargs:       shows fields and other keywords
        # fingerprint:  can be used to verify that the correct API key is used
        self.debug_print(f"_make_rest_call url: {url}")
        self.debug_print(f"_make_rest_call kwargs {kwargs}")

        # Make the call
        try:
            resp = request_func(
                url,
                headers=my_headers,
                verify=config.get("recordedfuture_verify_ssl", False),
                params=params,
                timeout=timeout,
                **kwargs,
            )
        except requests.exceptions.Timeout as e:
            self.error_print("Timeout Exception", dump_object=e)
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Timeout error when connecting to server"),
                resp_json,
            )
        except Exception as err:
            self.error_print("Request exception", dump_object=err)
            error_code, error_message = self._get_error_message_from_exception(err)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    f"Error Connecting to server. Error code:{error_code}. Error message:{error_message}",
                ),
                resp_json,
            )

        if resp.status_code in [200, 201]:
            return self._process_response(resp, action_result, **kwargs)

        elif resp.status_code == 401:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error Connecting to server. Details: Error code: 401 Unauthorised.",
                ),
                None,
            )
        elif resp.status_code == 403:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error Connecting to server. Details: Error code: 403 Forbidden.",
                ),
                None,
            )
        elif resp.status_code == 400:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error Connecting to server. Details: Error code: 400 Bad Request.",
                ),
                None,
            )
        elif resp.status_code == 404:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error Connecting to server. Details: Error code: 404 Not Found.",
                ),
                resp,
            )
        else:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    f"Error Connecting to server. Details: Error code: {resp.status_code}.",
                ),
                None,
            )

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent
        # the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # it will use the RF token to verify that it works in the second part
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        params = {"output-format": "application/json"}

        # make rest call - further info: https://docs.splunk.com/Documentation/Phantom/4.10/DevelopApps/Tutorial
        my_ret_val, response = self._make_rest_call("/helo", action_result, params=params)

        if phantom.is_fail(my_ret_val):
            self.save_progress("Connectivity test failed. API endpoint not reachable")
            return action_result.get_status()

        self.save_progress("Successful connection to the API")

        self.save_progress("Verifying Recorded Future API token")

        my_ret_val, response = self._make_rest_call("/config/info", action_result)

        # this is never run as we don't take care of a non-successful reply properly
        if phantom.is_fail(my_ret_val):
            self.save_progress("Test Credentials Failed")
            return action_result.get_status()

        # Return success
        self.save_progress("Token is accepted by the API")

        self.save_progress("Connectivity and credentials test passed. You may now close this window")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_intelligence(self, param, ioc, entity_type):
        """Return intelligence for an entity."""
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Params for the API call
        params = {"entity_type": entity_type, "ioc": ioc}

        # make rest call
        my_ret_val, response = self._make_rest_call("/lookup/intelligence", action_result, json=params, method="post")

        self.debug_print(
            "_handle_intelligence",
            {
                "path_info": ("%s/%s", entity_type, ioc),
                "action_result": action_result,
                "params": params,
                "my_ret_val": my_ret_val,
                "response": response,
            },
        )

        # Do not fail on 404. Give a message to user with success status.
        if phantom.is_fail(my_ret_val) and response.status_code == 404:
            action_result.set_status(
                phantom.APP_SUCCESS,
                status_message="Recorded Future does not have any information on this indicator.",
            )

        if phantom.is_fail(my_ret_val):
            return action_result.get_status()

        res = response.get("data", {})
        action_result.add_data(res)
        self.save_progress("Added data with keys {}", list(res.keys()))

        # Update the summary
        summary = action_result.get_summary()
        if "risk" in res:
            if "criticalityLabel" in res["risk"]:
                summary["criticalityLabel"] = res["risk"]["criticalityLabel"]
            if "riskSummary" in res["risk"]:
                summary["riskSummary"] = res["risk"]["riskSummary"]
        if res.get("timestamps", {}).get("lastSeen", ""):
            summary["lastSeen"] = res["timestamps"]["lastSeen"]

        action_result.set_summary(summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_reputation(self, param, category, entity):
        """Return reputation information."""
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Params for the API call
        params = {category: entity}

        # make rest call
        my_ret_val, response = self._make_rest_call("/lookup/reputation", action_result, json=params, method="post")

        self.debug_print(
            "_handle_reputation",
            {
                "path_info": entity,
                "endpoint": "/lookup/reputation",
                "action_result": action_result,
                "params": params,
                "my_ret_val": my_ret_val,
                "response": response,
            },
        )

        if phantom.is_fail(my_ret_val):
            return action_result.get_status()

        # the BFI returns a list of entities. In future we may add the capability for
        # to do a reputation lookup of more than one entity
        entity = response.pop(0)

        summary = action_result.get_summary()

        if entity.get("id", ""):
            summary["risk score"] = entity.get("riskscore", "")
            summary["risk summary"] = "{} rules triggered of {}".format(
                entity.get("rulecount", ""),
                entity.get("maxrules", ""),
            )
        else:
            summary = action_result.get_summary()
            summary["riskscore"] = "No information available."

        action_result.add_data(entity)
        action_result.set_summary(summary)
        self.save_progress("Added data with keys {}", list(entity.keys()))

        # Return success, no need to set the message, only the status BaseConnector
        # will create a textual message based off the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_actions(self, param, action: str):
        if action == "search":
            return self._handle_list_search(param)
        if action == "details":
            return self._handle_list_details(param, info_type="info")
        if action == "entities":
            return self._handle_list_details(param, info_type="entities")
        if action == "status":
            return self._handle_list_details(param, info_type="status")
        if action == "create":
            return self._handle_list_create(param)
        if action == "add-entity":
            return self._handle_manage_list_entities(param, action="add")
        if action == "remove-entity":
            return self._handle_manage_list_entities(param, action="remove")

    def _get_list_action_result(self, action_result, my_ret_val, response_obj):
        if phantom.is_fail(my_ret_val):
            return action_result.get_status()

        summary = action_result.get_summary()
        action_result.add_data(response_obj)
        action_result.set_summary(summary)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_search(self, param):
        """Find lists"""
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(param))
        params = {"limit": param.get("limit", 25)}
        entity_types = param.get("entity_types", "")
        list_name = param.get("list_name", "")
        if entity_types:
            params["type"] = UnicodeDammit(escape(entity_types)).unicode_markup
        if list_name:
            params["name"] = UnicodeDammit(escape(list_name)).unicode_markup

        my_ret_val, response = self._make_rest_call("/list/search", action_result, json=params, method="post")

        self.debug_print(
            "_handle_list_search",
            {
                "endpoint": "/list/search",
                "action_result": action_result,
                "param": param,
                "params": params,
                "my_ret_val": my_ret_val,
                "response": response,
            },
        )

        return self._get_list_action_result(
            action_result=action_result,
            my_ret_val=my_ret_val,
            response_obj=response,
        )

    def _handle_list_create(self, param):
        """Create new list"""
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(param))
        params = {
            "name": UnicodeDammit(param["list_name"]).unicode_markup,
            "type": UnicodeDammit(param["entity_types"]).unicode_markup,
        }
        my_ret_val, response = self._make_rest_call("/list/create", action_result, json=params, method="post")
        self.debug_print(
            "_handle_list_create",
            {
                "endpoint": "/list/create",
                "action_result": action_result,
                "params": params,
                "my_ret_val": my_ret_val,
                "response": response,
            },
        )
        return self._get_list_action_result(
            action_result=action_result,
            my_ret_val=my_ret_val,
            response_obj=response,
        )

    def _handle_list_details(self, param, info_type: Literal["info", "status", "entities"]):
        """Get list details"""
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(param))
        list_id = UnicodeDammit(param["list_id"]).unicode_markup
        my_ret_val, response = self._make_rest_call(f"/list/{list_id}/{info_type}", action_result, method="get")
        self.debug_print(
            "_handle_list_details",
            {
                "endpoint": f"/list/{list_id}/{info_type}",
                "action_result": action_result,
                "my_ret_val": my_ret_val,
                "response": response,
            },
        )
        return self._get_list_action_result(action_result=action_result, my_ret_val=my_ret_val, response_obj=response)

    def _handle_manage_list_entities(self, param, action: Literal["add", "remove"]):
        """Add/remove entity to list"""
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(param))
        list_id = UnicodeDammit(param["list_id"]).unicode_markup
        entity_id = param.get("entity_id")
        entity_name = param.get("entity_name")
        entity_type = param.get("entity_type")

        data = {
            "name": (UnicodeDammit(escape(entity_name)).unicode_markup if entity_name else None),
            "type": (UnicodeDammit(escape(entity_type)).unicode_markup if entity_type else None),
            "id": (UnicodeDammit(escape(entity_id)).unicode_markup if entity_id else None),
        }
        my_ret_val, response = self._make_rest_call(f"/list/{list_id}/entity/{action}", action_result, json=data, method="post")
        self.debug_print(
            "_handle_manage_list_entities",
            {
                "endpoint": f"/list/{list_id}/entity/{action}",
                "action_result": action_result,
                "my_ret_val": my_ret_val,
                "response": response,
                "data": data,
            },
        )
        return self._get_list_action_result(
            action_result=action_result,
            my_ret_val=my_ret_val,
            response_obj=response,
        )

    def _handle_triage(self, param):
        """Return triage information."""
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Params for the API call
        param_types = ["ip", "domain", "url", "hash"]
        params = {}
        for i in param.keys():
            if i in param_types:
                params[i] = [UnicodeDammit(entry.strip()).unicode_markup for entry in param.get(i).split(",") if entry != "None"]

        self.save_progress(f"Params found to triage: {params}")

        # make rest call
        my_ret_val, response = self._make_rest_call(
            "/lookup/triage/{}?{}".format(
                UnicodeDammit(param["threat_context"]).unicode_markup,
                "&format=phantom",
            ),
            action_result,
            json=params,
            method="post",
        )

        self.debug_print(
            "_handle_triage",
            {
                "path_info": "triage",
                "endpoint": "/lookup/triage",
                "action_result": action_result,
                "params": params,
                "my_ret_val": my_ret_val,
                "response": response,
            },
        )

        self.save_progress("Obtained API response")

        if phantom.is_fail(my_ret_val):
            return action_result.get_status()

        # there will always be a response with data, how best represent this?
        summary = action_result.get_summary()
        if response.get("verdict", ""):
            summary["assessment"] = "Suspected to be malicious"
            summary["riskscore"] = response.get("triage_riskscore", "")
        elif not response.get("entities", []):
            summary["assessment"] = "No information available"
        else:
            summary["assessment"] = "Not found to be malicious"
            summary["riskscore"] = response.get("triage_riskscore", "")

        action_result.add_data(response)
        action_result.set_summary(summary)
        self.save_progress("Added data with keys {}", response.keys())

        # Return success, no need to set the message, only the status BaseConnector
        # will create a textual message based off the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_contexts(self, param):
        """List available contexts"""

        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # make rest call
        my_ret_val, response = self._make_rest_call("/config/triage/contexts", action_result)

        self.debug_print(
            "_handle_list_contexts",
            {
                "action_result": action_result,
                "my_ret_val": my_ret_val,
                "response": response,
            },
        )

        if phantom.is_fail(my_ret_val):
            self.save_progress("API call to retrieve triage contexts failed.")
            return action_result.get_status()

        if response:
            self.save_progress("Added data with keys {}", list(response.keys()))

            summary = action_result.get_summary()
            summary_statement = ""
            for triage_context in list(response.keys()):
                # Assemble summary
                if summary_statement == "":
                    summary_statement = triage_context
                else:
                    summary_statement = summary_statement + ", " + triage_context

                action_result.add_data(
                    {
                        "context": triage_context,
                        "name": response[triage_context].get("name"),
                        "datagroup": response[triage_context].get("datagroup"),
                    }
                )

            summary["contexts_available_for_threat_assessment"] = summary_statement

        else:
            self.save_progress("API call failed to retrieve any information.")
            summary = "API call to retrieve triage contexts failed"

        action_result.set_summary(summary)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary
        # dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _write_file_to_vault(self, container, file_data, file_name):
        if hasattr(vault.Vault, "get_vault_tmp_dir"):
            file_path = os.path.join(vault.Vault.get_vault_tmp_dir(), file_name)
        else:
            file_path = os.path.join(os.path.join(paths.PHANTOM_VAULT, "/tmp"), file_name)

        with open(file_path, "wb") as file:
            file.write(file_data)
            _, message, _ = vault.vault_add(
                container=container,
                file_location=file_path,
                file_name=file_name,
                metadata=None,
                trace=True,
            )
        self.debug_print(f"Add file - {message} - {container}")

    def _add_screenshots_to_container(self, container, screenshots):
        for screenshot in screenshots:
            file_name = f"{uuid.uuid4()}.png"
            file_data = base64.b64decode(screenshot)
            self._write_file_to_vault(container, file_data, file_name)

    def _on_poll_playbook_alerts(self, param, config, action_result):
        """Polling for triggered playbook alerts"""
        params = {}
        # Return early if no playbook alert categories are specified.
        if not config.get("on_poll_playbook_alert_type"):
            self.save_progress("No Playbook Alert Categories have been specified for polling")
            return []

        if self.is_poll_now():
            param["max_count"] = param.get("container_count", MAX_CONTAINERS)
            params["from_date"] = None
        else:
            # Different number of max containers if first run
            if self._state.get("first_run", True):
                # set the config to _not_ first run hereafter
                self._state["first_run"] = False
                param["max_count"] = config.get("first_max_count", MAX_CONTAINERS)
                self.save_progress("First time Ingestion detected.")
                params["from_date"] = config.get("on_poll_playbook_alert_start_time")
            else:
                param["max_count"] = config.get("max_count", MAX_CONTAINERS)
                # For all the runs after tge first one we get alerts filtered by update_data instead of create_date.
                params["last_updated_date"] = self._state.get("last_playbook_alerts_fetch_time") or config.get(
                    "on_poll_playbook_alert_start_time"
                )

        # Asset Settings in Asset Configuration allows a negative number
        if int(param["max_count"]) <= 0:
            param["max_count"] = MAX_CONTAINERS

        # Prepare the REST call to get all alerts within the timeframe and with status New
        params["state"] = self._state
        params["limit"] = param.get("max_count", 100)
        params["categories"] = [el.strip() for el in config.get("on_poll_playbook_alert_type", "").split(",") if el.strip()]
        params["statuses"] = [el.strip() for el in config.get("on_poll_playbook_alert_status", "").split(",") if el.strip()]
        params["priorities"] = (
            [el.strip() for el in config["on_poll_playbook_alert_priority"].split(",")]
            if config.get("on_poll_playbook_alert_priority")
            else None
        )

        # Make the rest call
        my_ret_val, containers = self._make_rest_call(
            "/playbook_alert/on_poll",
            action_result,
            json=params,
            method="post",
        )
        # Something went wrong
        if phantom.is_fail(my_ret_val):
            return action_result.get_status()

        return containers

    def _on_poll(self, param):
        """Entry point for obtaining alerts and rules."""
        # new containers and artifacts will be stored in containers[]
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))
        config = self.get_config()

        self.save_progress("Polling Playbook Alerts")
        containers = self._on_poll_playbook_alerts(param, config, action_result)
        try:
            for container in containers:
                screenshots = container.pop("images", [])
                ret_val, msg, cid = self.save_container(container)
                self._add_screenshots_to_container(cid, screenshots)
                if phantom.is_fail(ret_val):
                    self.save_progress(f"Error saving containers: {msg}")
                    self.error_print(f"Error saving containers: {msg} -- CID: {cid}")
                    return action_result.set_status(phantom.APP_ERROR, "Error while trying to add the containers")
        except TypeError:
            if not containers:
                self.save_progress("Error in API request, please see spawn.log for more details")
            else:
                self.save_progress("API response provided no new playbook alert containers to ingest")

        action_result.set_status(phantom.APP_SUCCESS)
        self._state["last_playbook_alerts_fetch_time"] = datetime.now().isoformat()

        if not config.get("on_poll_alert_ruleids"):
            return action_result.get_status()

        self.save_progress("Polling Alerts")
        containers = self._on_poll_alerts(param, config, action_result)
        try:
            for container in containers:
                ret_val, msg, cid = self.save_container(container)

                if phantom.is_fail(ret_val):
                    self.save_progress(f"Error saving containers: {msg}")
                    self.debug_print(f"Error saving containers: {msg} -- CID: {cid}")
                    return action_result.set_status(phantom.APP_ERROR, "Error while trying to add the containers")

                # Always update the alerts with new status to ensure that they are not left in limbo
                # description has string in the format -> "Container created from alert {alert_id}"
                # we get alert_id from it.
                params = [{"id": container["description"].split(" ")[4], "status": "Pending"}]
                my_ret_val, response = self._make_rest_call("/alert/update", action_result, json=params, method="post")

                # Something went wrong
                if phantom.is_fail(my_ret_val):
                    return action_result.get_status()
        except TypeError:
            if not containers:
                self.save_progress("Error in API request, please see spawn.log for more details")
            else:
                self.save_progress("API response provided no new playbook alert containers to ingest")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _on_poll_alerts(self, param, config, action_result):
        """Polling for triggered alerts given a list of rule IDs."""
        start_time = time.time()
        rollback_start_time = start_time
        if "start_time" in self._state:
            rollback_start_time = self._state["start_time"]

        # obtain the list of rule ids to use to obtain alerts
        list_of_rules = config.get("on_poll_alert_ruleids")
        if not list_of_rules:
            self.save_progress("No Alert Rule IDs have been specified for polling")
            return action_result.set_status(phantom.APP_ERROR)
        rule_list = [x.strip() for x in list_of_rules.split(",")]

        if self.is_poll_now():
            param["max_count"] = param.get("container_count", MAX_CONTAINERS)
            timeframe = ""
        else:
            # Different number of max containers if first run
            if self._state.get("first_run", True):
                # set the config to _not_ first run hereafter
                self._state["first_run"] = False
                self._state["start_time"] = start_time
                param["max_count"] = config.get("first_max_count", MAX_CONTAINERS)
                self.save_progress("First time Ingestion detected.")
                timeframe = ""
            else:
                param["max_count"] = config.get("max_count", MAX_CONTAINERS)
                # calculate time since last fetch
                interval = ceil((start_time - self._state.get("start_time", start_time)) / 3600) + 3
                self._state["start_time"] = start_time
                timeframe = f"-{interval}h to now"

        # Asset Settings in Asset Configuration allows a negative number
        if int(param["max_count"]) <= 0:
            param["max_count"] = MAX_CONTAINERS

        # Prepare the REST call to get all alerts within the timeframe and with status New
        params = {
            "triggered": timeframe,
            "rules": rule_list,
            "severity": config.get("on_poll_alert_severity"),
            "limit": param.get("max_count", 100),
            "limited_entity_scope": config.get("on_poll_alert_full_alert") != "All entities",
        }
        params["status"] = [el.strip() for el in config.get("on_poll_alert_status", "").split(",") if el.strip()]

        # Make the rest call
        my_ret_val, containers = self._make_rest_call(
            "/alert/on_poll",
            action_result,
            json=params,
            method="post",
        )

        # Something went wrong
        if phantom.is_fail(my_ret_val):
            status = action_result.get_status()
            # make sure to revert to the old start time,
            # so that next iteration will try again with a longer interval.
            self._state["start_time"] = rollback_start_time
            return status

        # sort the containers to get the oldest first
        containers.sort(key=lambda k: k["triggered"], reverse=False)

        # if necessary truncate the list of containers TODO need to fix other issue first
        # if len(containers) > param['max_count'] + 1:
        #     containers = containers[0:param['max_count'] + 1]

        return containers

    def _handle_alert_search(self, param):
        """Implement lookup of alerts issued for an alert rule."""
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent
        # the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        rule_id = UnicodeDammit(param["rule_id"]).unicode_markup
        timeframe = UnicodeDammit(param["timeframe"]).unicode_markup
        assert rule_id is not None
        assert timeframe is not None

        # Prepare the REST call
        params = {"triggered": timeframe}

        # Make rest call
        my_ret_val, response = self._make_rest_call(f"/alert/rule/{rule_id}", action_result, params=params)

        self.debug_print(
            "_handle_alert_search",
            {
                "path_info": f"/alert/rule/{rule_id}",
                "action_result": action_result,
                "params": params,
                "my_ret_val": my_ret_val,
                "response": response,
            },
        )

        # Something went wrong
        if phantom.is_fail(my_ret_val):
            return action_result.get_status()

        # Setup summary
        summary = action_result.get_summary()
        summary["total_number_of_alerts"] = response["counts"].get("total", 0)
        summary["alerts_returned"] = response["counts"].get("returned", 0)

        # No results can be non existing rule id or just that, no results...
        if response["counts"]["total"] == 0:
            action_result.set_summary(summary)
            return action_result.set_status(
                phantom.APP_SUCCESS,
                f'No alerts triggered from rule {rule_id} within timerange "{timeframe}"',
            )

        # Add info about the rule to summary and action_result['data']
        summary["rule_name"] = response["data"]["results"][0]["rule"]["name"]
        summary["rule_id"] = response["data"]["results"][0]["rule"]["id"]
        action_result.set_summary(summary)

        # For each alert that match the rule id/timerange search details
        # are fetched and added.
        alerts = []
        for alert in response["data"]["results"]:
            self.save_progress(f"In alert loop: {alert}")
            url2 = "/alert/lookup/{}".format(alert["id"])
            ret_val2, response2 = self._make_rest_call(url2, action_result)
            self.debug_print(
                "_handle_alert_search",
                {
                    "path_info": url2,
                    "action_result": action_result,
                    "params": params,
                    "my_ret_val": ret_val2,
                    "response": response2,
                },
            )
            # Something went wrong
            if phantom.is_fail(ret_val2):
                return action_result.get_status()

            # Add the response into the data section
            alerts.append(response2)
            self.save_progress('Alert: "{}" triggered "{}"'.format(response2["title"], response2["triggered"]))

        action_result.add_data({"rule": response["data"]["results"][0]["rule"], "alerts": alerts})

        # Return success, no need to set the message, only the status
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_alert_lookup(self, param):
        """Implement lookup of alerts issued for an alert rule."""
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent
        # the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        alert_id = UnicodeDammit(param["alert_id"]).unicode_markup

        # Make rest call
        my_ret_val, response = self._make_rest_call(f"/alert/lookup/{alert_id}", action_result)

        self.debug_print(
            "_handle_alert_lookup",
            {
                "path_info": f"/alert/lookup/{alert_id}",
                "action_result": action_result,
                "my_ret_val": my_ret_val,
                "response": response,
            },
        )

        # Something went wrong
        if phantom.is_fail(my_ret_val):
            return action_result.get_status()

        # Setup summary
        action_result.add_data(response)
        summary = action_result.get_summary()

        # Add info about the rule to summary and action_result['data'] TODO format date
        summary["alert_title"] = response.get("title", "")
        summary["triggered"] = response.get("triggered", "")
        action_result.set_summary(summary)

        # Return success, no need to set the message, only the status
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_alert_update(self, param):
        """Implement lookup of alerts issued for an alert rule."""

        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent
        # the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = [
            {
                "id": UnicodeDammit(param.get("alert_id", "")).unicode_markup,
                "status": UnicodeDammit(param.get("alert_status", "")).unicode_markup,
                "note": UnicodeDammit(param.get("alert_note", "")).unicode_markup,
            }
        ]

        # Make rest call
        my_ret_val, response = self._make_rest_call("/alert/update", action_result, json=params, method="post")

        self.debug_print(
            "_handle_alert_update",
            {
                "path_info": "alert/update",
                "action_result": action_result,
                "params": params,
                "my_ret_val": my_ret_val,
                "response": response,
            },
        )

        # Something went wrong
        if phantom.is_fail(my_ret_val):
            return action_result.get_status()

        # Setup response including summary
        res = response.get("success", "")
        action_result.add_data(res[0])
        summary = action_result.get_summary()

        if response.get("success", ""):
            summary["update"] = "Successful"
        else:
            summary["update"] = "Not successful"
            summary["reason"] = response["error"].get("reason", "")
        action_result.set_summary(summary)

        # Return success, no need to set the message, only the status
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_alert_rule_search(self, param):
        """Make a freetext search for alert rules."""
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent
        # the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("DEBUG: started fetching rules")

        # Prepare the REST call
        if not UnicodeDammit(param.get("rule_search", "")).unicode_markup:
            params = {"limit": 100}
        else:
            params = {
                "freetext": UnicodeDammit(param.get("rule_search", "")).unicode_markup,
                "limit": 100,
            }

        # make rest call
        my_ret_val, response = self._make_rest_call("/config/alert/rules", action_result, params=params)

        self.debug_print(
            "_handle_alert_rule_search",
            {
                "path_info": "config/alert/rules",
                "action_result": action_result,
                "params": params,
                "my_ret_val": my_ret_val,
                "response": response,
            },
        )

        # Handle failure
        if phantom.is_fail(my_ret_val):
            return action_result.get_status()

        # Now post process the data
        rule_ids = []
        for result in response["data"]["results"]:
            action_result.add_data({"id": result["id"], "name": result["title"]})
            rule_ids.append(result["id"])

        # Summary
        summary = action_result.get_summary()
        summary["rules_returned"] = response["counts"]["returned"]
        summary["total_number_of_rules"] = response["counts"]["total"]
        summary["rule_id_list"] = ",".join(rule_ids)
        action_result.set_summary(summary)

        # Return success, no need to set the message, only the status
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_playbook_alerts_search(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent
        # the action for this param
        action_result = self.add_action_result(ActionResult(param))
        params = {
            "categories": ([category.strip() for category in param["category"].split(",")] if "category" in param else None),
            "statuses": ([RF_PLAYBOOK_STATUS_MAP.get(param["status"])] if "status" in param else None),
            "priorities": ([UnicodeDammit(param["priority"]).unicode_markup] if "priority" in param else None),
            "limit": param.get("limit", 100),
            "from_date": UnicodeDammit(param.get("from_date", "")).unicode_markup,
            "last_updated_date": UnicodeDammit(param.get("last_updated_date", "")).unicode_markup,
        }
        params = {key: value for key, value in params.items() if value}
        # make rest call
        my_ret_val, response = self._make_rest_call("/playbook_alert/search", action_result, json=params, method="post")

        self.debug_print(
            "_handle_playbook_alert_search",
            {
                "path_info": "/playbook_alert/search",
                "action_result": action_result,
                "params": params,
                "my_ret_val": my_ret_val,
                "response": response,
            },
        )

        # Handle failure
        if phantom.is_fail(my_ret_val):
            return action_result.get_status()

        # Summary
        summary = action_result.get_summary()
        action_result.add_data(response)
        action_result.set_summary(summary)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_playbook_alert_details(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent
        # the action for this param
        action_result = self.add_action_result(ActionResult(param))

        # make rest call
        my_ret_val, response = self._make_rest_call(
            f"/playbook_alert/{param['alert_id']}",
            action_result,
        )

        self.debug_print(
            "_handle_playbook_alert_details",
            {
                "path_info": f"/playbook_alert/domain_abuse/{param['alert_id']}",
                "action_result": action_result,
                "my_ret_val": my_ret_val,
                "response": response,
            },
        )

        # Handle failure
        if phantom.is_fail(my_ret_val):
            return action_result.get_status()

        # Summary
        summary = action_result.get_summary()
        action_result.add_data(response)
        action_result.set_summary(summary)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_playbook_alert_update(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent
        # the action for this param
        action_result = self.add_action_result(ActionResult(param))

        params = {
            "priority": UnicodeDammit(param.get("priority", "")).unicode_markup,
            "status": UnicodeDammit(RF_PLAYBOOK_STATUS_MAP.get(param.get("status"), "")).unicode_markup,
            "log_message": UnicodeDammit(param.get("log_message", "")).unicode_markup,
        }
        params = {key: value for key, value in params.items() if value}

        # make rest call
        my_ret_val, response = self._make_rest_call(
            f"/playbook_alert/{param['alert_id']}",
            json=params,
            action_result=action_result,
            method="put",
        )

        self.debug_print(
            "_handle_playbook_alert_update",
            {
                "path_info": f"/playbook_alert/{param['alert_id']}",
                "action_result": action_result,
                "my_ret_val": my_ret_val,
                "response": response,
            },
        )
        # Handle failure
        if phantom.is_fail(my_ret_val):
            return action_result.get_status()

        # Summary
        summary = action_result.get_summary()
        action_result.add_data(response)
        action_result.set_summary(summary)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_entities_search(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent
        # the action for this param
        action_result = self.add_action_result(ActionResult(param))
        params = {
            "name": UnicodeDammit(param["name"]).unicode_markup,
            "type": (UnicodeDammit(param["entity_type"]).unicode_markup if "entity_type" in param else None),
            "limit": param.get("limit", 10),
        }
        params = {key: value for key, value in params.items() if value}
        # make rest call
        my_ret_val, response = self._make_rest_call("/entity/search", action_result, json=params, method="post")

        self.debug_print(
            "_handle_entities_search",
            {
                "path_info": "/entity/search",
                "action_result": action_result,
                "params": params,
                "my_ret_val": my_ret_val,
                "response": response,
            },
        )

        # Handle failure
        if phantom.is_fail(my_ret_val):
            return action_result.get_status()

        # Summary
        summary = action_result.get_summary()
        action_result.add_data(response)
        action_result.set_summary(summary)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_links_search(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent
        # the action for this param
        action_result = self.add_action_result(ActionResult(param))
        params = {
            "entity_id": (UnicodeDammit(param["entity_id"]).unicode_markup if "entity_id" in param else None),
            "entity_name": (UnicodeDammit(param["entity_name"]).unicode_markup if "entity_name" in param else None),
            "entity_type": (UnicodeDammit(param["entity_type"]).unicode_markup if "entity_type" in param else None),
            "timeframe": (UnicodeDammit(param["timeframe"]).unicode_markup if "timeframe" in param else "-90d"),
            "technical_type": (UnicodeDammit(param["technical_type"]).unicode_markup if "technical_type" in param else None),
            "source_type": (UnicodeDammit(param["source_type"]).unicode_markup if "source_type" in param else None),
        }
        params = {key: value for key, value in params.items() if value}
        # make rest call
        my_ret_val, response = self._make_rest_call("/links/search", action_result, json=params, method="post")
        # Handle failure
        if phantom.is_fail(my_ret_val):
            return action_result.get_status()

        # Summary
        summary = action_result.get_summary()
        action_result.add_data(response)
        action_result.set_summary(summary)
        self.debug_print(
            "_handle_links_search",
            {
                "path_info": "/links/search",
                "action_result": action_result,
                "params": params,
                "my_ret_val": my_ret_val,
                "response": response,
            },
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_detection_rule_search(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent
        # the action for this param
        action_result = self.add_action_result(ActionResult(param))
        params = {
            "entity_id": (UnicodeDammit(param["entity_id"]).unicode_markup if "entity_id" in param else None),
            "entity_name": (UnicodeDammit(param["entity_name"]).unicode_markup if "entity_name" in param else None),
            "entity_type": (UnicodeDammit(param["entity_type"]).unicode_markup if "entity_type" in param else None),
            "rule_types": (UnicodeDammit(param["rule_types"]).unicode_markup if "rule_types" in param else None),
            "title": (UnicodeDammit(param["title"]).unicode_markup if "title" in param else None),
        }
        params = {key: value for key, value in params.items() if value}
        # make rest call
        my_ret_val, response = self._make_rest_call("/detection_rule/search", action_result, json=params, method="post")
        # Handle failure
        if phantom.is_fail(my_ret_val):
            return action_result.get_status()
        container_id = self.get_container_id()
        # Write rules to files.
        for detection_rule in response:
            for rule in detection_rule.get("rules"):
                file_name = rule["file_name"]
                file_content = rule["content"]
                if file_name and file_content:
                    file_content = file_content.encode()
                    self._write_file_to_vault(container_id, file_content, file_name)
        # Summary
        summary = action_result.get_summary()
        action_result.add_data(response)
        action_result.set_summary(summary)
        self.debug_print(
            "_handle_detection_rule_search",
            {
                "path_info": "/detection_rule/search",
                "action_result": action_result,
                "params": params,
                "my_ret_val": my_ret_val,
                "response": response,
            },
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_threat_actor_intelligence(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent
        # the action for this param
        action_result = self.add_action_result(ActionResult(param))
        params = {
            "threat_actor": UnicodeDammit(param["threat_actor"]).unicode_markup,
            "links": param["links"],
        }
        # make rest call
        my_ret_val, response = self._make_rest_call("/threat/map/actors", action_result, json=params, method="post")
        # Handle failure
        if phantom.is_fail(my_ret_val):
            return action_result.get_status()

        # Summary
        summary = action_result.get_summary()
        action_result.add_data(response)
        action_result.set_summary(summary)
        self.debug_print(
            "_handle_threat_actor_intelligence",
            {
                "path_info": "/threat/map/actors",
                "action_result": action_result,
                "params": params,
                "my_ret_val": my_ret_val,
                "response": response,
            },
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_threat_map(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent
        # the action for this param
        action_result = self.add_action_result(ActionResult(param))
        # make rest call
        my_ret_val, response = self._make_rest_call("/threat/map", action_result, method="get")
        # Handle failure
        if phantom.is_fail(my_ret_val):
            return action_result.get_status()

        # Summary
        summary = action_result.get_summary()
        action_result.add_data(response)
        action_result.set_summary(summary)
        self.debug_print(
            "_handle_threat_map",
            {
                "path_info": "/threat/map",
                "action_result": action_result,
                "my_ret_val": my_ret_val,
                "response": response,
            },
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_collective_insights_submission(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent
        # the action for this param
        action_result = self.add_action_result(ActionResult(param))
        params = {
            "entity_name": (UnicodeDammit(param["entity_name"]).unicode_markup if "entity_name" in param else None),
            "entity_type": (UnicodeDammit(param["entity_type"]).unicode_markup if "entity_type" in param else None),
            "entity_field": (UnicodeDammit(param["entity_field"]).unicode_markup if "entity_field" in param else None),
            "entity_source_type": (UnicodeDammit(param["entity_source_type"]).unicode_markup if "entity_source_type" in param else None),
            "event_id": (UnicodeDammit(param["event_id"]).unicode_markup if "event_id" in param else None),
            "event_name": (UnicodeDammit(param["event_name"]).unicode_markup if "event_name" in param else None),
            "event_type": (UnicodeDammit(param["event_type"]).unicode_markup if "event_type" in param else None),
            "mitre_codes": (UnicodeDammit(param["mitre_codes"]).unicode_markup if "mitre_codes" in param else None),
            "malware": (UnicodeDammit(param["malware"]).unicode_markup if "malware" in param else None),
            "timestamp": (UnicodeDammit(param["timestamp"]).unicode_markup if "timestamp" in param else None),
        }
        params = {key: value for key, value in params.items() if value}
        # make rest call
        my_ret_val, response = self._make_rest_call("/collective-insights/detections", action_result, json=params, method="post")
        # Handle failure
        if phantom.is_fail(my_ret_val):
            return action_result.get_status()

        # Summary
        summary = action_result.get_summary()
        action_result.add_data(response)
        action_result.set_summary(summary)
        self.debug_print(
            "_handle_collective_insights_submission",
            {
                "path_info": "/collective-insights/detections",
                "action_result": action_result,
                "my_ret_val": my_ret_val,
                "response": response,
            },
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        """Handle a call to the app, switch depending on action."""
        my_ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()
        self.debug_print(f"DEBUG: action_id = {action_id}")

        # Try to split on _ in order to handle reputation/intelligence and
        # ip/domain/file/vulnerability/url permutation.
        if len(action_id.split("_")) == 2:
            entity_type, operation_type = action_id.split("_")
        else:
            entity_type, operation_type = None, None
        self.debug_print(f"DEBUG: entity_type, operation_type = {entity_type}, {operation_type}")

        # Switch depending on action
        if action_id == "test_connectivity":
            my_ret_val = self._handle_test_connectivity(param)

        elif operation_type == "intelligence":
            omap = INTELLIGENCE_MAP
            path_info_tmplt, fields, tag, do_quote = omap[entity_type]
            param_tag = UnicodeDammit(param[tag]).unicode_markup
            my_ret_val = self._handle_intelligence(param, param_tag, entity_type)
        elif operation_type == "reputation":
            # phantom entity type file has to be changed to hash
            if entity_type == "file":
                tag = "hash"
            else:
                tag = entity_type
            param_tag = UnicodeDammit(param[tag]).unicode_markup
            my_ret_val = self._handle_reputation(param, tag, param_tag)

        elif action_id == "threat_assessment":
            # todo: need to check the in-parameters
            my_ret_val = self._handle_triage(param)

        elif action_id == "list_contexts":
            # todo: need to check the in-parameters
            my_ret_val = self._handle_list_contexts(param)

        elif action_id == "alert_rule_search":
            self.debug_print("DEBUG: started fetching rules")
            my_ret_val = self._handle_alert_rule_search(param)

        elif action_id == "alert_search":
            my_ret_val = self._handle_alert_search(param)

        elif action_id == "alert_lookup":
            my_ret_val = self._handle_alert_lookup(param)

        elif action_id == "alert_update":
            my_ret_val = self._handle_alert_update(param)

        elif action_id == "on_poll":
            my_ret_val = self._on_poll(param)

        elif entity_type == "list":
            my_ret_val = self._handle_list_actions(param, operation_type)

        elif action_id == "playbook_alerts_search":
            my_ret_val = self._handle_playbook_alerts_search(param)

        elif action_id == "update_playbook_alert":
            my_ret_val = self._handle_playbook_alert_update(param)

        elif action_id == "playbook_alert_details":
            my_ret_val = self._handle_playbook_alert_details(param)

        elif action_id == "entity_search":
            my_ret_val = self._handle_entities_search(param)

        elif action_id == "links_search":
            my_ret_val = self._handle_links_search(param)

        elif action_id == "detection_rule_search":
            my_ret_val = self._handle_detection_rule_search(param)

        elif action_id == "threat_actor_intelligence":
            my_ret_val = self._handle_threat_actor_intelligence(param)

        elif action_id == "threat_map":
            my_ret_val = self._handle_threat_map(param)

        elif action_id == "collective_insights_submit":
            my_ret_val = self._handle_collective_insights_submission(param)

        return my_ret_val

    def _is_ip(self, input_ip_address):
        """Function that checks given address and return True if address is valid IPv4 or IPV6 address.

        :param input_ip_address: IP address
        :return: status (success/failure)
        """

        ip_address_input = UnicodeDammit(input_ip_address).unicode_markup

        try:
            ipaddress.ip_address(ip_address_input)
        except ValueError:
            return False

        return True

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()
        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._state = {"app_version": self.get_app_json().get("app_version")}
            return self.set_status(phantom.APP_ERROR, RF_STATE_FILE_CORRUPT_ERROR)

        # get the asset config
        config = self.get_config()

        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = config.get("recordedfuture_base_url")

        self.set_validator("ipv6", self._is_ip)

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == "__main__":
    # noinspection PyUnresolvedReferences
    import argparse

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
            print("Accessing the Login page")
            r = requests.get(login_url, verify=True, timeout=timeout)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=True, data=data, headers=headers, timeout=timeout)
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = RecordedfutureConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            # noinspection PyProtectedMember
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
