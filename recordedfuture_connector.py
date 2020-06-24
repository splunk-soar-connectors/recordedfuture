#
# File: recordedfuture_connector.py
#
# Copyright (c) Recorded Future, Inc., 2019-2020
#
# This unpublished material is proprietary to Recorded Future.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Recorded Future.
#
# ---------------------------------------------
# Phantom Recorded Future Connector python file
# ---------------------------------------------

# Global imports
import os
import requests
import sys

try:
    import urllib
except:
    import urllib.request
    import urllib.parse
    import urllib.error

import json
import hashlib
import platform
# noinspection PyCompatibility
import ipaddress
# noinspection PyUnresolvedReferences
from bs4 import BeautifulSoup

# Phantom App imports
# noinspection PyUnresolvedReferences
import phantom.app as phantom
# noinspection PyUnresolvedReferences
from phantom.base_connector import BaseConnector
# noinspection PyUnresolvedReferences
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
from recordedfuture_consts import *
from bs4 import UnicodeDammit


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class RecordedfutureConnector(BaseConnector):
    """Implement a Connector towards Recorded Future's ConnectAPI."""

    def __init__(self):
        """Initialize."""
        # Call the BaseConnectors init first
        super(RecordedfutureConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    @staticmethod
    def _process_empty_response(response, action_result):
        """Process an empty result."""
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Status code: {0}. Empty response and no information in the header".format(response.status_code)), None)

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
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception as err:
            error_text = "Cannot parse error details: {0}".format(err)

        try:
            if sys.version_info[0] < 3:
                error_text = UnicodeDammit(error_text).unicode_markup.encode('utf-8')
            else:
                error_text = UnicodeDammit(error_text).unicode_markup
        except:
            error_text = error_text

        message = "Please check the app configuration parameters. Status Code: {0}. Data from server:\n{1}\n".format(
            status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message),
                      None)

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
                "entity": {
                    "name": '',
                    'type': None,
                    'id': None
                },
                "timestamps": {
                    "firstSeen": "never",
                    "lastSeen": "never"
                },
                "risk": {
                    "criticalityLabel": "None",
                    "rules": None,
                    "evidenceDetails": [],
                    "riskSummary": "No information available.",
                    "criticality": None,
                    "riskString": "",
                    "score": None
                }
            }
        }
        if 'intelCard' in fields:
            resp_json['data']['intelCard'] = ''
        if 'threatLists' in fields:
            resp_json['data']['threatLists'] = []
        if 'relatedEntities' in fields:
            resp_json['data']['relatedEntities'] = []
        if 'location' in fields:
            resp_json['data']['location'] = {}
        if 'metrics' in fields:
            resp_json['data']['metrics'] = []
        return resp_json

    def _process_json_response(self, resp, action_result, **kwargs):
        """Process a JSON response."""
        # Try a json parse
        try:
            resp_json = resp.json()
        except Exception as err:
            error_code, error_msg = self._get_error_message_from_exception(err)
            return RetVal(action_result.set_status(
                phantom.APP_ERROR,
                "Unable to parse JSON response. Error code: {0}. Error message: {1}".format(error_code, error_msg)),
                None)

        # Please specify the status codes here
        if 200 <= resp.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # If an IOC has no data in Recorded Future's API it returns 404.
        # While this is correct in REST semantics it's not what our app
        # needs. We will create an empty response instead.
        self.debug_print('_process_json_response kwargs: ', kwargs)
        if 'fields' in kwargs.get('params', {}):
            fields = kwargs['params']['fields'].split(',')
            self.debug_print('_process_json_response fields: ', fields)
            if resp.status_code == 404:
                resp_json = self._create_empty_response(fields)

                return RetVal(phantom.APP_SUCCESS, resp_json)

        msg = "No data found"

        if resp_json.get('message'):
            msg = resp_json.get('message')

        if resp_json.get('error').get('message'):
            if msg:
                msg = "{} and {}".format(msg, resp_json.get('error').get('message'))
            else:
                msg = resp_json.get('error').get('message')

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} " \
                  "Data from server: {1}".format(resp.status_code, self._handle_py_ver_compat_for_input_str(msg))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message),
                      None)

    def _process_response(self, resp, action_result, **kwargs):
        """Process the response.

        The response handling is handled differently depending on whether
        it's text, HTML or JSON.
        """
        # store the r_text in debug data, it will get dumped in the logs if
        # the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': resp.status_code})
            action_result.add_debug_data({'r_text': resp.text})
            action_result.add_debug_data({'r_headers': resp.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in resp.headers.get('Content-Type', ''):
            return self._process_json_response(resp, action_result, **kwargs)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in resp.headers.get('Content-Type', ''):
            return self._process_html_response(resp, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not resp.text:
            return self._process_empty_response(resp, action_result)

        # everything else is actually an error at this point
        error_msg = self._handle_py_ver_compat_for_input_str(resp.text.replace('{', '{{').replace('}', '}}'))
        message = "Can't process response from server. Status Code: {0} " \
                  "Data from server: {1}".format(resp.status_code,
                                                 error_msg)

        return RetVal(action_result.set_status(phantom.APP_ERROR, message),
                      None)

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        try:
            if hasattr(e, 'args'):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = "Error code unavailable"
                    error_msg = e.args[0]
            else:
                error_code = "Error code unavailable"
                error_msg = "Unknown error occurred. Please check the asset configuration and|or action parameters."
        except:
            error_code = "Error code unavailable"
            error_msg = "Unknown error occurred. Please check the asset configuration and|or action parameters."

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = "Error occurred while connecting to the server. Please check the asset configuration and|or the action parameters."
        except:
            error_msg = "Unknown error occurred. Please check the asset configuration and|or action parameters."

        return error_code, error_msg

    def _handle_py_ver_compat_for_input_str(self, input_str):
        """
        This method returns the encoded|original string based on the Python version.
        :param sys.version_info[0]: Python major version
        :param input_str: Input string to be processed
        :return: input_str
        """

        try:
            if input_str and sys.version_info[0] < 3:
                input_str = UnicodeDammit(input_str).unicode_markup.encode('utf-8')
            elif input_str:
                input_str = UnicodeDammit(input_str).unicode_markup
        except:
            self.debug_print("Error occurred while handling python 2to3 compatibility for the input string")

        return input_str

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
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
            return RetVal(action_result.set_status(
                phantom.APP_ERROR,
                "Invalid method: {0}".format(method)),
                resp_json)
        # Create a URL to connect to
        url = "{}{}".format(self._handle_py_ver_compat_for_input_str(self._base_url), endpoint)
        # Create a HTTP_USER_AGENT header
        # container_id is added to track actions associated with an event in
        # order to improve the app
        platform_id = 'Phantom_%s' % self.get_product_version()
        pdict = dict(app_name=os.path.basename(__file__),
                     container_id=self.get_container_id(),
                     os_id=platform.platform(),
                     pkg_name='phantom',
                     pkg_version=version,
                     requests_id=requests.__version__,
                     platform_id=platform_id)
        user_agent_tplt = '{app_name}/{container_id} ({os_id}) ' \
                          '{pkg_name}/{pkg_version} ' \
                          'python-requests/{requests_id} ({platform_id})'
        user_agent = user_agent_tplt.format(**pdict)
        # headers
        api_key = config.get('recordedfuture_api_token')
        my_headers = {
            'X-RFToken': api_key,
            'User-Agent': user_agent
        }

        # Ensure we log some useful data:
        # url:          shows if the url to ConnectAPI has been changed
        # kwargs:       shows fields and other keywords
        # fingerprint:  can be used to verify that the correct API key is used
        self.debug_print('_make_rest_call url: {}'.format(url))
        self.debug_print('_make_rest_call kwargs {}'.format(kwargs))
        try:
            self.debug_print('_make_rest_call api key fingerprint: %s'
                % hashlib.md5(api_key).hexdigest()[:6])
        except:
            self.debug_print('_make_rest_call api key fingerprint: %s'
                 % hashlib.md5(api_key.encode('utf-8')).hexdigest()[:6])

        # Make the call
        try:
            resp = request_func(
                url,
                headers=my_headers,
                verify=config.get('recordedfuture_verify_ssl', False),
                **kwargs)
        except Exception as err:
            error_code, error_msg = self._get_error_message_from_exception(err)

            return RetVal(action_result.set_status(
                phantom.APP_ERROR,
                "Error Connecting to server. Details: Error code:{0}. Error message:{1}".format(error_code, error_msg)),
                resp_json)
        # Process the response
        return self._process_response(resp, action_result, **kwargs)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent
        # the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to endpoint")

        # make rest call
        my_ret_val, response = self._make_rest_call('/domain/google.com',
                                                    action_result)

        if phantom.is_fail(my_ret_val):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_intelligence(self, param, path_info, fields, operation_type):
        """Return intelligence for an entity."""
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Params for the API call
        params = {
            'fields': ','.join(fields)
        }

        # make rest call
        my_ret_val, response = self._make_rest_call(path_info,
                                                    action_result,
                                                    params=params)

        self.debug_print('_handle_intelligence',
                         {'path_info': path_info,
                          'action_result': action_result,
                          'params': params,
                          'my_ret_val': my_ret_val,
                          'response': response})

        if phantom.is_fail(my_ret_val):
            return action_result.get_status()

        res = response.get('data', {})
        action_result.add_data(res)
        self.save_progress('Added data with keys {}', list(res.keys()))

        # Update the summary
        summary = action_result.get_summary()
        if 'risk' in res:
            if 'criticalityLabel' in res['risk']:
                summary['criticalityLabel'] = res['risk'][
                    'criticalityLabel']
            if 'riskSummary' in res['risk']:
                summary['riskSummary'] = res['risk']['riskSummary']
        if 'timestamps' in res:
            if 'lastSeen' in res['timestamps']:
                summary['lastSeen'] = res['timestamps']['lastSeen']

        action_result.set_summary(summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_reputation(self, param, category, entity):
        """Return reputation information."""
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Params for the API call
        params = {
            category: entity
        }

        # make rest call
        my_ret_val, response = self._make_rest_call('/soar/enrichment',
                                                    action_result,
                                                    json=params,
                                                    method='post')

        self.debug_print('_handle_reputation', {'path_info': entity,
                                                'endpoint': '/soar/enrichment',
                                                'action_result': action_result,
                                                'params': params,
                                                'my_ret_val': my_ret_val,
                                                'response': response})

        if phantom.is_fail(my_ret_val):
            return action_result.get_status()
        if response.get('data', {}).get('results', []):
            summary = action_result.get_summary()
            item = response['data']['results'][0]
            risk = item['risk']
            rule = risk['rule']
            if 'evidence' in rule:
                evidence_list = rule['evidence']
                evidence = [{
                    'ruleid': evidence_id,
                    'timestamp': evidence_list[evidence_id]['timestamp'],
                    'description': evidence_list[evidence_id]['description'],
                    'rule': evidence_list[evidence_id]['rule'],
                    'level': evidence_list[evidence_id]['level'],
                    'mitigation': evidence_list[evidence_id].get('mitigation', None)}
                    for evidence_id in list(evidence_list.keys())]
            else:
                evidence = []

            res = {
                'id': item['entity']['id'],
                'name': item['entity']['name'],
                'type': item['entity']['type'],
                'risklevel': risk['level'],
                'riskscore': risk['score'],
                'rulecount': rule['count'],
                # 'maxrules': rule['maxCount'],
                'evidence': evidence,
                'description':
                    item['entity'].get('description', None)
            }

            if rule.get('maxCount'):
                res['maxrules'] = rule['maxCount']

            if 'description' in item['entity']:
                res['description'] = item['entity']['description']

            # Update the summary
            summary = action_result.get_summary()
            summary['risk score'] = res['riskscore']
            summary['risk summary'] = '%s rules triggered of %s' % (
                res['rulecount'], res['maxrules'])

        else:
            res = {
                "id": None,
                "name": '',
                "type": None,
                "description": '',
                "risklevel": None,
                "riskscore": None,
                "rulecount": None,
                "maxrules": None,
            }
            summary = action_result.get_summary()
            summary['riskscore'] = "No information available."

        action_result.add_data(res)
        self.save_progress('Added data with keys {}', list(res.keys()))

        action_result.set_summary(summary)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary
        # dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_triage(self, param):
        """Return threat assessment information."""
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Params for the API call
        param_types = ['ip', 'domain', 'url', 'hash']
        params = {}
        for i in param.keys():
            if i in param_types:
                params[i] = [self._handle_py_ver_compat_for_input_str(entry.strip()) for entry in param.get(i).split(',')
                             if entry != 'None']

        self.save_progress('Params found to triage: %s' % params)

        # make rest call
        my_ret_val, response = self._make_rest_call(
            '/soar/triage/contexts/%s?%s' % (self._handle_py_ver_compat_for_input_str(param['threat_context']),
                                             '&format=phantom'),
            action_result,
            json=params,
            method='post')

        self.debug_print('_handle_triage', {'path_info': 'triage',
                                            'endpoint': '/soar/triage',
                                            'action_result': action_result,
                                            'params': params,
                                            'my_ret_val': my_ret_val,
                                            'response': response})

        self.save_progress('Obtained API response')

        if phantom.is_fail(my_ret_val):
            return action_result.get_status()

        # there will always be a response with data, how best represent this?
        summary = action_result.get_summary()
        if response:
            # restructure json
            res = {
                'context': response['context'],
                'verdict': response['verdict'],
                'assessment_riskscore': response['scores']['max'],
                'entities': [{
                    'id': entity['id'],
                    'name': entity['name'],
                    'type': entity['type'],
                    'score': entity['score'],
                    'evidence': entity['rule']['evidence']}
                    for entity in response['entities']]
            }
            action_result.add_data(res)

            # set summary
            if response['verdict']:
                summary['assessment'] = 'Suspected to be malicious'
            else:
                summary['assessment'] = 'Not found to be malicious'
            summary['riskscore'] = response['scores']['max']
        else:
            res = {}

        action_result.set_summary(summary)
        self.save_progress('Added data with keys {}', res.keys())

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary
        # dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_contexts(self, param):
        """List available contexts"""

        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier()))

        # make rest call
        my_ret_val, response = self._make_rest_call('/soar/triage/contexts',
                                                    action_result)

        self.debug_print('_handle_list_contexts',
                         {'action_result': action_result,
                          'my_ret_val': my_ret_val,
                          'response': response})

        if phantom.is_fail(my_ret_val):
            self.save_progress("API call to retrieve triage contexts failed.")
            return action_result.get_status()

        if response:
            self.save_progress('Added data with keys {}', list(response.keys()))

            summary = action_result.get_summary()
            summary_statement = ''
            for triage_context in list(response.keys()):
                # Assemble summary
                if summary_statement == '':
                    summary_statement = triage_context
                else:
                    summary_statement = summary_statement + ', ' + triage_context

                action_result.add_data({
                    "context": triage_context,
                    "name": response[triage_context].get('name'),
                    "datagroup": response[triage_context].get('datagroup')
                })

            summary['contexts_available_for_threat_assessment'] = \
                summary_statement

        else:
            self.save_progress("API call failed to retrieve any information.")
            summary = 'API call to retrieve triage contexts failed'

        action_result.set_summary(summary)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary
        # dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _parse_rule_data(self, res):
        """Reformat entities returned by the alert verb."""
        from collections import defaultdict
        entities = defaultdict(list)
        for ent in res.get('entities', []):
            if ent['entity'] is not None:
                entities[ent['entity']['type']].append(ent['entity']['name'])
            for doc in ent.get('documents'):
                for ref in doc.get('references'):
                    for entity in ref.get('entities'):
                        entities[entity['type']].append(entity['name'])
        return entities

    def _handle_alert_data_lookup(self, param):
        """Implement lookup of alerts issued for an alert rule."""
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent
        # the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        rule_id = self._handle_py_ver_compat_for_input_str(param['rule_id'])
        timeframe = self._handle_py_ver_compat_for_input_str(param['timeframe'])
        assert rule_id is not None
        assert timeframe is not None

        # Prepare the REST call
        params = {
            'alertRule': rule_id,
            'triggered': timeframe
        }

        # Make rest call
        my_ret_val, response = self._make_rest_call('/alert/search',
                                                    action_result,
                                                    params=params)

        self.debug_print('_handle_alert_data_lookup',
                         {'path_info': '/alert/search',
                          'action_result': action_result,
                          'params': params,
                          'my_ret_val': my_ret_val,
                          'response': response})

        # Something went wrong
        if phantom.is_fail(my_ret_val):
            return action_result.get_status()

        # Setup summary
        summary = action_result.get_summary()
        summary['total_number_of_alerts'] = response['counts']['total']
        summary['returned_number_of_alerts'] = response['counts']['returned']

        # No results can be non existing rule id or just that, no results...
        if response['counts']['total'] == 0:
            action_result.set_summary(summary)
            return action_result.set_status(phantom.APP_SUCCESS,
                                            'No alerts triggered from rule %s '
                                            'within timerange "%s"'
                                            % (rule_id,
                                               timeframe))

        # Add info about the rule to summary and action_result['data']
        summary['rule_name'] = response['data']['results'][0]['rule']['name']
        summary['rule_id'] = response['data']['results'][0]['rule']['id']
        action_result.set_summary(summary)

        # For each alert that match the rule id/timerange search details
        # are fetched and added.
        alerts = []
        for alert in response['data']['results']:
            self.save_progress('In alert loop: %s' % alert)
            url2 = '/alert/%s' % alert['id']
            ret_val2, response2 = self._make_rest_call(url2, action_result)
            self.debug_print('_handle_alert_data_lookup',
                             {'path_info': url2,
                              'action_result': action_result,
                              'params': None,
                              'my_ret_val': ret_val2,
                              'response': response2})

            entities = self._parse_rule_data(response2['data'])
            self.save_progress('ENTITIES: %s' % entities)

            # Add the response into the data section
            current_alert = {
                'alertTitle': response2['data']['title'],
                'triggered': response2['data']['triggered'],
                'alertUrl': response2['data']['url'],
                'content': response2['data'],
                'entities': entities
            }
            alerts.append({'alert': current_alert})
            self.save_progress('Alert: "%s" triggered "%s"'
                               % (response2['data']['title'],
                                  response2['data']['triggered']))

        action_result.add_data({'rule': response['data']['results'][0]['rule'],
                                'alerts': alerts})

        # Return success, no need to set the message, only the status
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_rule_id_lookup(self, param):
        """Make a freetext search for alert rules."""
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent
        # the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Prepare the REST call
        params = {
            'freetext': self._handle_py_ver_compat_for_input_str(param['rule_name']),
            'limit': 100
        }

        # make rest call
        my_ret_val, response = self._make_rest_call('/alert/rule',
                                                    action_result,
                                                    params=params)

        self.debug_print('_handle_rule_id_lookup',
                         {'path_info': '/alert/rule',
                          'action_result': action_result,
                          'params': params,
                          'my_ret_val': my_ret_val,
                          'response': response})

        # Handle failure
        if phantom.is_fail(my_ret_val):
            return action_result.get_status()

        # Now post process the data
        rule_ids = []
        for result in list(response['data'].values()):
            for rule in result:
                action_result.add_data({'rule': rule})
                rule_ids.append(rule['id'])

        # Summary
        summary = action_result.get_summary()
        summary['total_number_of_rules'] = response['counts']['total']
        summary['returned_number_of_rules'] = response['counts']['returned']
        summary['rule_id_list'] = ','.join(rule_ids)
        action_result.set_summary(summary)

        # Return success, no need to set the message, only the status
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        """Handle a call to the app, switch depending on action."""
        my_ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()
        self.debug_print('DEBUG: action_id = %s' % action_id)

        # Try to split on _ in order to handle reputation/intelligence and
        # ip/domain/file/vulnerability/url permutation.
        if len(action_id.split('_')) == 2:
            entity_type, operation_type = action_id.split('_')
        else:
            entity_type, operation_type = None, None
        self.debug_print('DEBUG: entity_type, operation_type = %s, %s'
                         % (entity_type, operation_type))

        # Switch depending on action
        if action_id == 'test_connectivity':
            my_ret_val = self._handle_test_connectivity(param)

        elif operation_type == 'intelligence':
            omap = INTELLIGENCE_MAP
            path_info_tmplt, fields, tag, do_quote = omap[entity_type]
            param_tag = self._handle_py_ver_compat_for_input_str(param[tag])
            if do_quote:
                if sys.version_info[0] < 3:
                    path_info = path_info_tmplt % urllib.quote_plus(param_tag)
                else:
                    path_info = path_info_tmplt % urllib.parse.quote_plus(param_tag)
            else:
                path_info = path_info_tmplt % param_tag
            my_ret_val = self._handle_intelligence(param, path_info, fields,
                                                   operation_type)
        elif operation_type == 'reputation':
            # phantom entity type file has to be changed to hash
            if entity_type == 'file':
                tag = 'hash'
            else:
                tag = entity_type
            param_tag = self._handle_py_ver_compat_for_input_str(param[tag])
            my_ret_val = self._handle_reputation(param, tag, param_tag)

        elif action_id == 'threat_assessment':
            # todo: need to check the in-parameters
            my_ret_val = self._handle_triage(param)
        elif action_id == 'list_contexts':
            # todo: need to check the in-parameters
            my_ret_val = self._handle_list_contexts(param)

        elif action_id == 'rule_id_lookup':
            my_ret_val = self._handle_rule_id_lookup(param)

        elif action_id == 'alert_data_lookup':
            my_ret_val = self._handle_alert_data_lookup(param)

        return my_ret_val

    def _is_ip(self, input_ip_address):
        """ Function that checks given address and return True if address is valid IPv4 or IPV6 address.

        :param input_ip_address: IP address
        :return: status (success/failure)
        """

        ip_address_input = UnicodeDammit(input_ip_address).unicode_markup

        try:
            ipaddress.ip_address(ip_address_input)
        except:
            return False

        return True

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = config.get('recordedfuture_base_url')

        self.set_validator('ipv6', self._is_ip)

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':
    # noinspection PyUnresolvedReferences
    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

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
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False,
                               data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(
                e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = RecordedfutureConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            # noinspection PyProtectedMember
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
