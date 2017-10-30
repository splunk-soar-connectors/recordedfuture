# --
# File: recordedfuture_connector.py
#
# Copyright (c) Recorded Future, Inc., 2016
#
# This unpublished material is proprietary to Recorded Future.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Recorded Future.
#
# --
# -----------------------------------------
# Recorded Future App Connector python file
# -----------------------------------------

# Phantom App imports
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Imports local to this App
import simplejson as json
import urllib2

# Constants
RECORDEDFUTURE_API_TOKEN = 'recordedfuture_api_token'
RECORDEDFUTURE_API_BASENAME = 'recordedfuture_api_basename'

RECORDEDFUTURE_ERR_QUERY = "Recorded Future query failed"
RECORDEDFUTURE_SUCC_QUERY = "Recorded Future query successful"
RECORDEDFUTURE_QUERY_RETURNED_NO_DATA = "No data response from Recorded Future API (HTTP 404)"
RECORDEDFUTURE_ERR_SERVER_CONNECTION = "Connection to server failed"
RECORDEDFUTURE_ERR_CONNECTIVITY_TEST = "Connectivity test failed"
RECORDEDFUTURE_SUCC_CONNECTIVITY_TEST = "Connectivity test passed"


# Define the App Class
class RecordedFutureConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(RecordedFutureConnector, self).__init__()

    # Get RF API token
    def initialize(self):
        self._token = None
        self._apiBasename = None

        config = self.get_config()
        self._apiBasename = config.get(RECORDEDFUTURE_API_BASENAME)
        if (not self._apiBasename):
            self._apiBasename = "https://api.recordedfuture.com/v2/"
        self._token = config.get(RECORDEDFUTURE_API_TOKEN)
        if (not self._token):
            self.save_progress("Recorded Future API token not set")
            return phantom.APP_ERROR
        else:
            self.save_progress("Creating Recorded Future API connection object")
            return phantom.APP_SUCCESS

    def _test_connectivity(self, param):

        try:
            test_query = self._apiBasename + "domain/recordedfuture.com?comment=PhantomCyber"
            req = urllib2.Request(test_query, None, {"X-RFToken": self._token})
            self.save_progress("Running a domain lookup to check connectivity")
            self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, "Recorded Future API")
            urllib2.urlopen(req)
        except Exception as e:
            self.set_status(phantom.APP_ERROR, RECORDEDFUTURE_ERR_SERVER_CONNECTION, e)
            self.append_to_message(RECORDEDFUTURE_ERR_CONNECTIVITY_TEST)
            return self.get_status()

        self.save_progress(RECORDEDFUTURE_SUCC_CONNECTIVITY_TEST)
        return self.set_status(phantom.APP_SUCCESS)

    def _handle_enrich(self, url, action_result):

        try:
            self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, "Recorded Future API")
            req = urllib2.Request(url, None, {"X-RFToken": self._token})
            res = json.loads(urllib2.urlopen(req).read())['data']
            action_result.add_data(res)
            summary = {}
            if ('risk' in res) and ('criticalityLabel' in res['risk']):
                summary['criticalityLabel'] = res['risk']['criticalityLabel']
            if ('risk' in res) and ('riskSummary' in res['risk']):
                summary['riskSummary'] = res['risk']['riskSummary']
            if ('timestamps' in res) and ('lastSeen' in res['timestamps']):
                summary['lastSeen'] = res['timestamps']['lastSeen']
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_SUCCESS)
            return action_result.get_status()
        except urllib2.HTTPError as e:
            if e.code == 404:
              action_result.set_status(phantom.APP_SUCCESS, RECORDEDFUTURE_QUERY_RETURNED_NO_DATA)
              return action_result.get_status()
            else:
              action_result.set_status(phantom.APP_ERROR, RECORDEDFUTURE_ERR_QUERY, e)
              return action_result.get_status()
        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, RECORDEDFUTURE_ERR_QUERY, e)
            return action_result.get_status()

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())
        self.debug_print("param", param)

        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        url_pattern = self._apiBasename + "{0}/{1}?fields={2}&comment=PhantomCyber"
        if (action_id == "domain_reputation"):
            url = url_pattern.format("domain",
                                     param["domain"],
                                     "%2C".join(["timestamps", "risk", "threatLists", "intelCard", "metrics"]))
            ret_val = self._handle_enrich(url, action_result)
        elif (action_id == "ip_reputation"):
            url = url_pattern.format("ip",
                                     param["ip"],
                                     "%2C".join(["timestamps", "risk", "threatLists", "intelCard", "metrics", "location"]))
            ret_val = self._handle_enrich(url, action_result)
        elif (action_id == "file_reputation"):
            url = url_pattern.format("hash",
                                     param["hash"],
                                     "%2C".join(["timestamps", "risk", "threatLists", "intelCard", "metrics", "hashAlgorithm"]))
            ret_val = self._handle_enrich(url, action_result)
        elif (action_id == "lookup_vulnerability"):
            url = url_pattern.format("vulnerability",
                                     param["vulnerability"],
                                     "%2C".join(["timestamps", "risk", "threatLists", "intelCard", "metrics", "cvss", "nvdDescription"]))
            ret_val = self._handle_enrich(url, action_result)
        elif (action_id == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity(param)

        return ret_val


if __name__ == '__main__':

    import sys
    import pudb
    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = RecordedFutureConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
