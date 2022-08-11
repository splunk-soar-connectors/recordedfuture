# File: recordedfuture_view.py
#
# Copyright (c) Recorded Future, Inc., 2019-2022
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

APP_URL = 'https://app.recordedfuture.com/live/sc/entity/%s%%3A%s'
VULN_APP_URL = 'https://app.recordedfuture.com/live/sc/entity/%s'


def format_result(result, all_data=False):
    retval = {'param': result.get_param()}

    data = result.get_data()
    if data:
        retval['data'] = data[0]

    try:
        # assemble the string needed for an URL to Recorded Future portal
        if (
            data and 'risk' in retval['data'] and retval['data']['risk']['score'] is not None
        ):
            if 'domain' in retval['param']:
                retval['intelCard'] = APP_URL % ('idn', retval['param']['domain'])
            elif 'ip' in retval['param']:
                retval['intelCard'] = APP_URL % ('ip', retval['param']['ip'])
            elif 'hash' in retval['param']:
                retval['intelCard'] = APP_URL % ('hash', retval['param']['hash'])
            elif 'url' in retval['param']:
                retval['intelCard'] = APP_URL % ('url', retval['param']['url'])
            elif 'vulnerability' in retval['param']:
                retval['intelCard'] = VULN_APP_URL % (retval['data']['entity']['id'])

            for rule in retval['data']['risk']['evidenceDetails']:
                rule['timestampShort'] = rule['timestamp'][:10]

        # add cvss info only if present (should only be applicable by vulnerabilities)
        if data and 'cvss' in retval['data'] and 'published' in retval['data']['cvss']:
            retval['data']['cvss']['publishedShort'] = retval['data']['cvss'][
                'published'
            ][:10]
            retval['data']['cvss']['lastModifiedShort'] = retval['data']['cvss'][
                'lastModified'
            ][:10]

        # format date and time to be shorter and easier to read
        retval['data']['timestamps']['firstSeenShort'] = retval['data']['timestamps'][
            'firstSeen'
        ][:10]
        retval['data']['timestamps']['lastSeenShort'] = retval['data']['timestamps'][
            'lastSeen'
        ][:10]
    except Exception:
        retval['data'] = None

    # set summary, status and message for the action
    summary = result.get_summary()
    if summary:
        retval['summary'] = summary

    status = result.get_status()
    if status:
        retval['status'] = 'Success'
    else:
        retval['status'] = 'Failure'

    message = result.get_message()
    if message:
        retval['message'] = message

    return retval


def format_reputation_result(result, all_data=False):
    retval = {'param': result.get_param()}

    data = result.get_data()
    if data:
        retval['data'] = data[0]

    if data and retval['data']['riskscore'] is not None:
        if 'domain' in retval['param']:
            retval['intelCard'] = APP_URL % ('idn', retval['param']['domain'])
        elif 'ip' in retval['param']:
            retval['intelCard'] = APP_URL % ('ip', retval['param']['ip'])
        elif 'hash' in retval['param']:
            retval['intelCard'] = APP_URL % ('hash', retval['param']['hash'])
        elif 'url' in retval['param']:
            retval['intelCard'] = APP_URL % ('url', retval['param']['url'])
        elif 'vulnerability' in retval['param']:
            retval['intelCard'] = VULN_APP_URL % (retval['data']['id'])

    summary = result.get_summary()
    if summary:
        retval['summary'] = summary

    status = result.get_status()
    if status:
        retval['status'] = 'Success'
    else:
        retval['status'] = 'Failure'

    message = result.get_message()
    if message:
        retval['message'] = message

    return retval


def format_contexts_result(result, all_data=False):
    retval = {'param': result.get_param()}

    data = result.get_data()
    if data:
        retval['data'] = data

    summary = result.get_summary()
    if summary:
        retval['summary'] = summary

    status = result.get_status()
    if status:
        retval['status'] = 'Success'
    else:
        retval['status'] = 'Failure'

    message = result.get_message()
    if message:
        retval['message'] = message

    return retval


def intelligence_results(provides, all_app_runs, context):
    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            formatted = format_result(result)
            if not formatted:
                continue
            results.append(formatted)

    return 'intelligence_results.html'


def reputation_results(provides, all_app_runs, context):
    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            formatted = format_reputation_result(result)
            if not formatted:
                continue
            results.append(formatted)

    return 'reputation_results.html'


def contexts_results(provides, all_app_runs, context):
    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            formatted = format_contexts_result(result)
            if not formatted:
                continue
            results.append(formatted)

    return 'contexts_results.html'


def format_alert_result(result):
    return format_result(result)


def alert_lookup_results(provides, all_app_runs, context):
    """Setup the view for an alert."""
    context['results'] = results = []

    for summary, action_results in all_app_runs:

        for result in action_results:
            formatted = {'param': result.get_param(), 'data': result.get_data()}
            if not formatted:
                continue
            results.append(formatted)

    return 'alert_lookup_results.html'


def alert_update_results(provides, all_app_runs, context):
    """Setup the view for an alert."""
    context['results'] = results = []

    for summary, action_results in all_app_runs:

        for result in action_results:
            formatted = {'param': result.get_param(), 'data': result.get_data()}
            if not formatted:
                continue
            results.append(formatted)

    return 'alert_update_results.html'


def alert_search_results(provides, all_app_runs, context):
    """Setup the view for alert results."""
    context['results'] = results = []

    for summary, action_results in all_app_runs:

        for result in action_results:
            formatted = {'param': result.get_param(), 'data': result.get_data()}
            if not formatted:
                continue
            results.append(formatted)

    return 'alert_search_results.html'


def alert_rule_search_results(provides, all_app_runs, context):
    """Render the list of Alert Rules that match the search."""
    context['results'] = results = []

    for summary, action_results in all_app_runs:

        for result in action_results:
            formatted = {'param': result.get_param(), 'data': result.get_data()}
            if not formatted:
                continue
            results.append(formatted)

    return 'alert_rule_search_results.html'


def format_threat_assessment_result(result, all_data=False):
    retval = {'param': result.get_param()}

    data = result.get_data()
    if data:
        ret_data = {key: data[0][key] for key in data[0].keys() if key != 'entities'}

        entities = data[0]['entities']
        entities.sort(key=lambda x: int(x.get('riskscore', "0")))
        ret_data['entities'] = [entity for entity in entities if entity['riskscore']]
        retval['data'] = ret_data
    else:
        retval['data'] = 'NO DATA'

    summary = result.get_summary()
    if summary:
        retval['summary'] = summary

    status = result.get_status()
    if status:
        retval['status'] = 'Success'
    else:
        retval['status'] = 'Failure'

    message = result.get_message()
    if message:
        retval['message'] = message

    return retval


def threat_assessment_results(provides, all_app_runs, context):
    """Setup the view for Threat Assessment results."""
    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            formatted = format_threat_assessment_result(result)
            if not formatted:
                continue
            results.append(formatted)

    return 'threat_assessment_results.html'
