# --
# File: recordedfuture_view.py
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
# --
# -----------------------------------------
# Recorded Future App View python file
# -----------------------------------------

APP_URL = 'https://app.recordedfuture.com/live/sc/entity/%s%%3A%s'
VULN_APP_URL = 'https://app.recordedfuture.com/live/sc/entity/%s'


def format_result(result, all_data=False):
    retval = {'param': result.get_param()}

    data = result.get_data()
    if data:
        retval['data'] = data[0]

    if data and 'risk' in retval['data'] \
            and retval['data']['risk']['score'] is not None:
        if 'domain' in retval['param']:
            retval['intelCard'] = APP_URL % ('idn', retval['param']['domain'])
        elif 'ip' in retval['param']:
            retval['intelCard'] = APP_URL % ('ip', retval['param']['ip'])
        elif 'hash' in retval['param']:
            retval['intelCard'] = APP_URL % ('hash', retval['param']['hash'])
        elif 'url' in retval['param']:
            retval['intelCard'] = APP_URL % ('url', retval['param']['url'])
        elif 'vulnerability' in retval['param']:
            retval['intelCard'] = VULN_APP_URL \
                                  % (retval['data']['entity']['id'])

        for rule in retval['data']['risk']['evidenceDetails']:
            rule['timestampShort'] = rule['timestamp'][:10]

    if data and 'cvss' in retval['data'] \
            and 'published' in retval['data']['cvss']:
        retval['data']['cvss']['publishedShort'] = \
            retval['data']['cvss']['published'][:10]
        retval['data']['cvss']['lastModifiedShort'] = \
            retval['data']['cvss']['lastModified'][:10]

    retval['data']['timestamps']['firstSeenShort'] = \
        retval['data']['timestamps']['firstSeen'][:10]
    retval['data']['timestamps']['lastSeenShort'] = \
        retval['data']['timestamps']['lastSeen'][:10]

    summary = result.get_summary()
    if (summary):
        retval['summary'] = summary

    status = result.get_status()
    if (status):
        retval['status'] = 'Success'
    else:
        retval['status'] = 'Failure'

    message = result.get_message()
    if (message):
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
    if (summary):
        retval['summary'] = summary

    status = result.get_status()
    if (status):
        retval['status'] = 'Success'
    else:
        retval['status'] = 'Failure'

    message = result.get_message()
    if (message):
        retval['message'] = message

    return retval


def format_contexts_result(result, all_data=False):
    retval = {'param': result.get_param()}

    data = result.get_data()
    if data:
        retval['data'] = data

    summary = result.get_summary()
    if (summary):
        retval['summary'] = summary

    status = result.get_status()
    if (status):
        retval['status'] = 'Success'
    else:
        retval['status'] = 'Failure'

    message = result.get_message()
    if (message):
        retval['message'] = message

    return retval


def intelligence_results(provides, all_app_runs, context):
    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            formatted = format_result(result)
            if (not formatted):
                continue
            results.append(formatted)
    return 'intelligence_results.html'


def reputation_results(provides, all_app_runs, context):
    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            formatted = format_reputation_result(result)
            if (not formatted):
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


def alert_data_results(provides, all_app_runs, context):
    """Setup the view for alert results."""
    context['results'] = results = []

    for summary, action_results in all_app_runs:

        for result in action_results:
            # formatted = format_alert_result(result, True)
            formatted = {
                'param': result.get_param(),
                'data': result.get_data()
            }
            if not formatted:
                continue
            results.append(formatted)

    return 'alert_data_results.html'


def alert_rules_results(provides, all_app_runs, context):
    """Render the list of Alert Rules that match the search."""
    context['results'] = results = []

    for summary, action_results in all_app_runs:

        for result in action_results:
            # formatted = format_alert_result(result, True)
            formatted = {
                'param': result.get_param(),
                'data': result.get_data()
            }
            if not formatted:
                continue
            results.append(formatted)

    return 'alert_rules_results.html'


def format_threat_assessment_result(result, all_data=False):
    retval = {'param': result.get_param()}

    data = result.get_data()
    if data:
        # retval['data'] = data[0]
        ret_data = {key: data[0][key]
                    for key in data[0].keys()
                    if key != 'entities'}

        entities = data[0]['entities']
        entities.sort(key=lambda x: int(x.get('score', "0")))
        ret_data['entities'] = [entity for entity in entities
                                if entity['score']]
        retval['data'] = ret_data
    else:
        retval['data'] = 'NO DATA'

    summary = result.get_summary()
    if (summary):
        retval['summary'] = summary

    status = result.get_status()
    if (status):
        retval['status'] = 'Success'
    else:
        retval['status'] = 'Failure'

    message = result.get_message()
    if (message):
        retval['message'] = message

    return retval


def threat_assessment_results(provides, all_app_runs, context):
    """Setup the view for Threat Assessment results."""
    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            formatted = format_threat_assessment_result(result)
            if (not formatted):
                continue
            results.append(formatted)
            # retval = {'param': result.get_param()}
            # retval['data'] = {'riskscore': 90}
            # results.append(retval)
    return 'threat_assessment_results.html'
