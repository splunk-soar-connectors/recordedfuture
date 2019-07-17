# --
# File: recordedfuture_view.py
#
# Copyright (c) Recorded Future, Inc., 2019
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


def format_result(result, all_data=False):

    retval = {'param': result.get_param()}

    data = result.get_data()
    if data:
        retval['data'] = data[0]

    if data and 'risk' in retval['data'] \
            and retval['data']['risk']['score'] is not None:
        if 'ip' in retval['param']:
            retval['intelCard'] = APP_URL % ('ip', retval['param']['ip'])
        elif 'hash' in retval['param']:
            retval['intelCard'] = APP_URL % ('hash', retval['param']['hash'])
        elif 'domain' in retval['param']:
            retval['intelCard'] = APP_URL % ('idn', retval['param']['domain'])

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


def reputation_results(provides, all_app_runs, context):
    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            formatted = format_result(result)
            if (not formatted):
                continue
            results.append(formatted)
    return 'reputation_results.html'


def format_alert_result(result):
    return format_result(result)


def alert_results(provides, all_app_runs, context):
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

    return 'alert_results.html'
