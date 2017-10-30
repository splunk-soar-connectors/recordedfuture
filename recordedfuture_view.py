# --
# File: recordedfuture_view.py
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
# Recorded Future App View python file
# -----------------------------------------


def format_result(result):

    retval = { 'param': result.get_param() }

    data = result.get_data()
    if (data):
        retval['data'] = data[0]

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


def display_results(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            formatted = format_result(result)
            if (not formatted):
                continue
            results.append(formatted)
    return 'display_results.html'
