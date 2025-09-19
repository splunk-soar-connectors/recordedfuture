# File: recordedfuture_view.py
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
from datetime import datetime

from recordedfuture_consts import RF_PLAYBOOK_STATUS_MAP


APP_URL = "https://app.recordedfuture.com/live/sc/entity/%s%%3A%s"
VULN_APP_URL = "https://app.recordedfuture.com/live/sc/entity/%s"

ENTITY_LIST_STATUS_VALUE_TO_LITERAL_MAPPING = {
    "ready": "Ready (no pending updates)",
    "pending": "Processing update",
    "processing": "Processing update",
    "added": "added",
    "unchanged": "is already in list",
    "not_in_list": "is not in list",
    "removed": "removed from list",
}

PLAYBOOK_ALERT_CATEGORY_DISPLAY_MAPPING = {
    "domain_abuse": "Domain Abuse",
    "cyber_vulnerability": "Vulnerability",
    "code_repo_leakage": "Code Repo Leakage",
}


def format_datetime_string(datetime_string):
    try:
        return datetime.strptime(datetime_string, "%Y-%m-%dT%H:%M:%S.%f%z").strftime("%Y-%m-%d, %H:%M")
    except ValueError:
        return datetime_string


def format_domain_abuse_details_result(result):
    retval = {"param": result.get_param()}

    data = result.get_data()
    if data:
        data = data[0]
    else:
        retval["data"] = data
        return retval

    data["panel_status"]["created"] = format_datetime_string(data["panel_status"]["created"])
    data["panel_status"]["updated"] = format_datetime_string(data["panel_status"]["updated"])

    panel_evidence_whois = data.get("panel_evidence_whois", {})
    if panel_evidence_whois and not isinstance(panel_evidence_whois.get("body"), list):
        panel_evidence_whois["body"] = []

    retval["data"] = data
    return retval


def format_result(result, all_data=False):
    retval = {"param": result.get_param()}

    data = result.get_data()
    if data:
        retval["data"] = data[0]

    try:
        # assemble the string needed for an URL to Recorded Future portal
        if data and "risk" in retval["data"] and retval["data"]["risk"]["score"] is not None:
            if "domain" in retval["param"]:
                retval["intelCard"] = APP_URL % ("idn", retval["param"]["domain"])
            elif "ip" in retval["param"]:
                retval["intelCard"] = APP_URL % ("ip", retval["param"]["ip"])
            elif "hash" in retval["param"]:
                retval["intelCard"] = APP_URL % ("hash", retval["param"]["hash"])
            elif "url" in retval["param"]:
                retval["intelCard"] = APP_URL % ("url", retval["param"]["url"])
            elif "vulnerability" in retval["param"]:
                retval["intelCard"] = VULN_APP_URL % (retval["data"]["entity"]["id"])

            for rule in retval["data"]["risk"]["evidenceDetails"]:
                rule["timestampShort"] = rule["timestamp"][:10]

        # add cvss info only if present (should only be applicable by vulnerabilities)
        if data and "cvss" in retval["data"] and "published" in retval["data"]["cvss"]:
            retval["data"]["cvss"]["publishedShort"] = retval["data"]["cvss"]["published"][:10]
            retval["data"]["cvss"]["lastModifiedShort"] = retval["data"]["cvss"]["lastModified"][:10]

        # format date and time to be shorter and easier to read
        retval["data"]["timestamps"]["firstSeenShort"] = retval["data"]["timestamps"]["firstSeen"][:10]
        retval["data"]["timestamps"]["lastSeenShort"] = retval["data"]["timestamps"]["lastSeen"][:10]
    except Exception:
        retval["data"] = None

    # set summary, status and message for the action
    summary = result.get_summary()
    if summary:
        retval["summary"] = summary

    status = result.get_status()
    if status:
        retval["status"] = "Success"
    else:
        retval["status"] = "Failure"

    message = result.get_message()
    if message:
        retval["message"] = message

    return retval


def format_reputation_result(result, all_data=False):
    retval = {"param": result.get_param()}

    data = result.get_data()
    if data:
        retval["data"] = data[0]

    if data and retval["data"]["riskscore"] is not None:
        if "domain" in retval["param"]:
            retval["intelCard"] = APP_URL % ("idn", retval["param"]["domain"])
        elif "ip" in retval["param"]:
            retval["intelCard"] = APP_URL % ("ip", retval["param"]["ip"])
        elif "hash" in retval["param"]:
            retval["intelCard"] = APP_URL % ("hash", retval["param"]["hash"])
        elif "url" in retval["param"]:
            retval["intelCard"] = APP_URL % ("url", retval["param"]["url"])
        elif "vulnerability" in retval["param"]:
            retval["intelCard"] = VULN_APP_URL % (retval["data"]["id"])

    summary = result.get_summary()
    if summary:
        retval["summary"] = summary

    status = result.get_status()
    if status:
        retval["status"] = "Success"
    else:
        retval["status"] = "Failure"

    message = result.get_message()
    if message:
        retval["message"] = message

    return retval


def format_contexts_result(result, all_data=False):
    retval = {"param": result.get_param()}

    data = result.get_data()
    if data:
        retval["data"] = data

    summary = result.get_summary()
    if summary:
        retval["summary"] = summary

    status = result.get_status()
    if status:
        retval["status"] = "Success"
    else:
        retval["status"] = "Failure"

    message = result.get_message()
    if message:
        retval["message"] = message

    return retval


def intelligence_results(provides, all_app_runs, context):
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            formatted = format_result(result)
            if not formatted:
                continue
            results.append(formatted)

    return "views/intelligence_results.html"


def reputation_results(provides, all_app_runs, context):
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            formatted = format_reputation_result(result)
            if not formatted:
                continue
            results.append(formatted)

    return "views/reputation_results.html"


def contexts_results(provides, all_app_runs, context):
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            formatted = format_contexts_result(result)
            if not formatted:
                continue
            results.append(formatted)

    return "views/contexts_results.html"


def format_alert_result(result):
    return format_result(result)


def alert_lookup_results(provides, all_app_runs, context):
    """Setup the view for an alert."""
    context["results"] = results = []

    for summary, action_results in all_app_runs:
        for result in action_results:
            formatted = {"param": result.get_param(), "data": result.get_data()}
            if not formatted:
                continue
            results.append(formatted)

    return "views/alert_lookup_results.html"


def alert_update_results(provides, all_app_runs, context):
    """Setup the view for an alert."""
    context["results"] = results = []

    for summary, action_results in all_app_runs:
        for result in action_results:
            formatted = {"param": result.get_param(), "data": result.get_data()}
            if not formatted:
                continue
            results.append(formatted)

    return "views/alert_update_results.html"


def alert_search_results(provides, all_app_runs, context):
    """Setup the view for alert results."""
    context["results"] = results = []

    for summary, action_results in all_app_runs:
        for result in action_results:
            formatted = {"param": result.get_param(), "data": result.get_data()}
            if not formatted:
                continue
            results.append(formatted)

    return "views/alert_search_results.html"


def alert_rule_search_results(provides, all_app_runs, context):
    """Render the list of Alert Rules that match the search."""
    context["results"] = results = []

    for summary, action_results in all_app_runs:
        for result in action_results:
            formatted = {"param": result.get_param(), "data": result.get_data()}
            if not formatted:
                continue
            results.append(formatted)

    return "views/alert_rule_search_results.html"


def format_threat_assessment_result(result, all_data=False):
    retval = {"param": result.get_param()}

    data = result.get_data()
    if data:
        ret_data = {key: data[0][key] for key in data[0].keys() if key != "entities"}

        entities = data[0]["entities"]
        entities.sort(key=lambda x: int(x.get("riskscore", "0")))
        ret_data["entities"] = [entity for entity in entities if entity["riskscore"]]
        retval["data"] = ret_data
    else:
        retval["data"] = "NO DATA"

    summary = result.get_summary()
    if summary:
        retval["summary"] = summary

    status = result.get_status()
    if status:
        retval["status"] = "Success"
    else:
        retval["status"] = "Failure"

    message = result.get_message()
    if message:
        retval["message"] = message

    return retval


def threat_assessment_results(provides, all_app_runs, context):
    """Setup the view for Threat Assessment results."""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            formatted = format_threat_assessment_result(result)
            if not formatted:
                continue
            results.append(formatted)

    return "views/threat_assessment_results.html"


def list_search_results(provides, all_app_runs, context):
    """Setup the view for list search results."""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()
            if result_data:
                result_data = result_data[0]
            results.append({"param": result.get_param(), "data": result_data})

    return "views/list_search_results.html"


def list_create_results(provides, all_app_runs, context):
    """Setup the view for list create result"""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()
            if result_data:
                result_data = result_data[0]
            results.append({"param": result.get_param(), "data": result_data})

    return "views/list_create_results.html"


def list_details_results(provides, all_app_runs, context):
    """Setup the view for list details result"""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()
            if result_data:
                result_data = result_data[0]
                result_data["created"] = format_datetime_string(result_data["created"])
                result_data["updated"] = format_datetime_string(result_data["updated"])

            results.append({"param": result.get_param(), "data": result_data})

    return "views/list_details_results.html"


def list_status_results(provides, all_app_runs, context):
    """Setup the view for list status info"""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()
            if result_data:
                result_data = result_data[0]
                result_data["status"] = ENTITY_LIST_STATUS_VALUE_TO_LITERAL_MAPPING.get(result_data["status"])
            results.append({"param": result.get_param(), "data": result_data})

    return "views/list_status_results.html"


def list_entities_results(provides, all_app_runs, context):
    """Setup the view for list status info"""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()
            if result_data:
                result_data = result_data[0]
                for entity in result_data:
                    entity["added"] = format_datetime_string(entity["added"])
                    entity["status"] = ENTITY_LIST_STATUS_VALUE_TO_LITERAL_MAPPING.get(entity["status"])
            results.append({"param": result.get_param(), "data": result_data})

    return "views/list_entities_results.html"


def list_entities_management_results(provides, all_app_runs, context):
    """Setup the view for list status info"""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()
            if result_data:
                result_data = result_data[0]
                result_data["result"] = ENTITY_LIST_STATUS_VALUE_TO_LITERAL_MAPPING.get(result_data["result"])
            results.append({"param": result.get_param(), "data": result_data})

    return "views/list_entities_management_results.html"


def playbook_alert_search_results(provides, all_app_runs, context):
    """Setup the view for Playbook alerts search result"""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()
            if result_data:
                result_data = result_data[0]
                for search_result in result_data:
                    search_result["created"] = format_datetime_string(search_result["created"])
                    search_result["updated"] = format_datetime_string(search_result["updated"])
                    search_result["status"] = RF_PLAYBOOK_STATUS_MAP.get(search_result["status"], search_result["status"])
                    search_result["category_display"] = PLAYBOOK_ALERT_CATEGORY_DISPLAY_MAPPING.get(
                        search_result["category"], search_result["category"]
                    )

            results.append({"param": result.get_param(), "data": result_data})

    return "views/playbook_alert_search_results.html"


def playbook_alert_update_results(provides, all_app_runs, context):
    """Setup the view for Playbook alert update"""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()
            if result_data:
                result_data = result_data[0]
            results.append({"param": result.get_param(), "data": result_data})

    return "views/playbook_alert_update_results.html"


def playbook_alert_details_results(provides, all_app_runs, context):
    """Setup the view for Playbook alert details"""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            results.append(format_domain_abuse_details_result(result))

    return "views/playbook_alert_details_results.html"


def entity_search_results(provides, all_app_runs, context):
    """Setup the view for entity search results."""

    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()
            if result_data:
                result_data = result_data[0]
            results.append({"param": result.get_param(), "data": result_data})

    return "views/entity_search_results.html"


def links_search_results(provides, all_app_runs, context):
    """Setup the view for links search results."""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()
            if result_data:
                result_data = result_data[0]
            results.append({"param": result.get_param(), "data": result_data})
    return "views/links_search_results.html"


def detection_rule_search_results(provides, all_app_runs, context):
    """Setup the view for detection rule search results."""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()
            if result_data:
                result_data = result_data[0]
            results.append({"param": result.get_param(), "data": result_data})
    return "views/detection_rule_search_results.html"


def threat_actor_intelligence_results(provides, all_app_runs, context):
    """Setup the view for threat actor intelligence results."""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()
            if result_data:
                result_data = result_data[0]
                result_data["categories"] = [category.get("name") for category in result_data.get("categories", [])]
            results.append({"param": result.get_param(), "data": result_data})
    return "views/threat_actor_intelligence_results.html"


def threat_map_results(provides, all_app_runs, context):
    """Setup the view for threat map results."""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()
            if result_data:
                result_data = result_data[0]
                for actor in result_data.get("threatActor", []):
                    actor["categories"] = [category.get("name") for category in actor.get("categories", [])]
            results.append({"param": result.get_param(), "data": result_data})
    return "views/threat_map_results.html"


def identity_leaked_credentials_results(provides, all_app_runs, context):
    """Setup the view for leaked credentials results."""
    context["results"] = results = []

    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()

            if not result_data:
                continue

            formatted_detections = []
            for detection in result_data:
                detection_entry = {
                    "id": detection.get("id"),
                    "organization_id": detection.get("organization_id"),
                    "novel": detection.get("novel"),
                    "type": detection.get("type"),
                    "subject": detection.get("subject"),
                    "password": detection.get("password") or {},
                    "authorization_service": detection.get("authorization_service") or {},
                    "cookies": detection.get("cookies") or [],
                    "malware_family": detection.get("malware_family") or {},
                    "dump": detection.get("dump") or {},
                    "created": detection.get("created"),
                }
                formatted_detections.append(detection_entry)

            results.append(
                {
                    "param": result.get_param(),
                    "detections": formatted_detections,
                    "summary": result.get_summary(),
                }
            )

    return "views/identity_leaked_credentials_results.html"


def collective_insights_submission_results(provides, all_app_runs, context):
    """Setup the view for collective insights submission."""
    return "views/collective_insights_submission_results.html"


def fetch_analyst_notes_results(provides, all_app_runs, context):
    """Setup the view for displaying fetched analyst notes."""
    context["results"] = results = []

    for summary, action_results in all_app_runs:
        for result in action_results:
            formatted = {
                "param": result.get_param(),
                "data": result.get_data(),
                "summary": result.get_summary(),
            }
            if not formatted.get("data"):
                continue
            results.append(formatted)

    return "views/fetch_analyst_notes_results.html"
