# RELEASE NOTES

## VERSION 2.0

This version uses Recorded Future's new SOAR API when performing the reputation
actions. This API is designed for much higher volume of calls.

A new configuration option has been added to disable SSL certificate verification.
This is sometimes needed when access to Internet is through a proxy.

### Upgrading

In most cases no manual action is required.

## VERSION 1.2

This version is a complete re-write of the app. It is not backwards compatible
with previous versions.

### Upgrading

When upgrading from a previous version of the app it will be necessary to do
the following steps for each playbook that uses the app:

1. Verify that the asset configuration is still valid.
1. Determine if it is still possible to use "ip reputation", "file reputation",
   or "domain reputation" or if it necessary to switch to the corresponding
   "intelligence" action. To switch or not depends on what results are
   used.
1. Adapt any component that uses data from an action in the app. Most JSON
   paths have changed.

### Changed Actions

1. **ip reputation**: the action returns a smaller set of information 
   compared to previous versions. The new action "ip intelligence" returns
   a similar set of information as the previous version, the format is
   changed however.
1. **domain reputation**: the action returns a smaller set of information 
   compared to previous versions. The new action "domain intelligence" returns
   a similar set of information as the previous version, the format is
   changed however.
1. **file reputation**: the action returns a smaller set of information 
   compared to previous versions. The new action "file intelligence" returns
   a similar set of information as the previous version, the format is
   changed however.
1. **lookup vulnerability**: the action as been renamed to 
   **vulnerability reputation**. It returns a smaller set of information 
   compared to previous versions. The new action "vulnerability intelligence" 
   returns a similar set of information as the previous version, the format is
   changed however.


### New Actions

1. **ip intelligence**: get an extensive context for the given IP number. 
   Full Risk information, Related Entities, Metrics, Threat Lists and 
   Timestamps are provided.
1. **domain intelligence**: get an extensive context for the given domain.
   Full Risk information, Related Entities, Metrics, Threat Lists and 
   Timestamps are provided.
1. **file intelligence**: get an extensive context for the given file hash.
   Full Risk information, Related Entities, Metrics, Threat Lists, Hash
   Algorithm and Timestamps are provided.
1. **vulnerability intelligence**: get an extensive context for the given
   vulnerability (ex CVE id).
   Full Risk information, Related Entities, Metrics, Threat Lists, CVSS 
   data, NVD Description and Timestamps are provided.
1. **url intelligence**: get an extensive context for the given url.
   Full Risk information, Related Entities, Metrics and Timestamps is 
   provided.
1. **url reputation**: get reputation information for an URL.
1. **alert rule lookup**: search for Alert Rule Ids by Rule Name.
1. **alert data lookup**: fetch all information about Recorded Future Alerts 
   triggered for an Alert Rule Id and a time range.
