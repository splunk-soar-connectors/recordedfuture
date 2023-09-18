**Unreleased**
* Added new actions:
    * links search - find links data in Recorded Future dataset.
    * detection rule search - download detection rules (yara, sigma, snort) into the system for provided entity.
    * threat actor intelligence - get intelligence data for threat actor.
    * threat map - get a threat map from Recorded Future.
* Change the way Playbook alerts are polled from Recorded future into the Splunk SOAR. On the first poll the creation date is used to poll the alerts and all the next poll the alert that were updated during the time period from last poll to current poll.
* Now the intelligence commands will not fail with error NotFound but will successfully finish with the message that Recorded future does not have data for that entity.
* Added a code_repo_leakage type of playbook alerts.
* Recorded Future AI Insights added to Intelligence and Alert Lookup results.
