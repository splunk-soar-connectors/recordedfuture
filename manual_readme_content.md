[comment]: # " File: README.md"
[comment]: # ""
[comment]: # "Copyright (c) Recorded Future, Inc, 2019-2024"
[comment]: # ""
[comment]: # "This unpublished material is proprietary to Recorded Future. All"
[comment]: # "rights reserved. The methods and techniques described herein are"
[comment]: # "considered trade secrets and/or confidential. Reproduction or"
[comment]: # "distribution, in whole or in part, is forbidden except by express"
[comment]: # "written permission of Recorded Future."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
Recorded Future App for Phantom allows clients to work smarter, respond faster, and strengthen their
defenses through automation and orchestration. The Recorded Future App provides a number of actions
that enable the creation of Playbooks to do automated enrichment, correlation, threat hunting, and
alert handling.

# Ingest alerts into events

With alerting rules set up in your Recorded Future enterprise, triggered alerts can now be ingested
in Splunk SOAR as events.The ingestion configuration is set per asset under the tabs "Asset
Settings" and "Ingest Settings".

"Asset Settings" defines a list of rule IDs, what severity to apply to the new events and set the
limits for the number of events created by the ingestion.

<img src="img/recorded_future_asset_settings.png" style="{border-style: solid;}" />

The scheduling of the ingestion is set under "Ingest Settings"

![](img/recorded_future_asset_ingest.png)
