# File: recordedfuture_consts.py
#
# Copyright (c) Recorded Future, Inc, 2019-2023
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

# Define your constants here
version = '4.0.1'
buildid = '306'

# timeout for our http requests to bfi_phantom
timeout = 63
MAX_CONTAINERS = 100

# These dicts map which path_info, which fields, what the Recorded Future
# category is called and whether to quote the entity or not.
# They are used to make the reputation/intelligence method parameterized.
# (path_info template, fields, quote parameter)

INTELLIGENCE_MAP = {
    'ip': (
        '/ip/%s',
        [
            'entity',
            'risk',
            'timestamps',
            "threatLists",
            "intelCard",
            "metrics",
            "location",
            "relatedEntities",
        ],
        'ip',
        False,
    ),
    'domain': (
        '/domain/idn:%s',
        [
            'entity',
            'risk',
            'timestamps',
            "threatLists",
            "intelCard",
            "metrics",
            "relatedEntities",
        ],
        'domain',
        False,
    ),
    'file': (
        '/hash/%s',
        [
            'entity',
            'risk',
            'timestamps',
            "threatLists",
            "intelCard",
            "metrics",
            "hashAlgorithm",
            "relatedEntities",
        ],
        'hash',
        False,
    ),
    'vulnerability': (
        '/vulnerability/%s',
        [
            'entity',
            'risk',
            'timestamps',
            "threatLists",
            "intelCard",
            "metrics",
            "cvss",
            "nvdDescription",
            "relatedEntities",
        ],
        'vulnerability',
        False,
    ),
    'url': (
        '/url/%s',
        ['entity', 'risk', 'timestamps', "metrics", "relatedEntities"],
        'url',
        True,
    ),
}
RF_STATE_FILE_CORRUPT_ERR = (
    "Error occurred while loading the state file due to its unexpected format. "
    "Resetting the state file with the default format. Please try again."
)
