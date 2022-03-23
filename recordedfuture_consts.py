# File: recordedfuture_consts.py
#
# Copyright (c) Recorded Future, Inc., 2019-2022
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
version = '3.1.0'
buildid = '264'

# timeout for our http requests to bfi_phantom
timeout = 33

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
