#
# File: recordedfuture_consts.py
#
# Copyright (c) Recorded Future, Inc., 2019-2022
#
# This unpublished material is proprietary to Recorded Future.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Recorded Future.
#
# ---------------------------------------------
# Phantom Recorded Future Connector python file
# ---------------------------------------------

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
