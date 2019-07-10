#
# File: recordedfuture_consts.py
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
# ---------------------------------------------
# Phantom Recorded Future Connector python file
# ---------------------------------------------

# Define your constants here
version = '1.2.0'
buildid = '136803'


# These dicts map which path_info, which fields, what the Recorded Future
# category is called and whether to quote the entity or not.
# They are used to make the reputation/intelligence method parameterized.
# (path_info template, fields, quote parameter)
REPUTATION_MAP = {
    'ip': ('/ip/%s',
           ['entity', 'risk', 'timestamps'],
           'ip',
           False),
    'domain': ('/domain/idn:%s',
               ['entity', 'risk', 'timestamps'],
               'domain',
               False),
    'file': ('/hash/%s',
             ['entity', 'risk', 'timestamps'],
             'hash',
             False),
    'vulnerability': ('/vulnerability/%s',
                      ['entity', 'risk', 'timestamps'],
                      'vulnerability',
                      False),
    'url': ('/url/%s',
            ['entity', 'risk', 'timestamps'],
            'url',
            True),
}
INTELLIGENCE_MAP = {
    'ip': ('/ip/%s',
           ['entity', 'risk', 'timestamps', "threatLists", "intelCard",
            "metrics", "location", "relatedEntities"],
           'ip',
           False),
    'domain': ('/domain/idn:%s',
               ['entity', 'risk', 'timestamps', "threatLists",
                "intelCard", "metrics", "relatedEntities"],
               'domain',
               False),
    'file': ('/hash/%s',
             ['entity', 'risk', 'timestamps', "threatLists", "intelCard",
              "metrics", "hashAlgorithm", "relatedEntities"],
             'hash',
             False),
    'vulnerability': ('/vulnerability/%s',
                      ['entity', 'risk', 'timestamps', "threatLists",
                       "intelCard",
                       "metrics", "cvss", "nvdDescription", "relatedEntities"],
                      'vulnerability',
                      False),
    'url': ('/url/%s',
            ['entity', 'risk', 'timestamps', "metrics", "relatedEntities"],
            'url',
            True),
}
