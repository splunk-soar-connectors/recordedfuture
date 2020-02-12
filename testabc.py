#!/usr/bin/env python
#coding=utf-8

from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.acs_exception.exceptions import ClientException
from aliyunsdkcore.acs_exception.exceptions import ServerException
from aliyunsdkram.request.v20150501.ListGroupsRequest import ListGroupsRequest
from aliyunsdkram.request.v20150501.ListRolesRequest import ListRolesRequest

client = AcsClient('LTAIaBIOsKZWH1Ml', 'XCFshaAEgBIt4KeeQBwpGiP8Twcq3K', 'cn-hangzhou')

request = ListRolesRequest()
request.set_accept_format('json')

response = client.do_action_with_exception(request)
print type(response)
# python2:  print(response) 
print str(response)
