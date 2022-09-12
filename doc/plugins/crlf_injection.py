#!/usr/bin/env python
# -*- encoding: utf-8 -*-

'''
HTTP相应拆分攻击检测
注意HTTP响应拆分不是发送两个HTTP请求，而是在参数中注入\r\n符号之后，参数中的内容直接赋值
给响应头中的location字段，这样http头部会多出一个自定义的头部，攻击者可以自己构造任意的http响应页面
date： 2015/1/21
'''

from twebscaner.libs import severity
from twebscaner.libs.base_handler import *
from twebscaner.libs.config import INVAILD_EXT
from twebscaner.libs.config import PLUGIN_TYPE
from twebscaner.libs.data import CONF
from twebscaner.libs.fuzzer.checkpoint import checkPointQuerystring, \
    checkPointForm, checkPointHeaders, checkPointCookie
from twebscaner.libs.url_parse import URL
from twebscaner.libs.vulns import Vuln

logger = logging.getLogger('plugins')

HEADER_NAME = 'vulnerable073b'
HEADER_VALUE = 'ae5cdfc6'


class crlf_injection(BasePlugin):
    HEADER_INJECTION_TESTS = ("webmap\r\n" + HEADER_NAME + ": " + HEADER_VALUE,
                              "webmap\r" + HEADER_NAME + ": " + HEADER_VALUE,
                              "webmap\n" + HEADER_NAME + ": " + HEADER_VALUE)

    def __init__(self, options={}):
        BasePlugin.__init__(self, PLUGIN_TYPE.AUDIT_PLUGIN)
        self.detect_header = False
        self.detect_cookie = False

    def audit(self, response, task):
        if not response.ok:
            return

        if URL(task['url']).getExtension().lower() in INVAILD_EXT:
            return

        try:
            checkPointForm(self, task, self.HEADER_INJECTION_TESTS, False, [], self.analyze_result,
                           args={'host': URL(task['url']).getFullDomain()})

            checkPointQuerystring(self, task, self.HEADER_INJECTION_TESTS, False, [], self.analyze_result,
                                  args={'host': URL(task['url']).getFullDomain()})

            if self.detect_header and checkPoint.getHeaders():
                checkPointHeaders(self, task, self.HEADER_INJECTION_TESTS, False, CONF.DETECT_HEADERS,
                                  self.analyze_result,
                                  args={'host': URL(task['url']).getFullDomain()})

            if self.detect_cookie and checkPoint.getCookie():
                checkPointCookie(self, task, self.HEADER_INJECTION_TESTS, False, [], self.analyze_result,
                                 args={'host': URL(task['url']).getFullDomain()})

        except Exception as e:
            logger.error(e)

    @catch_status_code_error
    def analyze_result(self, response, task):
        for header, value in response.headers.items():
            if HEADER_NAME in header and value.lower() == HEADER_VALUE:
                host = response.save['args'].get('host', '')
                desc = '发现CRLF漏洞，添加响应头 %s: %s ' % (header, value)
                vul = Vuln.from_task(host, 'CRLF注入', desc, severity.URGENT, 0, self.get_name(), task)
                self.submit_vuln(vul)

            elif HEADER_NAME in header and value.lower() != HEADER_VALUE:
                return False

            elif HEADER_NAME in value.lower():
                return False