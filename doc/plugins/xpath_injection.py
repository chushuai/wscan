#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import re
import time
import os
import json

from twebscaner.libs.base_handler import *
from twebscaner.libs.url_parse import URL
from twebscaner.libs.vulns import Vuln
from twebscaner.libs import utils
from twebscaner.libs.data import CONF
from twebscaner.libs.http import *
from twebscaner.libs.sql_tools import dbms
from twebscaner.libs.quick_match.multi_in import MultiIn
from twebscaner.libs.quick_match.multi_re import MultiRE
from twebscaner.libs.fuzzer.checkpoint import checkPointQuerystring, \
        checkPointForm, checkPointHeaders, checkPointCookie
from twebscaner.libs import severity
from twebscaner.libs.config import INVAILD_EXT
from twebscaner.libs.config import PLUGIN_TYPE

logger = logging.getLogger('plugins')

class xpath_injection(BasePlugin):

    XPATH_PATTERNS = (
        'System.Xml.XPath.XPathException:',
        'MS.Internal.Xml.',
        'Unknown error in XPath',
        'org.apache.xpath.XPath',
        'A closing bracket expected in',
        'An operand in Union Expression does not produce a node-set',
        'Cannot convert expression to a number',
        'Document Axis does not allow any context Location Steps',
        'Empty Path Expression',
        'DOMXPath::'
        'Empty Relative Location Path',
        'Empty Union Expression',
        "Expected ')' in",
        'Expected node test or name specification after axis operator',
        'Incompatible XPath key',
        'Incorrect Variable Binding',
        'libxml2 library function failed',
        'libxml2',
        'Invalid predicate',
        'Invalid expression',
        'xmlsec library function',
        'xmlsec',
        "error '80004005'",
        "A document must contain exactly one root element.",
        '<font face="Arial" size=2>Expression must evaluate to a node-set.',
        "Expected token ']'",
        "<p>msxml4.dll</font>",
        "<p>msxml3.dll</font>",

        # Put this here cause i did not know if it was a sql injection
        # This error appears when you put wierd chars in a lotus notes document
        # search ( nsf files ).
        '4005 Notes error: Query is not understandable',
    )
    _multi_in = MultiIn(XPATH_PATTERNS)

    XPATH_TEST_PAYLOADS = [
        "d'z\"0",
        # http://www.owasp.org/index.php/Testing_for_XML_Injection
        "<!--"
    ]

    def __init__(self, options={}):
        BasePlugin.__init__(self, PLUGIN_TYPE.AUDIT_PLUGIN)
        self.detect_header = options.get('detect_header', False)
        self.detect_cookie = options.get('detect_cookie', False)

    def audit(self, response, task):
        if not response.ok:
            return

        if URL(task['url']).getExtension().lower() in INVAILD_EXT:
            return

        try:
            checkPointForm(self, task, self.XPATH_TEST_PAYLOADS, False, [], self.analyze_result,
                           args = {'host':URL(task['url']).getFullDomain(), 'orig_resp':response.text})

            checkPointQuerystring(self, task, self.XPATH_TEST_PAYLOADS, False, [], self.analyze_result,
                                  args = {'host':URL(task['url']).getFullDomain(), 'orig_resp':response.text})

            if self.detect_header and checkPoint.getHeaders():
                checkPointHeaders(self, task, self.XPATH_TEST_PAYLOADS, False, [], self.analyze_result,
                                  args = {'host':URL(task['url']).getFullDomain(), 'orig_resp':response.text})

            if self.detect_cookie and checkPoint.getCookie():
                checkPointCookie(self, task, self.XPATH_TEST_PAYLOADS, False, [], self.analyze_result,
                                 args = {'host':URL(task['url']).getFullDomain(), 'orig_resp':response.text})

        except Exception, e:
            logger.error(e)

    @catch_status_code_error
    def analyze_result(self, response, task):
        orig_resp_body = response.save['args'].get('orig_resp', {})
        host = response.save['args'].get('host', '')

        xpath_error_list = self._find_xpath_error(response)
        for xpath_error in xpath_error_list:
            if xpath_error not in response.text:
                desc = '发现XPath注入， 错误描述: %s'
                desc %= xpath_error
                vul = Vuln.from_task(host, 'XPath注入', desc, severity.URGENT, 0, self.get_name(), task)
                self.submit_vuln(vul)
                break

    def _find_xpath_error(self, response):
        """
        This method searches for xpath errors in html's.
        :param response: The HTTP response object
        :return: A list of errors found on the page
        """
        res = []
        for xpath_error_match in self._multi_in.query(response.text):
            res.append(xpath_error_match)
        return res