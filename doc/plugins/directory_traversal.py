#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import os
import re

from twebscaner.libs import severity
from twebscaner.libs.base_handler import *
from twebscaner.libs.check import getCachedRules
from twebscaner.libs.config import INVAILD_EXT
from twebscaner.libs.config import PLUGIN_TYPE
from twebscaner.libs.fuzzer.checkpoint import checkPointQuerystring, \
    checkPointForm, checkPointHeaders, checkPointCookie
from twebscaner.libs.url_parse import URL
from twebscaner.libs.vulns import Vuln

logger = logging.getLogger('plugins')

FILE_INCLUDE_XML_DB = os.path.join(os.getcwd(), 'data', 'sensitive', 'file_include.xml')


class directory_traversal(BasePlugin):

    def __init__(self, options={}):
        BasePlugin.__init__(self, PLUGIN_TYPE.AUDIT_PLUGIN)
        self.detect_header = False
        self.detect_cookie = False
        self.check_rules = self.load_rule()

    def load_rule(self):
        rules = getCachedRules(common=FILE_INCLUDE_XML_DB)
        for item in rules:
            if item == 'FI':
                rule_list = []
                for rule in rules['FI']['']:
                    rule_list.append(rule)

                rules['FI'][''] = rule_list
            else:
                for vector in rules[item]:
                    rules[item][vector] = rules[item][vector]

        nop = []
        for item in rules:
            if len(rules[item]) == 0:
                nop.append(item)

        for i in nop:
            rules.pop(i)
        return rules

    def audit(self, response, task):
        if not response.ok:
            return

        if URL(task['url']).getExtension().lower() in INVAILD_EXT:
            return

        for item in self.check_rules:  # FI/LFI/RFI
            for payload in self.check_rules[item]:
                payload = payload
                regex = self.check_rules[item][payload]
                try:
                    checkPointForm(self, task, [payload], False, [], self.analyze_result,
                                   args={'host': URL(task['url']).getFullDomain(), 'payload': payload, 'regex': regex})

                    checkPointQuerystring(self, task, [payload], False, [], self.analyze_result,
                                          args={'host': URL(task['url']).getFullDomain(), 'payload': payload,
                                                'regex': regex})

                    if self.detect_header and checkPoint.getHeaders():
                        checkPointHeaders(self, task, [payload], False, [], self.analyze_result,
                                          args={'host': URL(task['url']).getFullDomain(), 'payload': payload,
                                                'regex': regex})

                    if self.detect_cookie and checkPoint.getCookie():
                        checkPointCookie(self, task, [payload], False, [], self.analyze_result,
                                         args={'host': URL(task['url']).getFullDomain(), 'payload': payload,
                                               'regex': regex})

                except Exception as e:
                    logger.error(e)

    @catch_status_code_error
    def analyze_result(self, response, task):
        payload = response.save['args'].get('payload', '')
        regex = response.save['args'].get('regex', '')
        host = response.save['args'].get('host', '')
        vul = False
        match = None
        if payload == '':
            for r in regex:
                match = re.findall(r, response.text, re.I)
                if match:
                    vul = True
                    break
        else:
            match = re.findall(regex, response.text, re.I)
            if match:
                vul = True

        if vul:
            desc = '发现目录穿越漏洞，匹配内容%s' % match[0]
            vuln = Vuln.from_task(host, '目录穿越', desc, severity.URGENT, 0, self.get_name(), task)
            self.submit_vuln(vuln)

    def _findsql_error(self, response):
        res = []

        for match in self._multi_in.query(response.text):
            dbms_type = [x[1] for x in self.SQL_ERRORS_STR if x[0] == match][0]
            res.append((match, dbms_type))

        for match, _, regex_comp, dbms_type in self._multi_re.query(response.text):
            res.append((match.group(0), dbms_type))

        return res