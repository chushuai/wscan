#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from twebscaner.libs import severity
from twebscaner.libs.base_handler import *
from twebscaner.libs.config import INVAILD_EXT, PLUGIN_TYPE
from twebscaner.libs.context.context import get_context_iter
from twebscaner.libs.fuzzer import checkpoint
from twebscaner.libs.fuzzer.fuzzer import createMutants, createRandAlNum
from twebscaner.libs.url_parse import URL
from twebscaner.libs.vulns import Vuln

logger = logging.getLogger('plugins')

RANDOMIZE = 'RANDOMIZE'


class xss(BasePlugin):
    PAYLOADS = [
        # Start a new tag
        '<',

        # Escape HTML comments
        '-->',

        # Escape JavaScript multi line and CSS comments
        '*/',

        # Escapes for CSS
        '*/:("\'',

        # The ":" is useful in cases where we want to add the javascript
        # protocol like <a href="PAYLOAD">   -->   <a href="javascript:alert()">
        ':',

        # Escape single line comments in JavaScript
        "\n",

        # Escape the HTML attribute value string delimiter
        '"',
        "'",
        "`",

        # Escape HTML attribute values without string delimiters
        " =",
    ]
    PAYLOADS = ['%s%s%s' % (RANDOMIZE, p, RANDOMIZE) for p in PAYLOADS]

    def __init__(self, options={}):
        BasePlugin.__init__(self, PLUGIN_TYPE.AUDIT_PLUGIN)

    def audit(self, response, task):

        if not response.ok:
            return

        if URL(task['url']).getExtension().lower() in INVAILD_EXT:
            return

        dummy = ['', ]

        mutants = []
        qs = checkpoint.getQs(task)
        if qs:
            mutants += createMutants(qs, dummy, False)

        form = checkpoint.getForm(task)
        if form:
            mutants += createMutants(form, dummy, False)

        for mutant in mutants:
            payload = replace_randomize(''.join(self.PAYLOADS))
            mutant.setModValue(payload)
            checkpoint.sendMutant(self, task, mutant, self._identify_trivial_xss,
                                  args={'mutant': mutant, 'orig_resp': response.text})

    @catch_status_code_error
    def _identify_trivial_xss(self, response, task):
        mutant = response.save['args']['mutant']
        payload = mutant.getModifyValue()

        headers = dict(response.headers.items())
        ct_options = headers.get('X-Content-Type-Options', None)
        content_type = headers.get('Content-Type', None)

        if content_type == 'application/json' and ct_options == 'nosniff':
            # No luck exploiting this JSON XSS
            return False

        if payload in response.text.lower():
            description = '发现XSS漏洞, 内容描述:%s' % mutant.description()
            vul = Vuln.from_task(URL(task['url']).getFullDomain(), '跨站脚本攻击', description, severity.HIGH, 0,
                                 self.get_name(), task)
            self.submit_vuln(vul)
            return

        orig_resp = response.save['args']['orig_resp']
        xss_strings = [replace_randomize(i) for i in self.PAYLOADS]

        for xss_string in xss_strings:
            xss_mutant = mutant.copy()
            xss_mutant.setModValue(xss_string)
            checkpoint.sendMutant(self, task, xss_mutant, self._analyze_echo_result,
                                  args={'host': URL(task['url']).getFullDomain(), 'mutant': xss_mutant,
                                        'orig_resp': orig_resp})

    @catch_status_code_error
    def _analyze_echo_result(self, response, task):
        mutant = response.save['args']['mutant']
        sent_payload = mutant.getModifyValue()

        # TODO: https://github.com/andresriancho/w3af/issues/12305
        body_lower = response.text.lower()
        sent_payload_lower = sent_payload.lower()

        for context in get_context_iter(body_lower, sent_payload_lower):
            if context.is_executable() or context.can_break():
                description = '发现XSS漏洞, 内容描述:%s' % mutant.description()
                vul = Vuln.from_task(URL(task['url']).getFullDomain(), '跨站脚本攻击', description, severity.HIGH, 0,
                                     self.get_name(), task)
                self.submit_vuln(vul)
                return


def replace_randomize(data):
    rand_str = createRandAlNum(5).lower()
    return data.replace(RANDOMIZE, rand_str)