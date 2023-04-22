# coding: utf-8

import os
import re

from twebscaner.libs.base_handler import *
from twebscaner.libs.config import INVAILD_EXT
from twebscaner.libs.config import PLUGIN_TYPE
from twebscaner.libs.function import get_rules, getCompiledRegex
from twebscaner.libs.url_parse import URL
from twebscaner.libs.vulns import Vuln
from twebscaner.libs.xmlobject import XMLFile

CONTENT_XML_DB = os.path.join(os.getcwd(), 'data', 'sensitive', 'content_parse_rules.xml')

logger = logging.getLogger('plugins')


class info_disclosure(BasePlugin):

    def __init__(self, options={}):
        BasePlugin.__init__(self, PLUGIN_TYPE.AUDIT_PLUGIN)
        self.content_xmlobject = XMLFile(path=CONTENT_XML_DB)
        self.detect_rules = get_rules(self.content_xmlobject, 'all')
        self.detect_url = []

    def audit(self, response, task):

        if URL(task['url']).getExtension().lower() in INVAILD_EXT:
            return

        self.detect_sensitive_infomation(response, task)

    @catch_status_code_error
    def detect_sensitive_infomation(self, response, task):
        body = response.text
        host = URL(task['url']).getFullDomain()

        #
        if not response.is_text_or_html() or len(body) > 100 * 1024:
            return

        for check_rule in self.detect_rules:

            info_list = []
            rules_name = check_rule['rules_name']
            rules_name_zh = check_rule['name_zh']
            rules_risk = check_rule['risk']
            description = check_rule['desc']
            solution = check_rule['solution']
            for i in check_rule['regx']:
                regx = i['cdata'].encode('utf-8')
                httpcode = i['httpcode']
                value = i['value']

                if str(response.status_code) in httpcode or httpcode == 'all':
                    match = getCompiledRegex(regx, re.I).findall(body)
                    match = list(set(match))
                    for info in match:
                        desc = '发现%s, url地址:%s, 敏感内容:%s' % (rules_name_zh, task['url'], str(info))
                        vul = Vuln.from_task(host, rules_name_zh, desc, rules_risk, 0, rules_name, task)
                        vul.set_headers(task['fetch'].get('headers', {}))
                        self.submit_vuln(vul)

    def get_check_urls(self, task):

        check_url = []
        check_dirs = URL(task['url']).getDirectories()
        check_file = URL(task['url']).getFullPath()

        if task['fetch'].get('method', 'GET') == 'GET' and not task['fetch'].get('data', None):
            if check_file not in self.detect_url:
                self.detect_url.append(check_file)
        else:
            if check_file not in self.detect_url:
                self.detect_url.append(check_file)
                check_url.append(check_file)
        for dir in check_dirs:
            if dir not in self.detect_url:
                self.detect_url.append(dir)
                check_url.append(dir)
        return check_url

    def end(self):
        self.detect_url = []
