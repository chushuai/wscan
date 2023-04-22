#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import os
import re

from twebscaner.libs import severity
from twebscaner.libs.base_handler import *
from twebscaner.libs.config import PLUGIN_TYPE
from twebscaner.libs.duplication import directories_duplication
from twebscaner.libs.exception import appDataException, appBaseException
from twebscaner.libs.fuzzer.fuzzer import createRandNum, createRandAlpha
from twebscaner.libs.page_fingerprint import is_404
from twebscaner.libs.url_parse import URL
from twebscaner.libs.vulns import Vuln

logger = logging.getLogger('plugins')


class background_disclosure(BasePlugin):
    ADMIN_DIRS = ['admin', 'adm', 'login', 'system', 'manage']

    def __init__(self, options={}):
        BasePlugin.__init__(self, PLUGIN_TYPE.AUDIT_PLUGIN)
        self.analyzed_dirs = []
        self.analyzed_url = []
        self.duplication_dir = {}
        self.check_rule = []
        self.rand_dirname = createRandNum(5)
        self.rand_filename = createRandAlpha(5)

        self.load_background_db()

    def load_background_db(self):
        try:
            db_file = os.path.join(os.getcwd(), 'data', 'background', 'background.db')
            db_file_1 = open(db_file, "r")
        except Exception as e:
            raise appBaseException('Failed to open the scan databases. Exception: "' + str(e) + '".')
        else:

            # Put all the tests in a list
            test_list = db_file_1.readlines()
            # Close the files
            db_file_1.close()
            lines = 0
            if not self.check_rule:
                for line in test_list:
                    if not self.is_comment(line):
                        # This is a sample scan_database.db line :
                        # "apache","/docs/","200","GET","May give list of installed software"
                        to_send = self.parse(line)

                        lines += 1

                        # A line could generate more than one request...
                        # (think about @CGIDIRS)
                        for parameters in to_send:
                            self.check_rule.append(parameters)

            logger.debug('load %d background rules.' % lines)

    def is_comment(self, line):
        if line[0] == '"':
            return False
        return True

    def parse(self, line):
        splitted_line = line.split('","')

        server = splitted_line[0].replace('"', '')
        original_query = splitted_line[1].replace('"', '')
        expected_response = splitted_line[2].replace('"', '')
        http_code = splitted_line[3].replace('"', '')
        position = int(splitted_line[4].replace('"', ''))
        desc = splitted_line[5].replace('"', '')
        desc = desc.replace('\\n', '')
        desc = desc.replace('\\r', '')

        if original_query.count(' '):
            return []
        else:
            to_send = []
            to_send.append((server, original_query, expected_response, http_code, position, desc))

            to_mutate = []
            to_mutate.append(original_query)

            to_mutate2 = []
            for query in to_mutate:
                if query.count('@ADMINDIRS'):
                    for adminDir in self.ADMIN_DIRS:
                        query2 = query.replace('@ADMINDIRS', adminDir)
                        to_send.append((server, query2, expected_response, http_code, position, desc))
                        to_mutate2.append(query2)
                    to_mutate.remove(query)
                    to_send.remove((server, query, expected_response, http_code, position, desc))
            to_mutate.extend(to_mutate2)

            return to_send

    def audit(self, response, task):
        detect_path = []
        for directory in URL(task['url']).getDirectories():
            if directory not in self.analyzed_dirs:
                # 框架去重
                isdup, dir = directories_duplication(directory.url_string)
                if isdup:
                    if self.duplication_dir.has_key(dir):
                        self.duplication_dir[dir] += 1
                    else:
                        self.duplication_dir[dir] = 0
                    if self.duplication_dir[dir] > 5:
                        continue

                # Save the domain_path so I know I'm not working in vane
                self.analyzed_dirs.append(directory)
                detect_path.append(directory)

        for rule in self.check_rule:
            for domain_path in detect_path:
                (server, query, regx, httpcode, position, desc) = rule
                check_url = domain_path.urlJoin(query)

                if check_url not in self.analyzed_url:
                    self.analyzed_url.append(check_url)

                    paramers = {'dir': domain_path.url_string, 'rule': rule}
                    self.crawl(check_url.url_string, callback=self.detect_file_disclosure, validate_cert=False,
                               save=paramers)

    def detect_file_disclosure(self, response, task):
        try:
            paramers = response.save
            rule = paramers['rule']
            dir = paramers['dir']
            host = URL(task['url']).getFullDomain()
            code = response.status_code
            verify_vul = paramers.get('verify_vul', True)

            (server, query, regx, httpcode, position, desc) = rule

            if not response.url.startswith(response.orig_url):
                ##当做服务端跳转处理
                raise appDataException()

            # 判断是否存在浏览器跳转
            if re.search('(window\.location|location\.).*', response.text):
                raise appDataException()

            if is_404(response.text):
                raise appDataException()

            if str(code) not in httpcode and httpcode != 'all':
                raise appDataException()

            match = False
            if regx != '' and regx != 'None':
                if position == 0:
                    title = re.findall('<title>(.*?)</title>', response.text)
                    if title:
                        match = re.search(regx, title[0], re.I | re.S)
                    else:
                        match = False
                else:
                    match = re.search(regx, response.text, re.I | re.S)

            if not match:
                raise appDataException()

            if match and verify_vul:
                print(task['url'])
                paramers['verify_vul'] = False
                paramers['detect_url'] = task['url']

                second_check_url = ''
                if query.endswith('/'):
                    # 验证目录
                    second_check_url = URL(dir).urlJoin(self.rand_dirname + '/')
                    print(second_check_url.url_string)
                    self.crawl(second_check_url.url_string, callback=self.detect_file_disclosure, validate_cert=False,
                               save=paramers)

                else:
                    # 生成随机文件
                    second_check_url = URL(task['url']).urlJoin(
                        self.rand_filename + '.' + URL(task['url']).getExtension())
                    print(second_check_url.url_string)
                    self.crawl(second_check_url.url_string, callback=self.detect_file_disclosure, validate_cert=False,
                               save=paramers)

        except appDataException as e:
            if not verify_vul:
                detect_url = paramers['detect_url']
                desc = '发现后台管理地址，类型: %s 地址: %s 检测目录: %s' % (server, detect_url, dir)
                vul = Vuln(host, '后台管理地址泄露', desc, severity.MEDIUM, 0, self.get_name())
                vul.set_method('GET')
                vul.set_url(detect_url)
                vul.set_payload(query)
                vul.set_headers(task['fetch'].get('headers', {}))
                self.submit_vuln(vul)

        except Exception as e:
            logger.error(e)

    def end(self):
        self.analyzed_dirs = []
        self.analyzed_url = []
        self.duplication_dir = {}