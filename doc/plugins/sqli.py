#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import re
import time
import os
import json
import urlparse
import urllib

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
        checkPointForm, checkPointHeaders, checkPointCookie,checkPointJson
from twebscaner.libs import severity
from twebscaner.libs.config import INVAILD_EXT, PLUGIN_TYPE

logger = logging.getLogger('plugins')

class sqli(BasePlugin):

    SQL_ERRORS_STR = (
        # ASP / MSSQL
        (r'System.Data.OleDb.OleDbException', dbms.MSSQL),
        (r'[SQL Server]', dbms.MSSQL),
        (r'[Microsoft][ODBC SQL Server Driver]', dbms.MSSQL),
        (r'[SQLServer JDBC Driver]', dbms.MSSQL),
        (r'[SqlException', dbms.MSSQL),
        (r'System.Data.SqlClient.SqlException', dbms.MSSQL),
        (r'Unclosed quotation mark after the character string', dbms.MSSQL),
        (r"'80040e14'", dbms.MSSQL),
        (r'mssql_query()', dbms.MSSQL),
        (r'odbc_exec()', dbms.MSSQL),
        (r'Microsoft OLE DB Provider for ODBC Drivers', dbms.MSSQL),
        (r'Microsoft OLE DB Provider for SQL Server', dbms.MSSQL),
        (r'Incorrect syntax near', dbms.MSSQL),
        (r'Sintaxis incorrecta cerca de', dbms.MSSQL),
        (r'Syntax error in string in query expression', dbms.MSSQL),
        (r'ADODB.Field (0x800A0BCD)<br>', dbms.MSSQL),
        (r"ADODB.Recordset'", dbms.MSSQL),
        (r"Unclosed quotation mark before the character string", dbms.MSSQL),
        (r"'80040e07'", dbms.MSSQL),
        (r'Microsoft SQL Native Client error', dbms.MSSQL),
        (r'SQL Server Native Client', dbms.MSSQL),
        (r'Invalid SQL statement', dbms.MSSQL),

        # DB2
        (r'SQLCODE', dbms.DB2),
        (r'DB2 SQL error:', dbms.DB2),
        (r'SQLSTATE', dbms.DB2),
        (r'[CLI Driver]', dbms.DB2),
        (r'[DB2/6000]', dbms.DB2),

        # Sybase
        (r"Sybase message:", dbms.SYBASE),
        (r"Sybase Driver", dbms.SYBASE),
        (r"[SYBASE]", dbms.SYBASE),

        # Access
        (r'Syntax error in query expression', dbms.ACCESS),
        (r'Data type mismatch in criteria expression.', dbms.ACCESS),
        (r'Microsoft JET Database Engine', dbms.ACCESS),
        (r'[Microsoft][ODBC Microsoft Access Driver]', dbms.ACCESS),

        # ORACLE
        (r'Microsoft OLE DB Provider for Oracle', dbms.ORACLE),
        (r'wrong number or types', dbms.ORACLE),

        # POSTGRE
        (r'PostgreSQL query failed:', dbms.POSTGRE),
        (r'supplied argument is not a valid PostgreSQL result', dbms.POSTGRE),
        (r'unterminated quoted string at or near', dbms.POSTGRE),
        (r'pg_query() [:', dbms.POSTGRE),
        (r'pg_exec() [:', dbms.POSTGRE),

        # MYSQL
        (r'supplied argument is not a valid MySQL', dbms.MYSQL),
        (r'Column count doesn\'t match value count at row', dbms.MYSQL),
        (r'mysql_fetch_array()', dbms.MYSQL),
        (r'on MySQL result index', dbms.MYSQL),
        (r'You have an error in your SQL syntax;', dbms.MYSQL),
        (r'You have an error in your SQL syntax near', dbms.MYSQL),
        (r'MySQL server version for the right syntax to use', dbms.MYSQL),
        (r'Division by zero in', dbms.MYSQL),
        (r'not a valid MySQL result', dbms.MYSQL),
        (r'[MySQL][ODBC', dbms.MYSQL),
        (r"Column count doesn't match", dbms.MYSQL),
        (r"the used select statements have different number of columns",
            dbms.MYSQL),
        (r"DBD::mysql::st execute failed", dbms.MYSQL),
        (r"DBD::mysql::db do failed:", dbms.MYSQL),

        # Informix
        (r'com.informix.jdbc', dbms.INFORMIX),
        (r'Dynamic Page Generation Error:', dbms.INFORMIX),
        (r'An illegal character has been found in the statement',
            dbms.INFORMIX),
        (r'[Informix]', dbms.INFORMIX),
        (r'<b>Warning</b>:  ibase_', dbms.INTERBASE),
        (r'Dynamic SQL Error', dbms.INTERBASE),

        # DML
        (r'[DM_QUERY_E_SYNTAX]', dbms.DMLDATABASE),
        (r'has occurred in the vicinity of:', dbms.DMLDATABASE),
        (r'A Parser Error (syntax error)', dbms.DMLDATABASE),

        # Java
        (r'java.sql.SQLException', dbms.JAVA),
        (r'Unexpected end of command in statement', dbms.JAVA),

        # Coldfusion
        (r'[Macromedia][SQLServer JDBC Driver]', dbms.MSSQL),

        # SQLite
        (r'could not prepare statement', dbms.SQLITE),

        # Generic errors..
        (r'Unknown column', dbms.UNKNOWN),
        (r'where clause', dbms.UNKNOWN),
        (r'SqlServer', dbms.UNKNOWN),
        (r'syntax error', dbms.UNKNOWN),
        (r'Microsoft OLE DB Provider', dbms.UNKNOWN),
    )
    _multi_in = MultiIn(x[0] for x in SQL_ERRORS_STR)

    SQL_ERRORS_RE = (
        # ASP / MSSQL
        (r"Procedure '[^']+' requires parameter '[^']+'", dbms.MSSQL),
        # ORACLE
        (r'PLS-[0-9][0-9][0-9][0-9]', dbms.ORACLE),
        (r'ORA-[0-9][0-9][0-9][0-9]', dbms.ORACLE),
        # MYSQL
        (r"Table '[^']+' doesn't exist", dbms.MYSQL),
        # Generic errors..
        (r'MySqlException \(0x', dbms.UNKNOWN),
        (r'Warning.*mysql_.*', dbms.UNKNOWN),
        (r'SQL syntax.*MySQL', dbms.MYSQL),
        (r'valid MySQL result', dbms.MYSQL),
        (r'check the manual that corresponds to your (MySQL|MariaDB) server version', dbms.MYSQL),
        (r'com\.mysql\.jdbc\.exceptions', dbms.MYSQL)
    )
    _multi_re = MultiRE(SQL_ERRORS_RE, re.I | re.S)

    # Note that these payloads are similar but they do generate different errors
    # depending on the SQL query context they are used. Removing one or the
    # other will lower our SQLMap testenv coverage
    SQLI_STRINGS = (u"a'b\"c'd\"",
                    u"1'2\"3",
                    urllib.unquote('%df%5c%27'),
                    u'Type001001031')

    SQLI_MESSAGE = (u'A SQL error was found in the response supplied by '
                    u'the web application, the error is (only a fragment is '
                    u'shown): "%s". The error was found on response with id'
                    u' %s.')

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
            checkPointForm(self, task, self.SQLI_STRINGS, False, [], self.analyze_result,
                           args = {'host':URL(task['url']).getFullDomain(), 'orig_resp':response.text})

            checkPointJson(self, task, self.SQLI_STRINGS, False, [], self.analyze_result,
                           args = {'host':URL(task['url']).getFullDomain(), 'orig_resp':response.text})

            checkPointQuerystring(self, task, self.SQLI_STRINGS, False, [], self.analyze_result,
                                  args = {'host':URL(task['url']).getFullDomain(), 'orig_resp':response.text})

            if self.detect_header and checkPoint.getHeaders():
                checkPointHeaders(self, task, self.SQLI_STRINGS, False, [], self.analyze_result,
                                  args = {'host':URL(task['url']).getFullDomain(), 'orig_resp':response.text})

            if self.detect_cookie and checkPoint.getCookie():
                checkPointCookie(self, task, self.SQLI_STRINGS, False, [], self.analyze_result,
                                 args = {'host':URL(task['url']).getFullDomain(), 'orig_resp':response.text})

        except Exception, e:
            import traceback
            traceback.print_exc()
            logger.error(e)

    @catch_status_code_error
    def analyze_result(self, response, task):

        sql_error_list = self._findsql_error(response)
        orig_resp_body = response.save['args'].get('orig_resp', {})
        host = response.save['args'].get('host', '')
        for sql_error_string, dbms_type in sql_error_list:
            if sql_error_string not in orig_resp_body:
                desc = '发现SQL注入漏洞，数据库类型: %s 错误描述: %s'
                desc %= dbms_type, sql_error_string
                vul = Vuln.from_task(host, 'SQL注入', desc, severity.URGENT, 0, self.get_name(), task)
                self.submit_vuln(vul)
                break

    def _findsql_error(self, response):
        res = []

        for match in self._multi_in.query(response.text):
            dbms_type = [x[1] for x in self.SQL_ERRORS_STR if x[0] == match][0]
            res.append((match, dbms_type))

        for match, _, regex_comp, dbms_type in self._multi_re.query(response.text):
            res.append((match.group(0), dbms_type))

        return res