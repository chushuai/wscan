#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import re
import time

from twebscaner.libs import severity
from twebscaner.libs.base_handler import *
from twebscaner.libs.config import PLUGIN_TYPE
from twebscaner.libs.diff.diff import diff
from twebscaner.libs.diff.fuzzy_string_cmp import fuzzy_equal
from twebscaner.libs.fuzzer import checkpoint
from twebscaner.libs.fuzzer.fuzzer import createMutants, createRandNum
from twebscaner.libs.url_parse import URL
from twebscaner.libs.vulns import Vuln

logger = logging.getLogger('plugins')


class blindsql(BasePlugin):

    def __init__(self, options={}):
        BasePlugin.__init__(self, PLUGIN_TYPE.AUDIT_PLUGIN)
        self.equal_algorithm = 'setIntersection'
        self.equal_limit = 0.95

    def audit(self, response, task):

        dummy = ['', ]

        mutants = []
        qs = checkpoint.getQs(task)
        if qs:
            mutants += createMutants(qs, dummy, False)

        form = checkpoint.getForm(task)
        if form:
            mutants += createMutants(form, dummy, False)

        for mutant in mutants:
            val = ''
            if mutant.getOriginalValue() == '':
                rnd_num = str(createRandNum(2, []))
                mutant.setModValue(rnd_num)
                val = rnd_num
                checkpoint.sendMutant(self, task, mutant, self.analyze_orig_status, args={'mutant': mutant})
            else:
                val = mutant.getOriginalValue()
                self.find_sql(task, response, mutant, val)

    @catch_status_code_error
    def analyze_orig_status(self, response, task):
        mutant = response.save['args']['mutant']
        val = mutant.getModValue()
        self.find_sql(task, response, mutant, val)

    def find_sql(self, task, response, mutant, val):
        statements = self._get_statements(val)
        for statement_type in statements:
            for statementTuple in statements[statement_type]:
                true_mutant = mutant.copy()
                true_mutant.setModValue(statementTuple[0])
                false_mutant = mutant.copy()
                false_mutant.setModValue(statementTuple[1])
                checkpoint.sendMutant(self, task, true_mutant, self.analyze_true_status,
                                      args={'orig_response': response.text, 'false_mutant': false_mutant,
                                            'description': true_mutant.description()})

    @catch_status_code_error
    def analyze_true_status(self, response, task):
        orig_response = response.save['args']['orig_response']
        false_mutant = response.save['args']['false_mutant']

        if self.equal_with_limit(response.text, orig_response):
            description = response.save['args']['description']
            checkpoint.sendMutant(self, task, false_mutant, self.analyze_false_status,
                                  args={'true_response': response.text, 'description': description})

    @catch_status_code_error
    def analyze_false_status(self, response, task):
        true_response = response.save['args']['true_response']
        if not self.equal_with_limit(response.text, true_response):
            description = response.save['args']['description']
            vul = Vuln.from_task(URL(task['url']).getFullDomain(), 'SQL盲注', description, severity.URGENT, 0,
                                 self.get_name(), task)
            self.submit_vuln(vul)

    def _get_statements(self, oval, excludeNumbers=[]):
        res = {}

        rndNum = int(createRandNum(2, excludeNumbers))
        rndNum = rndNum + 5379
        rndNumPlusOne = rndNum + 1

        a = oval.strip()
        if a.isdigit():
            res['numeric'] = []
            trueStm = oval + ' AND %i=%i ' % (rndNum, rndNum)
            falseStm = oval + ' AND %i=%i ' % (rndNum, rndNumPlusOne)
            res['numeric'].append((trueStm, falseStm))

            return res

            trueStm = oval + ') AND %i=%i ' % (rndNum, rndNum)
            falseStm = oval + ') AND %i=%i ' % (rndNum, rndNumPlusOne)
            res['numeric'].append((trueStm, falseStm))

            trueStm = oval + ' AND %i=%i --' % (rndNum, rndNum)
            falseStm = oval + ' AND %i=%i --' % (rndNum, rndNumPlusOne)
            res['numeric'].append((trueStm, falseStm))
            trueStm = oval + ') AND %i=%i --' % (rndNum, rndNum)
            falseStm = oval + ') AND %i=%i --' % (rndNum, rndNumPlusOne)
            res['numeric'].append((trueStm, falseStm))

            # OR数字型SQL注入
            trueStm = oval + ' AND %i=%i OR 1=1' % (rndNum, rndNum)
            falseStm = oval + ' AND %i=%i OR 1=2' % (rndNum, rndNumPlusOne)
            res['numeric'].append((trueStm, falseStm))

        # Single quotes

        res['stringsingle'] = []
        trueStm = oval + "' AND '%i'='%i" % (rndNum, rndNum)
        falseStm = oval + "' AND '%i'='%i" % (rndNum, rndNumPlusOne)
        res['stringsingle'].append((trueStm, falseStm))

        trueStm = oval + "' AND '%i'='%i' --" % (rndNum, rndNum)
        falseStm = oval + "' AND '%i'='%i' --" % (rndNum, rndNumPlusOne)
        res['stringsingle'].append((trueStm, falseStm))
        trueStm = oval + "' AND '%i'='%i'))/*" % (rndNum, rndNum)
        falseStm = oval + "' AND '%i'='%i'))/*" % (rndNum, rndNumPlusOne)
        res['stringsingle'].append((trueStm, falseStm))

        # 前缀为')
        trueStm = oval + "') AND ('%i'='%i" % (rndNum, rndNum)
        falseStm = oval + "') AND ('%i'='%i" % (rndNum, rndNumPlusOne)
        res['stringsingle'].append((trueStm, falseStm))

        # 前缀为'))
        trueStm = oval + "')) AND (('%i'='%i" % (rndNum, rndNum)
        falseStm = oval + "')) AND (('%i'='%i" % (rndNum, rndNumPlusOne)
        res['stringsingle'].append((trueStm, falseStm))

        # 前缀为')))
        trueStm = oval + "'))) AND ((('%i'='%i" % (rndNum, rndNum)
        falseStm = oval + "'))) AND ((('%i'='%i" % (rndNum, rndNumPlusOne)
        res['stringsingle'].append((trueStm, falseStm))

        # AND搜索型SQL注入('%xx%')
        trueStm = oval + "%%' AND %i=%i AND '%%'='" % (rndNum, rndNum)
        falseStm = oval + "%%' AND %i=%i AND '%%'='" % (rndNum, rndNumPlusOne)
        res['stringsingle'].append((trueStm, falseStm))
        # OR搜索型SQL注入('%xx%')
        trueStm = oval + "%%' AND %i=%i OR '%%'='" % (rndNum, rndNum)
        falseStm = oval + "%%' OR %i=%i OR '%%'='" % (rndNum, rndNumPlusOne)
        res['stringsingle'].append((trueStm, falseStm))

        # Double quotes
        res['stringdouble'] = []
        trueStm = oval + '" AND "%i"="%i' % (rndNum, rndNum)
        falseStm = oval + '" AND "%i"="%i' % (rndNum, rndNumPlusOne)
        res['stringdouble'].append((trueStm, falseStm))
        trueStm = oval + '" AND "%i"="%i" --' % (rndNum, rndNum)
        falseStm = oval + '" AND "%i"="%i" --' % (rndNum, rndNumPlusOne)
        res['stringdouble'].append((trueStm, falseStm))
        trueStm = oval + '" AND "%i"="%i"))/*' % (rndNum, rndNum)
        falseStm = oval + '" AND "%i"="%i"))/*' % (rndNum, rndNumPlusOne)
        res['stringdouble'].append((trueStm, falseStm))
        # AND搜索型SQL注入('%xx%')
        trueStm = oval + '%%" AND %i=%i AND "%%"="' % (rndNum, rndNum)
        falseStm = oval + '%%" AND %i=%i AND "%%"="' % (rndNum, rndNumPlusOne)
        res['stringdouble'].append((trueStm, falseStm))
        # OR搜索型SQL注入('%xx%')
        trueStm = oval + '%%" AND %i=%i OR "%%"="' % (rndNum, rndNum)
        falseStm = oval + '%%" OR %i=%i OR "%%"="' % (rndNum, rndNumPlusOne)
        res['stringdouble'].append((trueStm, falseStm))

        # 前缀为')
        trueStm = oval + '") AND ("%i"="%i' % (rndNum, rndNum)
        falseStm = oval + '") AND ("%i"="%i' % (rndNum, rndNumPlusOne)
        res['stringdouble'].append((trueStm, falseStm))

        # 前缀为'))
        trueStm = oval + '")) AND (("%i"="%i' % (rndNum, rndNum)
        falseStm = oval + '")) AND (("%i"="%i' % (rndNum, rndNumPlusOne)
        res['stringdouble'].append((trueStm, falseStm))

        # 前缀为')))
        trueStm = oval + '"))) AND ((("%i"="%i' % (rndNum, rndNum)
        falseStm = oval + '"))) AND ((("%i"="%i' % (rndNum, rndNumPlusOne)
        res['stringdouble'].append((trueStm, falseStm))

        return res

    def equal(self, body1, body2):
        '''
        Determines if two pages are equal using some tricks.
        '''
        if self.equal_algorithm == 'setIntersection':
            return self._setIntersection(body1, body2)
        elif self.equal_algorithm == 'stringEq':
            return self._stringEq(body1, body2)

        raise appBaseException('Unknown algorithm selected.')

    def _stringEq(self, body1, body2):
        '''
        This is one of the equal algorithms.
        '''
        if body1 == body2:
            logger.debug('Pages are equal.')
            return True
        else:
            logger.debug('Pages are NOT equal.')
            return False

    def _setIntersection(self, body1, body2):
        '''
        This is one of the equal algorithms.
        '''
        sb1 = re.findall('(\w+)', body1)
        sb2 = re.findall('(\w+)', body2)

        setb1 = set(sb1)
        setb2 = set(sb2)

        intersection = setb1.intersection(setb2)

        totalLen = float(len(setb1) + len(setb2))
        if totalLen == 0:
            logger.debug('The length of both pages is zero. Cant apply setIntersection.')
            return False
        equal = (2 * len(intersection)) / totalLen
        if equal > self.equal_limit:
            logger.debug('Pages are equal, match rate: ' + str(equal))
            return True
        else:
            logger.debug('Pages are NOT equal, match rate: ' + str(equal))
            return False

    def equal_with_limit(self, body1, body2, compare_diff=False):
        """
        Determines if two pages are equal using a ratio.
        """
        start = time.time()

        if compare_diff:
            body1, body2 = diff(body1, body2)

        cmp_res = fuzzy_equal(body1, body2, self.equal_limit)

        are = 'ARE' if cmp_res else 'ARE NOT'
        args = (are, self.equal_limit)
        logger.debug('Strings %s similar enough (limit: %s)' % args)

        spent = time.time() - start
        logger.debug('Took %.2f seconds to run equal_with_limit' % spent)

        return cmp_res