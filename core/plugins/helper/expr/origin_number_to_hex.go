/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package expr

type OriginNumberToHex struct {
}

func (*OriginNumberToHex) GetPosition() int {
	return 0
}
func (*OriginNumberToHex) Value(string) (string, error) {
	// 创建 CEL 环境
	//env, err := cel.NewEnv(
	//	// 添加标准和扩展的运算符和函数
	//	cel.Lib(operators.Standard),
	//	cel.Lib(ext.Strings_stdlib),
	//)
	//if err != nil {
	//	log.Fatalf("Failed to create CEL environment: %v", err)
	//	return "", err
	//}
	//
	//// 定义输入参数
	//decls := []*decls.Decl{
	//	decls.NewVar("input", decls.String, nil),
	//}
	//
	//// 解析输入表达式
	//ast, iss := env.Compile(input, decls...)
	//if iss.Err() != nil {
	//	log.Fatalf("Compilation error: %v", iss.Err())
	//	return "", iss.Err()
	//}
	//
	//// 创建 CEL 评估器
	//prg, err := env.Program(ast)
	//if err != nil {
	//	log.Fatalf("Program creation error: %v", err)
	//	return "", err
	//}
	//
	//// 评估表达式
	//out, _, err := prg.Eval(map[string]any{"input": input})
	//if err != nil {
	//	log.Fatalf("Evaluation error: %v", err)
	//	return "", err
	//}
	//
	//// 获取结果并转换为字符串
	//result := ref.Val(out).Value().(string)
	//return result, nil
	return "", nil
}
