package client

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"github.com/dlclark/regexp2"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"log"
	"math/rand"
	"net/url"
)

func NewCELEnv() *cel.Env {
	env, err := cel.NewEnv(
		cel.Lib(&envLib{}),
	)
	if err != nil {
		log.Fatalf("environment creation error: %s\n", err)
	}
	return env
}

type envLib struct{}

func (e envLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Declarations(bsubmatchDec, md5Dec, submatchDec, randomIntDec, randomLowercaseDec, substrDec,
			base64StringDec, base64BytesDec, base64DecodeStringDec, base64DecodeBytesDec,
			urlencodeStringDec, urlencodeBytesDec, urldecodeStringDec, urldecodeBytesDec),
		cel.Declarations(
			decls.NewVar("response.body", decls.Bytes),
			decls.NewVar("response.status", decls.Int),
			decls.NewVar("response.headers", decls.NewMapType(decls.String, decls.String)),
		),
	}
}

func (e envLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{
		cel.Functions(submatchFunc, bsubmatchFunc, md5Func, randomIntFunc, randomLowercaseFunc, substrFunc,
			base64StringFunc, base64BytesFunc, base64DecodeStringFunc, base64DecodeBytesFunc,
			urlencodeStringFunc, urlencodeBytesFunc, urldecodeStringFunc, urldecodeBytesFunc),
	}
}

var submatchDec = decls.NewFunction("submatch",
	decls.NewInstanceOverload("submatch_string_map_string_tring",
		[]*exprpb.Type{decls.String, decls.String}, decls.NewMapType(decls.String, decls.String)))
var submatchFunc = &functions.Overload{
	Operator: "submatch_string_map_string_tring",
	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
		v1, ok := lhs.(types.String)
		if !ok {
			return types.ValOrErr(lhs, "unexpected type '%v' passed to bmatch", lhs.Type())
		}

		v2, ok := rhs.(types.String)
		if !ok {
			return types.ValOrErr(rhs, "unexpected type '%v' passed to bmatch", rhs.Type())
		}
		rexp, err := regexp2.Compile(v1.Value().(string), regexp2.RE2)
		if err != nil {
			return types.NewErr("failed to compile regexp: %s, %s", v1.Value(), err)
		}

		match, err := rexp.FindStringMatch(v2.Value().(string))
		if err != nil {
			return types.NewErr("find substring: %s", err)
		}

		m := make(map[string]string)
		for _, group := range match.Groups() {
			m[group.Name] = group.Capture.String()
		}
		return types.NewStringStringMap(types.DefaultTypeAdapter, m)
	},
}

var bsubmatchDec = decls.NewFunction("bsubmatch",
	decls.NewInstanceOverload("bsubmatch_bytes_map_string_tring",
		[]*exprpb.Type{decls.String, decls.Bytes}, decls.NewMapType(decls.String, decls.String)))
var bsubmatchFunc = &functions.Overload{
	Operator: "bsubmatch_bytes_map_string_tring",
	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
		v1, ok := lhs.(types.String)
		if !ok {
			return types.ValOrErr(lhs, "unexpected type '%v' passed to bmatch", lhs.Type())
		}

		v2, ok := rhs.(types.Bytes)
		if !ok {
			return types.ValOrErr(rhs, "unexpected type '%v' passed to bmatch", rhs.Type())
		}
		rexp, err := regexp2.Compile(v1.Value().(string), regexp2.RE2)
		if err != nil {
			return types.NewErr("failed to compile regexp: %s, %s", v1.Value(), err)
		}

		match, err := rexp.FindRunesMatch(bytes.Runes(v2.Value().([]byte)))
		if err != nil {
			return types.NewErr("find substring: %s", err)
		}

		m := make(map[string]string)
		for _, group := range match.Groups() {
			m[group.Name] = group.Capture.String()
		}
		return types.NewStringStringMap(types.DefaultTypeAdapter, m)
	},
}

//  字符串的 md5
var md5Dec = decls.NewFunction("md5", decls.NewOverload("md5_string", []*exprpb.Type{decls.String}, decls.String))
var md5Func = &functions.Overload{
	Operator: "md5_string",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.String)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to md5_string", value.Type())
		}
		return types.String(fmt.Sprintf("%x", md5.Sum([]byte(v))))
	},
}

//	截取字符串
var substrDec = decls.NewFunction("substr", decls.NewOverload("substr_string_int_int", []*exprpb.Type{decls.String, decls.Int, decls.Int}, decls.String))
var substrFunc = &functions.Overload{
	Operator: "substr_string_int_int",
	Function: func(values ...ref.Val) ref.Val {
		if len(values) == 3 {
			str, ok := values[0].(types.String)
			if !ok {
				return types.NewErr("invalid string to 'substr'")
			}
			start, ok := values[1].(types.Int)
			if !ok {
				return types.NewErr("invalid start to 'substr'")
			}
			length, ok := values[2].(types.Int)
			if !ok {
				return types.NewErr("invalid length to 'substr'")
			}
			runes := []rune(str)
			if start < 0 || length < 0 || int(start+length) > len(runes) {
				return types.NewErr("invalid start or length to 'substr'")
			}
			return types.String(runes[start : start+length])
		} else {
			return types.NewErr("too many arguments to 'substr'")
		}
	},
}

//	将字符串进行 base64 编码
var base64StringDec = decls.NewFunction("base64", decls.NewOverload("base64_string", []*exprpb.Type{decls.String}, decls.String))
var base64StringFunc = &functions.Overload{
	Operator: "base64_string",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.String)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to base64_string", value.Type())
		}
		return types.String(base64.StdEncoding.EncodeToString([]byte(v)))
	},
}

//	将bytes进行 base64 编码
var base64BytesDec = decls.NewFunction("base64", decls.NewOverload("base64_bytes", []*exprpb.Type{decls.Bytes}, decls.String))
var base64BytesFunc = &functions.Overload{
	Operator: "base64_bytes",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.Bytes)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to base64_bytes", value.Type())
		}
		return types.String(base64.StdEncoding.EncodeToString(v))
	},
}

//	将字符串进行 base64 解码
var base64DecodeStringDec = decls.NewFunction("base64Decode", decls.NewOverload("base64Decode_string", []*exprpb.Type{decls.String}, decls.String))
var base64DecodeStringFunc = &functions.Overload{
	Operator: "base64Decode_string",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.String)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to base64Decode_string", value.Type())
		}
		decodeBytes, err := base64.StdEncoding.DecodeString(string(v))
		if err != nil {
			return types.NewErr("%v", err)
		}
		return types.String(decodeBytes)
	},
}

//	将bytes进行 base64 编码
var base64DecodeBytesDec = decls.NewFunction("base64Decode", decls.NewOverload("base64Decode_bytes", []*exprpb.Type{decls.Bytes}, decls.String))
var base64DecodeBytesFunc = &functions.Overload{
	Operator: "base64Decode_bytes",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.Bytes)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to base64Decode_bytes", value.Type())
		}
		decodeBytes, err := base64.StdEncoding.DecodeString(string(v))
		if err != nil {
			return types.NewErr("%v", err)
		}
		return types.String(decodeBytes)
	},
}

//	将字符串进行 urlencode 编码
var urlencodeStringDec = decls.NewFunction("urlencode", decls.NewOverload("urlencode_string", []*exprpb.Type{decls.String}, decls.String))
var urlencodeStringFunc = &functions.Overload{
	Operator: "urlencode_string",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.String)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to urlencode_string", value.Type())
		}
		return types.String(url.QueryEscape(string(v)))
	},
}

//	将bytes进行 urlencode 编码
var urlencodeBytesDec = decls.NewFunction("urlencode", decls.NewOverload("urlencode_bytes", []*exprpb.Type{decls.Bytes}, decls.String))
var urlencodeBytesFunc = &functions.Overload{
	Operator: "urlencode_bytes",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.Bytes)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to urlencode_bytes", value.Type())
		}
		return types.String(url.QueryEscape(string(v)))
	},
}

//	将字符串进行 urldecode 解码
var urldecodeStringDec = decls.NewFunction("urldecode", decls.NewOverload("urldecode_string", []*exprpb.Type{decls.String}, decls.String))
var urldecodeStringFunc = &functions.Overload{
	Operator: "urldecode_string",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.String)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to urldecode_string", value.Type())
		}
		decodeString, err := url.QueryUnescape(string(v))
		if err != nil {
			return types.NewErr("%v", err)
		}
		return types.String(decodeString)
	},
}

//	将 bytes 进行 urldecode 解码
var urldecodeBytesDec = decls.NewFunction("urldecode", decls.NewOverload("urldecode_bytes", []*exprpb.Type{decls.Bytes}, decls.String))
var urldecodeBytesFunc = &functions.Overload{
	Operator: "urldecode_bytes",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.Bytes)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to urldecode_bytes", value.Type())
		}
		decodeString, err := url.QueryUnescape(string(v))
		if err != nil {
			return types.NewErr("%v", err)
		}
		return types.String(decodeString)
	},
}

//	两个范围内的随机数
var randomIntDec = decls.NewFunction("randomInt", decls.NewOverload("randomInt_int_int", []*exprpb.Type{decls.Int, decls.Int}, decls.Int))
var randomIntFunc = &functions.Overload{
	Operator: "randomInt_int_int",
	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
		from, ok := lhs.(types.Int)
		if !ok {
			return types.ValOrErr(lhs, "unexpected type '%v' passed to randomInt", lhs.Type())
		}
		to, ok := rhs.(types.Int)
		if !ok {
			return types.ValOrErr(rhs, "unexpected type '%v' passed to randomInt", rhs.Type())
		}
		min, max := int(from), int(to)
		return types.Int(rand.Intn(max-min) + min)
	},
}

//	指定长度的小写字母组成的随机字符串
var randomLowercaseDec = decls.NewFunction("randomLowercase", decls.NewOverload("randomLowercase_int", []*exprpb.Type{decls.Int}, decls.String))
var randomLowercaseFunc = &functions.Overload{
	Operator: "randomLowercase_int",
	Unary: func(value ref.Val) ref.Val {
		n, ok := value.(types.Int)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to randomLowercase", value.Type())
		}
		return types.String(RandLowerLetter(int(n)))
	},
}

func RandLowerLetter(n int) string {
	var letters = []rune("abcdefghigklmnopqrstuvwxyz")

	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}

	return string(b)
}
