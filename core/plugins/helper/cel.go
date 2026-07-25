/**
2 * @Author: shaochuyu
3 * @Date: 6/25/23
4 */

package helper

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"github.com/dlclark/regexp2"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"math/rand"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"wscan/core/model"
	"wscan/core/reverse"
	"wscan/core/utils"
	logger "wscan/core/utils/log"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

var (
	StrStrMapType = decls.NewMapType(decls.String, decls.String)
	RequestType   = decls.NewObjectType("model.Request")
	ResponseType  = decls.NewObjectType("model.Response")
	ReverseType   = decls.NewObjectType("model.Reverse")
	UrlTypeType   = decls.NewObjectType("model.UrlType")

	StandradEnvOptions = []cel.EnvOption{
		cel.Container("model"),
		cel.Types(
			&model.UrlType{},
			&model.Request{},
			&model.Response{},
			&model.Reverse{},
			StrStrMapType,
		),
		cel.Declarations(
			decls.NewVar("request", RequestType),
			decls.NewVar("response", ResponseType),
		),
		cel.Declarations(
			// functions
			decls.NewFunction("bcontains",
				decls.NewInstanceOverload("bytes_bcontains_bytes",
					[]*exprpb.Type{decls.Bytes, decls.Bytes},
					decls.Bool)),
			decls.NewFunction("ibcontains",
				decls.NewInstanceOverload("bytes_ibcontains_bytes",
					[]*exprpb.Type{decls.Bytes, decls.Bytes},
					decls.Bool)),
			decls.NewFunction("icontains",
				decls.NewInstanceOverload("icontains_string",
					[]*exprpb.Type{decls.String, decls.String},
					decls.Bool)),
			decls.NewFunction("bstartsWith",
				decls.NewInstanceOverload("bytes_bstartsWith_bytes",
					[]*exprpb.Type{decls.Bytes, decls.Bytes},
					decls.Bool)),
			decls.NewFunction("submatch",
				decls.NewInstanceOverload("string_submatch_string",
					[]*exprpb.Type{decls.String, decls.String},
					StrStrMapType,
				)),
			decls.NewFunction("bmatches",
				decls.NewInstanceOverload("string_bmatches_bytes",
					[]*exprpb.Type{decls.String, decls.Bytes},
					decls.Bool)),
			decls.NewFunction("bsubmatch",
				decls.NewInstanceOverload("string_bsubmatch_bytes",
					[]*exprpb.Type{decls.String, decls.Bytes},
					StrStrMapType,
				)),
			decls.NewFunction("wait",
				decls.NewInstanceOverload("reverse_wait_int",
					[]*exprpb.Type{decls.Any, decls.Int},
					decls.Bool)),
			decls.NewFunction("newReverse",
				decls.NewOverload("newReverse",
					[]*exprpb.Type{},
					ReverseType)),
			decls.NewFunction("md5",
				decls.NewOverload("md5_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("randomInt",
				decls.NewOverload("randomInt_int_int",
					[]*exprpb.Type{decls.Int, decls.Int},
					decls.Int)),
			decls.NewFunction("randomLowercase",
				decls.NewOverload("randomLowercase_int",
					[]*exprpb.Type{decls.Int},
					decls.String)),
			decls.NewFunction("base64",
				decls.NewOverload("base64_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("base64",
				decls.NewOverload("base64_bytes",
					[]*exprpb.Type{decls.Bytes},
					decls.String)),
			decls.NewFunction("base64Decode",
				decls.NewOverload("base64Decode_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("base64Decode",
				decls.NewOverload("base64Decode_bytes",
					[]*exprpb.Type{decls.Bytes},
					decls.String)),
			decls.NewFunction("urlencode",
				decls.NewOverload("urlencode_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("urlencode",
				decls.NewOverload("urlencode_bytes",
					[]*exprpb.Type{decls.Bytes},
					decls.String)),
			decls.NewFunction("urldecode",
				decls.NewOverload("urldecode_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("urldecode",
				decls.NewOverload("urldecode_bytes",
					[]*exprpb.Type{decls.Bytes},
					decls.String)),
			decls.NewFunction("substr",
				decls.NewOverload("substr_string_int_int",
					[]*exprpb.Type{decls.String, decls.Int, decls.Int},
					decls.String)),
			decls.NewFunction("replaceAll",
				decls.NewOverload("replaceAll_string_string_string",
					[]*exprpb.Type{decls.String, decls.String, decls.String},
					decls.String)),
			decls.NewFunction("printable",
				decls.NewOverload("printable_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("sleep",
				decls.NewOverload("sleep_int",
					[]*exprpb.Type{decls.Int},
					decls.Bool)),
			decls.NewFunction("faviconHash",
				decls.NewOverload("faviconHash_stringOrBytes",
					[]*exprpb.Type{decls.Any},
					decls.Int)),
			decls.NewFunction("toUintString",
				decls.NewOverload("toUintString_string_string",
					[]*exprpb.Type{decls.String, decls.String},
					decls.String)),
		),
	}
)

func NewFunctionDefineOptions(reg ref.TypeRegistry) []cel.EnvOption {
	newOptions := []cel.EnvOption{
		cel.CustomTypeAdapter(reg),
		cel.CustomTypeProvider(reg),
	}
	newOptions = append(newOptions, StandradEnvOptions...)

	return newOptions
}

var (
	ReversePool = sync.Pool{
		New: func() any {
			return new(model.Reverse)
		},
	}

	StandradProgramOption = []cel.ProgramOption{
		cel.Functions(
			&functions.Overload{
				Operator: "bytes_bcontains_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to bcontains", lhs.Type())
					}
					v2, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to bcontains", rhs.Type())
					}
					return types.Bool(bytes.Contains(v1, v2))
				},
			},
			&functions.Overload{
				Operator: "bytes_ibcontains_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to bcontains", lhs.Type())
					}
					v2, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to bcontains", rhs.Type())
					}
					return types.Bool(bytes.Contains(bytes.ToLower(v1), bytes.ToLower(v2)))
				},
			},
			&functions.Overload{
				Operator: "icontains_string",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to bcontains", lhs.Type())
					}
					v2, ok := rhs.(types.String)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to bcontains", rhs.Type())
					}
					// 不区分大小写包含
					return types.Bool(strings.Contains(strings.ToLower(string(v1)), strings.ToLower(string(v2))))
				},
			},
			&functions.Overload{
				Operator: "bytes_bstartsWith_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to bstartsWith", lhs.Type())
					}
					v2, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to bstartsWith", rhs.Type())
					}
					return types.Bool(bytes.HasPrefix(v1, v2))
				},
			},
			&functions.Overload{
				Operator: "string_bmatches_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					var isMatch = false
					var err error

					v1, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to bmatches", lhs.Type())
					}
					v2, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to bmatches", rhs.Type())
					}
					isMatch, err = regexp.Match(string(v1), []byte(v2))
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.Bool(isMatch)
				},
			},
			&functions.Overload{
				Operator: "matches_string",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					var (
						isMatch = false
						err     error
					)

					v1, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to matches", lhs.Type())
					}
					v2, ok := rhs.(types.String)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to matches", rhs.Type())
					}
					isMatch, err = regexp.Match(string(v1), []byte(v2))
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.Bool(isMatch)
				},
			},

			&functions.Overload{
				Operator: "md5_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to md5_string", value.Type())
					}
					return types.String(fmt.Sprintf("%x", md5.Sum([]byte(v))))
				},
			},
			&functions.Overload{
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
			},
			&functions.Overload{
				Operator: "randomLowercase_int",
				Unary: func(value ref.Val) ref.Val {
					n, ok := value.(types.Int)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to randomLowercase", value.Type())
					}
					return types.String(utils.RandLetters(int(n)))
				},
			},
			&functions.Overload{
				Operator: "base64_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to base64_string", value.Type())
					}
					return types.String(base64.StdEncoding.EncodeToString([]byte(v)))
				},
			},
			&functions.Overload{
				Operator: "base64_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to base64_bytes", value.Type())
					}
					return types.String(base64.StdEncoding.EncodeToString(v))
				},
			},
			&functions.Overload{
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
			},
			&functions.Overload{
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
			},
			&functions.Overload{
				Operator: "urlencode_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to urlencode_string", value.Type())
					}
					return types.String(url.QueryEscape(string(v)))
				},
			},
			&functions.Overload{
				Operator: "urlencode_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to urlencode_bytes", value.Type())
					}
					return types.String(url.QueryEscape(string(v)))
				},
			},
			&functions.Overload{
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
			},
			&functions.Overload{
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
			},
			&functions.Overload{
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
			},
			&functions.Overload{
				Operator: "reverse_wait_int",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					reverse, ok := lhs.Value().(*model.Reverse)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to 'wait'", lhs.Type())
					}
					timeout, ok := rhs.Value().(int64)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to 'wait'", rhs.Type())
					}

					return types.Bool(ReverseCheck(reverse, timeout))
				},
			},
			&functions.Overload{
				Operator: "replaceAll_string_string_string",
				Function: func(values ...ref.Val) ref.Val {
					s, ok := values[0].(types.String)
					if !ok {
						return types.ValOrErr(s, "unexpected type '%v' passed to replaceAll", s.Type())
					}
					old, ok := values[1].(types.String)
					if !ok {
						return types.ValOrErr(old, "unexpected type '%v' passed to replaceAll", old.Type())
					}
					new, ok := values[2].(types.String)
					if !ok {
						return types.ValOrErr(new, "unexpected type '%v' passed to replaceAll", new.Type())
					}

					return types.String(strings.ReplaceAll(string(s), string(old), string(new)))
				},
			},
			&functions.Overload{
				Operator: "printable_string",
				Unary: func(value ref.Val) ref.Val {
					s, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(s, "unexpected type '%v' passed to printable", s.Type())
					}

					clean := strings.Map(func(r rune) rune {
						if unicode.IsPrint(r) {
							return r
						}
						return -1
					}, string(s))

					return types.String(clean)
				},
			},
			&functions.Overload{
				Operator: "sleep_int",
				Unary: func(value ref.Val) ref.Val {
					i, ok := value.(types.Int)
					if !ok {
						return types.ValOrErr(i, "unexpected type '%v' passed to sleep", i.Type())
					}
					time.Sleep(time.Duration(int64(i)) * time.Second)
					return types.Bool(true)
				},
			},
			&functions.Overload{
				Operator: "faviconHash_stringOrBytes",
				Unary: func(value ref.Val) ref.Val {
					b, ok := value.(types.Bytes)
					if !ok {
						bStr, ok := value.(types.String)
						b = []byte(bStr)
						if !ok {
							return types.ValOrErr(bStr, "unexpected type '%v' passed to faviconHash", bStr.Type())
						}
					}
					return types.Int(utils.Mmh3Hash32(b))
				},
			},
			&functions.Overload{
				Operator: "toUintString_string_string",
				Function: func(values ...ref.Val) ref.Val {
					s1, ok := values[0].(types.String)
					s := string(s1)
					if !ok {
						return types.ValOrErr(s1, "unexpected type '%v' passed to toUintString", s1.Type())
					}
					direction, ok := values[1].(types.String)
					if !ok {
						return types.ValOrErr(direction, "unexpected type '%v' passed to toUintString", direction.Type())
					}
					if direction == "<" {
						s = utils.ReverseString(s)
					}
					if _, err := strconv.Atoi(s); err == nil {
						return types.String(s)
					} else {
						return types.NewErr("%v", err)
					}
				},
			},
		),
	}
)

func NewFunctionImplOptions(reg ref.TypeRegistry) []cel.ProgramOption {
	newOptions := []cel.ProgramOption{
		cel.Functions(
			&functions.Overload{
				Operator: "string_submatch_string",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					var (
						resultMap = make(map[string]string)
					)

					v1, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to submatch", lhs.Type())
					}
					v2, ok := rhs.(types.String)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to submatch", rhs.Type())
					}

					re := regexp2.MustCompile(string(v1), regexp2.RE2)
					if m, _ := re.FindStringMatch(string(v2)); m != nil {
						gps := m.Groups()
						for n, gp := range gps {
							if n == 0 {
								continue
							}
							resultMap[gp.Name] = gp.String()
						}
					}
					return types.NewStringStringMap(reg, resultMap)
				},
			},
			&functions.Overload{
				Operator: "string_bsubmatch_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					var (
						resultMap = make(map[string]string)
					)

					v1, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to bsubmatch", lhs.Type())
					}
					v2, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to bsubmatch", rhs.Type())
					}
					re := regexp2.MustCompile(string(v1), regexp2.RE2)
					if m, _ := re.FindStringMatch(string([]byte(v2))); m != nil {
						gps := m.Groups()
						for n, gp := range gps {
							if n == 0 {
								continue
							}
							resultMap[gp.Name] = gp.String()
						}
					}

					return types.NewStringStringMap(reg, resultMap)
				},
			},
			&functions.Overload{
				Operator: "newReverse",
				Function: func(values ...ref.Val) ref.Val {
					return reg.NativeToValue(NewReverse())
				},
			},
		),
	}

	newOptions = append(newOptions, StandradProgramOption...)

	return newOptions
}

var Reverse *reverse.Reverse

// xray dns反连平台
func NewReverse() (reverse *model.Reverse) {
	reverse = &model.Reverse{}
	reverse.IsDomainNameServer = false

	if Reverse == nil || Reverse.Config() == nil {
		return
	}
	unit := Reverse.Register(nil)
	urlStr, err := unit.GetEncodedVisitURL()
	if err != nil {
		logger.Fatal(err)
	}

	logger.Infof("reverse visit url: %s", urlStr)
	u, _ := url.Parse(urlStr)
	reverse.Url = ParseUrl(u)
	reverse.Domain = u.Hostname()
	reverse.LdapUrl = unit.GetLdapURL()
	reverse.RmiUrl = unit.GetRmiURL()
	reverse.Ip = u.Host
	return
}

func ReverseCheck(r *model.Reverse, timeout int64) bool {
	if Reverse == nil || Reverse.Config() == nil {
		return false
	}
	logger.Infof("reverse path url: %s, %d", r.Url.Path, timeout)
	end := time.Now().Add(time.Duration(timeout) * time.Second)
	for {
		if time.Now().After(end) {
			break
		}
		time.Sleep(1 * time.Second)
		if Reverse.FetchURLEvent(r.Url.Path) {
			return true
		}
	}
	return false
}

func PutReverse(reverse *model.Reverse) {
	//reverse.Url = nil
	//reverse.Domain = ""
	//reverse.Ip = ""
	//reverse.ReverseType = model.ReverseType_DnslogCN
	//reverse.IsDomainNameServer = false
	//
	//ReversePool.Put(reverse)
}

var (
	CustomLibPool = sync.Pool{
		New: func() any {
			return new(CustomLib)
		},
	}
)

// 自定义Lib库，包含变量和函数

type Env = cel.Env
type CustomLib struct {
	envOptions     []cel.EnvOption
	programOptions []cel.ProgramOption
}

// 执行表达式
func Evaluate(env *cel.Env, expression string, params map[string]any) (ref.Val, error) {

	ast, iss := env.Compile(expression)
	err := iss.Err()
	if err != nil {
		return nil, err
	}
	prg, err := env.Program(ast)
	if err != nil {
		return nil, err
	}
	out, _, err := prg.Eval(params)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func UrlTypeToString(u *model.UrlType) string {
	var buf strings.Builder

	if u.Scheme != "" {
		buf.WriteString(u.Scheme)
		buf.WriteByte(':')
	}
	if u.Scheme != "" || u.Host != "" {
		if u.Host != "" || u.Path != "" {
			buf.WriteString("//")
		}
		if h := u.Host; h != "" {
			buf.WriteString(u.Host)
		}
	}
	path := u.Path
	if path != "" && path[0] != '/' && u.Host != "" {
		buf.WriteString("/")
	}
	if buf.Len() == 0 {
		if i := strings.IndexByte(path, ':'); i > -1 && strings.IndexByte(path[:i], '/') == -1 {
			buf.WriteString("./")
		}
	}
	buf.WriteString(path)

	if u.Query != "" {
		buf.WriteByte('?')
		buf.WriteString(u.Query)
	}
	if u.Fragment != "" {
		buf.WriteByte('#')
		buf.WriteString(u.Fragment)
	}
	return buf.String()
}

func NewEnv(c *CustomLib) (*cel.Env, error) {
	return cel.NewEnv(cel.Lib(c))
}

func NewEnvOption() *CustomLib {
	c := CustomLibPool.Get().(*CustomLib)
	reg := types.NewEmptyRegistry()
	c.envOptions = NewFunctionDefineOptions(reg)
	c.programOptions = NewFunctionImplOptions(reg)
	return c
}

func NewExtraFunctionEnvOption(declOpt cel.EnvOption, progOpt cel.ProgramOption) *CustomLib {
	c := CustomLibPool.Get().(*CustomLib)
	c.envOptions = []cel.EnvOption{declOpt}
	c.programOptions = []cel.ProgramOption{progOpt}
	return c
}

func PutCustomLib(c *CustomLib) {
	c.envOptions = nil
	c.programOptions = nil

	CustomLibPool.Put(c)
}

func NewCompileOption(k string, t *exprpb.Type) cel.EnvOption {
	return cel.Declarations(decls.NewVar(k, t))
}

// 声明环境中的变量类型和函数
func (c *CustomLib) CompileOptions() []cel.EnvOption {
	return c.envOptions
}

func (c *CustomLib) ProgramOptions() []cel.ProgramOption {
	return c.programOptions
}

func (c *CustomLib) UpdateCompileOption(k string, t *exprpb.Type) {
	c.envOptions = append(c.envOptions, cel.Declarations(decls.NewVar(k, t)))
}

type RequestFuncType func(rule any) error

func (c *CustomLib) DefineRuleFunction(requestFunc RequestFuncType, ruleName string, rule any, function func(requestFunc RequestFuncType, ruleName string, rule any) (bool, error)) {
	c.envOptions = append(c.envOptions, cel.Declarations(
		decls.NewFunction(ruleName,
			decls.NewOverload(ruleName,
				[]*exprpb.Type{},
				decls.Bool)),
	))

	c.programOptions = append(c.programOptions, cel.Functions(
		&functions.Overload{
			Operator: ruleName,
			Function: func(values ...ref.Val) ref.Val {
				r, err := function(requestFunc, ruleName, rule)
				if err != nil {
					r = false
					logger.Error(err)
				}
				return types.Bool(r)
			},
		}))
}

var DefaultCelEnv, _ = NewEnv(NewEnvOption())

type CelExecutor struct {
	variableMap map[string]any
	c           *CustomLib
	globalEnv   *cel.Env
}

func NewCelExecutor() *CelExecutor {
	ce := CelExecutor{
		variableMap: make(map[string]any),
		c:           NewEnvOption(),
	}

	var err error
	if ce.globalEnv, err = NewEnv(ce.c); err != nil {
		logger.Fatal(err)
	}
	return &ce
}

func (ce *CelExecutor) SetVariable(key string, value any) {
	ce.variableMap[key] = value
}

func (ce *CelExecutor) EvaluateUpdateVariableMap(set yaml.MapSlice) error {
	for _, item := range set {
		k, expression := item.Key.(string), item.Value.(string)
		out, err := Evaluate(ce.globalEnv, expression, ce.variableMap)
		if err != nil {
			wrappedErr := errors.Wrapf(err, "Evalaute expression error: %s", expression)
			logger.Fatal(wrappedErr)
			continue
		}
		// 设置variableMap并且更新CompileOption
		switch value := out.Value().(type) {
		case *model.UrlType:
			if _, ok := ce.variableMap[k]; !ok {
				ce.c.UpdateCompileOption(k, UrlTypeType)
			}
			ce.variableMap[k] = UrlTypeToString(value)
		case *model.Reverse:
			if _, ok := ce.variableMap[k]; !ok {
				ce.c.UpdateCompileOption(k, ReverseType)
			}
			ce.variableMap[k] = value
		case int, int32, int64:
			if _, ok := ce.variableMap[k]; !ok {
				ce.c.UpdateCompileOption(k, decls.Int)
			}
			ce.variableMap[k] = value
		case map[string]string:
			if _, ok := ce.variableMap[k]; !ok {
				ce.c.UpdateCompileOption(k, StrStrMapType)
			}
			ce.variableMap[k] = value
		case string:
			if _, ok := ce.variableMap[k]; !ok {
				ce.c.UpdateCompileOption(k, decls.String)
			}
			ce.variableMap[k] = value
		default:
			if _, ok := ce.variableMap[k]; !ok {
				ce.c.UpdateCompileOption(k, decls.Any)
			}
			ce.variableMap[k] = value
		}
		// ? 需要重新生成一遍环境，否则之前增加的变量定义不生效
		ce.globalEnv, err = ce.ReCreateEnv()
		if err != nil {
			return err
		}
	}
	return nil
}

// 定义渲染函数
func (ce *CelExecutor) Render(v string) string {
	for k1, v1 := range ce.variableMap {
		_, isMap := v1.(map[string]string)
		if isMap {
			continue
		}
		v1Value := fmt.Sprintf("%v", v1)
		t := "{{" + k1 + "}}"
		if !strings.Contains(v, t) {
			continue
		}
		v = strings.ReplaceAll(v, t, v1Value)
	}
	return v
}

func (ce *CelExecutor) Evaluate(expression string) (ref.Val, error) {
	return Evaluate(ce.globalEnv, expression, ce.variableMap)
}

func (ce *CelExecutor) Close() {
	PutCustomLib(ce.c)
}

func (ce *CelExecutor) ReCreateEnv() (*Env, error) {
	env, err := NewEnv(ce.c)
	if err != nil {
		return nil, err
	}
	return env, nil
}
