/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package expression

import (
	"bytes"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/interpreter/functions"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/reflect/protoreflect"
	"net/url"
	"reflect"
	"strings"
	"wscan/core/http"
	logger "wscan/core/utils/log"
)

type CelRegistry struct {
	ref.TypeRegistry
	typeMap map[string]*typeRef
}

func (CelRegistry) Copy() ref.TypeRegistry {
	return nil
}
func (CelRegistry) EnumValue(string) ref.Val {
	return nil
}
func (CelRegistry) FindIdent(string) (ref.Val, bool) {
	return nil, false
}
func (CelRegistry) NewValue(string, map[string]ref.Val) ref.Val {
	return nil
}
func (CelRegistry) RegisterDescriptor(protoreflect.FileDescriptor) error {
	return nil
}
func (CelRegistry) RegisterMessage(protoreflect.ProtoMessage) error {
	return nil
}
func (CelRegistry) RegisterType([]ref.Type) error {
	return nil
}

type Expression struct {
	registry  *CelRegistry
	celEnv    *cel.Env
	idents    []*expr.Decl
	functions []*functions.Overload
	types     []*typeRef
}

func (expression *Expression) AddBFunctions() {

}
func (expression *Expression) AddCryptoFunctions() {

}
func (expression *Expression) AddIFunctions() {
	expression.idents = append(expression.idents, decls.NewFunction("bcontains",
		decls.NewInstanceOverload("bytes_bcontains_bytes",
			[]*expr.Type{decls.Bytes, decls.Bytes},
			decls.Bool)))
	expression.functions = append(expression.functions, &functions.Overload{
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
	})
}

func (expression *Expression) AddRandomFunctions() {

}
func (expression *Expression) AddRequest() {

}
func (expression *Expression) AddResponse() {

}
func (expression *Expression) AddReverse() {

}
func (expression *Expression) AddStringFunctions() {

}
func (expression *Expression) AddTimeFunctions() {

}
func (expression *Expression) AddURL() {

}
func (expression *Expression) AddVariable() {

}
func (exp *Expression) Compile(expression string) error {
	ast, iss := exp.celEnv.Compile(expression)
	err := iss.Err()
	if err != nil {
		return err
	}
	prg, err := exp.celEnv.Program(ast)
	if err != nil {
		return err
	}
	logger.Info(prg)
	//out, _, err := prg.Eval(params)
	//if err != nil {
	//	return err
	//}
	return nil
}
func (expression *Expression) Register() error {
	return nil
}
func (expression *Expression) Registry() {

}

type celRequest struct {
	*typeRef
	req    *http.Request
	refMap map[string]interface{}
}

func (celRequest) ConvertToNative(reflect.Type) (interface{}, error) {
	return nil, nil
}
func (celRequest) ConvertToType(ref.Type) ref.Val {
	return nil
}
func (celRequest) Equal(ref.Val) ref.Val {
	return nil
}
func (celRequest) HasTrait(int) bool {
	return false
}
func (celRequest) String() string {
	return ""
}
func (celRequest) Type() ref.Type {
	return nil
}
func (celRequest) TypeMap() map[string]*expr.Type {
	return nil
}
func (celRequest) TypeName() string {
	return ""
}

type celResponse struct {
	*typeRef
	refMap map[string]interface{}
}

func (celResponse) ConvertToNative(reflect.Type) (interface{}, error) {
	return nil, nil
}
func (celResponse) ConvertToType(ref.Type) ref.Val {
	return nil
}
func (celResponse) Equal(ref.Val) ref.Val {
	return nil
}
func (celResponse) HasTrait(int) bool {
	return false
}
func (celResponse) String() string {
	return ""
}
func (celResponse) Type() ref.Type {
	return nil
}
func (celResponse) TypeMap() map[string]*expr.Type {
	return nil
}
func (celResponse) TypeName() string {
	return ""
}

type celURL struct {
	*typeRef
	u *url.URL
}

func (celURL) ConvertToNative(reflect.Type) (interface{}, error) {
	return nil, nil
}
func (celURL) ConvertToType(ref.Type) ref.Val {
	return nil
}
func (celURL) Equal(ref.Val) ref.Val {
	return nil
}
func (celURL) HasTrait(int) bool {
	return false
}
func (celURL) Type() ref.Type {
	return nil
}
func (celURL) TypeMap() map[string]*expr.Type {
	return nil
}
func (celURL) TypeName() string {
	return ""
}

type iKeyStrStrMap struct {
	traits.Mapper
	mapStrStr map[string]string
}

func (iKeyStrStrMap) ConvertToNative(reflect.Type) (interface{}, error) {
	return nil, nil
}
func (iKeyStrStrMap) ConvertToType(ref.Type) ref.Val {
	return nil
}
func (iKeyStrStrMap) Equal(ref.Val) ref.Val {
	return nil
}
func (iKeyStrStrMap) HasTrait(int) bool {
	return false
}
func (iKeyStrStrMap) Type() ref.Type {
	return nil
}
func (iKeyStrStrMap) TypeMap() map[string]*expr.Type {
	return nil
}
func (iKeyStrStrMap) TypeName() string {
	return ""
}

type unparser struct {
	str    strings.Builder
	offset int32
	info   *expr.SourceInfo
}
