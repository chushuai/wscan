/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package expression

import (
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

type typeRef struct {
	*types.TypeValue
	ref map[string]*expr.Type
}

func (t typeRef) TypeMap() map[string]*expr.Type {
	t.ref["request"] = decls.NewObjectType("structs.Request")
	t.ref["response"] = decls.NewObjectType("structs.Response")
	return t.ref
}
