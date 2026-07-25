/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package http

import "reflect"

const (
	PositionQuery  = "query"
	PositionBody   = "body"
	PositionHeader = "header"
	PositionCookie = "cookie"
	PositionStatus = "status"
	PositionPath   = "path"
)

const (
	ParameterTypeValue  = "value"
	ParameterTypePrefix = "prefix"
	ParameterTypeSuffix = "suffix"
)

type Parameter struct {
	Position     string
	Key          string
	Value        string
	Prefix       string
	Suffix       string
	ContentType  string
	Filename     string
	Content      []byte
	hidden       bool
	hiddenValue  any
	buildEntries []string
	identifier   string
}

func (p *Parameter) Clone() *Parameter {
	newParam := Parameter{}
	newParam = *p

	return &newParam
}

// Assign 方法用于将一个 Parameter 的值赋值给另一个 Parameter
func (p *Parameter) Assign(other Parameter) {
	p.Position = other.Position
	p.Key = other.Key
	p.Value = other.Value
	p.Prefix = other.Prefix
	p.Suffix = other.Suffix
	p.ContentType = other.ContentType
	p.Filename = other.Filename
	p.Content = other.Content
	copy(p.Content, other.Content)
	p.hidden = other.hidden
	p.hiddenValue = other.hiddenValue
	p.buildEntries = other.buildEntries
	p.identifier = other.identifier
}

func (p *Parameter) DeepCopy() Parameter {
	clone := Parameter{}
	val := reflect.ValueOf(p).Elem()
	cloneVal := reflect.ValueOf(&clone).Elem()

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		cloneField := cloneVal.Field(i)

		if !cloneField.CanSet() {
			continue
		}
		if field.Kind() == reflect.Slice {
			if field.IsNil() {
				continue
			}
			sliceLen := field.Len()
			newSlice := reflect.MakeSlice(field.Type(), sliceLen, sliceLen)
			reflect.Copy(newSlice, field)
			cloneField.Set(newSlice)
		} else {
			cloneField.Set(field)
		}
	}

	return clone
}

func (p *Parameter) String() string {
	return p.Prefix + p.Value + p.Suffix
}

func cloneParameters(pList map[string]*Parameter) map[string]*Parameter {
	pList2 := make(map[string]*Parameter)
	for i, p := range pList {
		pList2[i] = p.Clone()
	}
	return pList2
}
