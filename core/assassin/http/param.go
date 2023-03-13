/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package http

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
	hiddenValue  interface{}
	buildEntries []string
	identifier   string
}

func (*Parameter) Clone() *Parameter {
	return nil
}

func (*Parameter) String() string {
	return ""
}
