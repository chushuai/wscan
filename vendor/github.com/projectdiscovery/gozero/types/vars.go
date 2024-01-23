package types

import "fmt"

type Variable struct {
	Name  string
	Value string
}

func (v *Variable) String() string {
	return fmt.Sprintf("%s=%s", v.Name, v.Value)
}
