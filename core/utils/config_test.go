package utils

import (
	"testing"
)

func TestGenerate(t *testing.T) {
	// Generate is an empty function, just verify it doesn't panic
	Generate()
}

func TestGenYamlDoc(t *testing.T) {
	// GenYamlDoc is an empty function, just verify it doesn't panic
	GenYamlDoc()
}

// Note: gen() is unexported but accessible from same package test
func TestGen(t *testing.T) {
	// gen is an empty function, just verify it doesn't panic
	gen()
}
