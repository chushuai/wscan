package jsonpath

import (
	"testing"
)

// ===== indexAsInt coverage boost =====

func TestIndexAsInt_IntValue(t *testing.T) {
	// case int: should return the int directly
	result, err := indexAsInt(3, nil, nil)
	if err != nil {
		t.Fatalf("indexAsInt(3) returned error: %v", err)
	}
	if result != 3 {
		t.Errorf("indexAsInt(3) = %d, want 3", result)
	}
}

func TestIndexAsInt_NegativeIntValue(t *testing.T) {
	result, err := indexAsInt(-1, nil, nil)
	if err != nil {
		t.Fatalf("indexAsInt(-1) returned error: %v", err)
	}
	if result != -1 {
		t.Errorf("indexAsInt(-1) = %d, want -1", result)
	}
}

func TestIndexAsInt_ZeroIntValue(t *testing.T) {
	result, err := indexAsInt(0, nil, nil)
	if err != nil {
		t.Fatalf("indexAsInt(0) returned error: %v", err)
	}
	if result != 0 {
		t.Errorf("indexAsInt(0) = %d, want 0", result)
	}
}

func TestIndexAsInt_ExprFuncReturnsInt(t *testing.T) {
	// case exprFunc: should call the function and return the int result
	var fn exprFunc = func(r, c any) (any, error) {
		return 5, nil
	}
	result, err := indexAsInt(fn, "root", "current")
	if err != nil {
		t.Fatalf("indexAsInt(exprFunc returning 5) returned error: %v", err)
	}
	if result != 5 {
		t.Errorf("indexAsInt(exprFunc returning 5) = %d, want 5", result)
	}
}

func TestIndexAsInt_ExprFuncUsesContext(t *testing.T) {
	// Verify that r and c are passed through to the exprFunc
	var fn exprFunc = func(r, c any) (any, error) {
		// Use r and c in computation
		root := r.(int)
		cur := c.(int)
		return root + cur, nil
	}
	result, err := indexAsInt(fn, 10, 20)
	if err != nil {
		t.Fatalf("indexAsInt with context returned error: %v", err)
	}
	if result != 30 {
		t.Errorf("indexAsInt with context = %d, want 30", result)
	}
}

// ===== indexAsString coverage boost =====

func TestIndexAsString_StringValue(t *testing.T) {
	// case string: should return the string directly
	result, err := indexAsString("myKey", nil, nil)
	if err != nil {
		t.Fatalf("indexAsString('myKey') returned error: %v", err)
	}
	if result != "myKey" {
		t.Errorf("indexAsString('myKey') = %q, want 'myKey'", result)
	}
}

func TestIndexAsString_EmptyStringValue(t *testing.T) {
	result, err := indexAsString("", nil, nil)
	if err != nil {
		t.Fatalf("indexAsString('') returned error: %v", err)
	}
	if result != "" {
		t.Errorf("indexAsString('') = %q, want empty string", result)
	}
}

func TestIndexAsString_ExprFuncReturnsString(t *testing.T) {
	// case exprFunc: should call the function and return the string result
	var fn exprFunc = func(r, c any) (any, error) {
		return "computedKey", nil
	}
	result, err := indexAsString(fn, "root", "current")
	if err != nil {
		t.Fatalf("indexAsString(exprFunc returning 'computedKey') returned error: %v", err)
	}
	if result != "computedKey" {
		t.Errorf("indexAsString(exprFunc returning 'computedKey') = %q, want 'computedKey'", result)
	}
}

func TestIndexAsString_ExprFuncUsesContext(t *testing.T) {
	// Verify that r and c are passed through to the exprFunc
	var fn exprFunc = func(r, c any) (any, error) {
		root := r.(string)
		cur := c.(string)
		return root + "." + cur, nil
	}
	result, err := indexAsString(fn, "store", "book")
	if err != nil {
		t.Fatalf("indexAsString with context returned error: %v", err)
	}
	if result != "store.book" {
		t.Errorf("indexAsString with context = %q, want 'store.book'", result)
	}
}
