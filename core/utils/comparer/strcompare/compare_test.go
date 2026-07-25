package strcompare

import (
	"math"
	"testing"
)

func TestNewStringArrayComparer(t *testing.T) {
	sac := NewStringArrayComparer([]string{"a", "b"}, []string{"c", "d"})
	if sac == nil {
		t.Fatal("NewStringArrayComparer returned nil")
	}
}

func TestStringArrayComparer_BothEmpty(t *testing.T) {
	sac := NewStringArrayComparer([]string{}, []string{})
	ratio := sac.Ratio()
	if ratio != 1.0 {
		t.Errorf("Ratio() for two empty arrays = %v, expected 1.0", ratio)
	}
}

func TestStringArrayComparer_OneEmpty(t *testing.T) {
	sac := NewStringArrayComparer([]string{"a"}, []string{})
	ratio := sac.Ratio()
	if ratio != 0.0 {
		t.Errorf("Ratio() for one empty array = %v, expected 0.0", ratio)
	}

	sac2 := NewStringArrayComparer([]string{}, []string{"a"})
	ratio2 := sac2.Ratio()
	if ratio2 != 0.0 {
		t.Errorf("Ratio() for second empty array = %v, expected 0.0", ratio2)
	}
}

func TestStringArrayComparer_Identical(t *testing.T) {
	sac := NewStringArrayComparer([]string{"a", "b", "c"}, []string{"a", "b", "c"})
	ratio := sac.Ratio()
	if ratio != 1.0 {
		t.Errorf("Ratio() for identical arrays = %v, expected 1.0", ratio)
	}
}

func TestStringArrayComparer_NoOverlap(t *testing.T) {
	sac := NewStringArrayComparer([]string{"a", "b"}, []string{"c", "d"})
	ratio := sac.Ratio()
	if ratio != 0.0 {
		t.Errorf("Ratio() for no overlap = %v, expected 0.0", ratio)
	}
}

func TestStringArrayComparer_PartialOverlap(t *testing.T) {
	// a,b,c vs b,c,d -> intersection = {b,c} = 2, union = {a,b,c,d} = 4
	// Jaccard = 2/4 = 0.5
	sac := NewStringArrayComparer([]string{"a", "b", "c"}, []string{"b", "c", "d"})
	ratio := sac.Ratio()
	if math.Abs(float64(ratio)-0.5) > 0.001 {
		t.Errorf("Ratio() for partial overlap = %v, expected 0.5", ratio)
	}
}

func TestStringArrayComparer_SingleOverlap(t *testing.T) {
	// a,b vs b,c -> intersection = {b} = 1, union = {a,b,c} = 3
	// Jaccard = 1/3
	sac := NewStringArrayComparer([]string{"a", "b"}, []string{"b", "c"})
	ratio := sac.Ratio()
	expected := float32(1.0) / float32(3.0)
	if math.Abs(float64(ratio)-float64(expected)) > 0.001 {
		t.Errorf("Ratio() = %v, expected %v", ratio, expected)
	}
}

func TestStringArrayComparer_DuplicatesIgnored(t *testing.T) {
	// Duplicates in input should be treated as sets
	// a,a,b vs b,b,c -> intersection = {b} = 1, union = {a,b,c} = 3
	// Jaccard = 1/3
	sac := NewStringArrayComparer([]string{"a", "a", "b"}, []string{"b", "b", "c"})
	ratio := sac.Ratio()
	expected := float32(1.0) / float32(3.0)
	if math.Abs(float64(ratio)-float64(expected)) > 0.001 {
		t.Errorf("Ratio() with duplicates = %v, expected %v", ratio, expected)
	}
}

func TestStringArrayComparer_SingleElementMatch(t *testing.T) {
	sac := NewStringArrayComparer([]string{"a"}, []string{"a"})
	ratio := sac.Ratio()
	if ratio != 1.0 {
		t.Errorf("Ratio() for single matching element = %v, expected 1.0", ratio)
	}
}

func TestStringArrayComparer_SingleElementNoMatch(t *testing.T) {
	sac := NewStringArrayComparer([]string{"a"}, []string{"b"})
	ratio := sac.Ratio()
	if ratio != 0.0 {
		t.Errorf("Ratio() for single non-matching element = %v, expected 0.0", ratio)
	}
}

func TestStringArrayComparer_Subset(t *testing.T) {
	// a,b vs a,b,c -> intersection = {a,b} = 2, union = {a,b,c} = 3
	// Jaccard = 2/3
	sac := NewStringArrayComparer([]string{"a", "b"}, []string{"a", "b", "c"})
	ratio := sac.Ratio()
	expected := float32(2.0) / float32(3.0)
	if math.Abs(float64(ratio)-float64(expected)) > 0.001 {
		t.Errorf("Ratio() for subset = %v, expected %v", ratio, expected)
	}
}

func TestStringArrayComparer_LargeArrays(t *testing.T) {
	a := make([]string, 100)
	b := make([]string, 100)
	for i := 0; i < 100; i++ {
		a[i] = string(rune('a'+i%26)) + string(rune('0'+i%10))
	}
	for i := 0; i < 50; i++ {
		b[i] = a[i] // same as a for first 50
	}
	// Different for second 50
	for i := 50; i < 100; i++ {
		b[i] = string(rune('A'+i%26)) + string(rune('0'+i%10))
	}
	sac := NewStringArrayComparer(a, b)
	ratio := sac.Ratio()
	// a has 100 unique elements, b has 100 unique elements
	// intersection = 50 (first 50 elements shared)
	// Jaccard = 50 / (100 + 100 - 50) = 50/150 = 1/3
	expected := float32(50.0) / float32(150.0)
	if math.Abs(float64(ratio)-float64(expected)) > 0.01 {
		t.Errorf("Ratio() for large arrays = %v, expected %v", ratio, expected)
	}
}
