package utils

import (
	"math"
	"testing"
)

func TestProbability_Avg(t *testing.T) {
	tests := []struct {
		name   string
		input  []float64
		expect float64
	}{
		{"empty", []float64{}, 0},
		{"single", []float64{5.0}, 5.0},
		{"two values", []float64{2.0, 4.0}, 3.0},
		{"three values", []float64{1.0, 2.0, 3.0}, 2.0},
		{"negative values", []float64{-1.0, 1.0}, 0.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Probability{Input: tt.input}
			result := p.Avg()
			if math.Abs(result-tt.expect) > 1e-9 {
				t.Errorf("Probability.Avg() = %f, want %f", result, tt.expect)
			}
		})
	}
}

func TestProbability_Sum(t *testing.T) {
	tests := []struct {
		name   string
		input  []float64
		expect float64
	}{
		{"empty", []float64{}, 0},
		{"single", []float64{5.0}, 5.0},
		{"multiple", []float64{1.0, 2.0, 3.0}, 6.0},
		{"negative", []float64{-1.0, 2.0}, 1.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Probability{Input: tt.input}
			result := p.Sum()
			if math.Abs(result-tt.expect) > 1e-9 {
				t.Errorf("Probability.Sum() = %f, want %f", result, tt.expect)
			}
		})
	}
}

func TestProbability_StdDev(t *testing.T) {
	tests := []struct {
		name   string
		input  []float64
		expect float64
	}{
		{"empty", []float64{}, 0},
		{"single value", []float64{5.0}, 0},
		{"two values", []float64{2.0, 4.0}, math.Sqrt(2.0)}, // sample stddev
		{"same values", []float64{3.0, 3.0}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Probability{Input: tt.input}
			result := p.StdDev()
			if math.Abs(result-tt.expect) > 1e-9 {
				t.Errorf("Probability.StdDev() = %f, want %f", result, tt.expect)
			}
		})
	}
}

func TestProbability_StdDev_KnownValues(t *testing.T) {
	// Test with known dataset: [2, 4, 4, 4, 5, 5, 7, 9]
	// Mean = 5, sample stddev ≈ 2.138090
	p := &Probability{Input: []float64{2, 4, 4, 4, 5, 5, 7, 9}}
	result := p.StdDev()
	// The sample variance calculation: sum of (x-mean)^2 / (n-1)
	// (9+1+1+1+0+0+4+16)/(7) = 32/7 ≈ 4.571, stddev ≈ 2.138
	expected := math.Sqrt(32.0 / 7.0)
	if math.Abs(result-expected) > 1e-9 {
		t.Errorf("Probability.StdDev() = %f, want %f", result, expected)
	}
}
