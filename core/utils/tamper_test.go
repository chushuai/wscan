package utils

import (
	"testing"
)

func TestTamperURLParam(t *testing.T) {
	tests := []struct {
		name       string
		urlString  string
		paramName  string
		paramValue string
		expectErr  bool
		checkFunc  func(string) bool
	}{
		{
			name:       "set new param",
			urlString:  "http://example.com/path",
			paramName:  "key",
			paramValue: "value",
			expectErr:  false,
			checkFunc:  func(s string) bool { return s == "http://example.com/path?key=value" },
		},
		{
			name:       "overwrite existing param",
			urlString:  "http://example.com/path?key=old",
			paramName:  "key",
			paramValue: "new",
			expectErr:  false,
			checkFunc:  func(s string) bool { return s == "http://example.com/path?key=new" },
		},
		{
			name:       "invalid URL",
			urlString:  "://invalid",
			paramName:  "key",
			paramValue: "value",
			expectErr:  true,
			checkFunc:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := TamperURLParam(tt.urlString, tt.paramName, tt.paramValue)
			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if tt.checkFunc != nil && !tt.checkFunc(result) {
					t.Errorf("TamperURLParam result = %q, check failed", result)
				}
			}
		})
	}
}

func TestObscureHost(t *testing.T) {
	tests := []struct {
		name      string
		urlString string
		expectErr bool
	}{
		{
			name:      "simple host with port",
			urlString: "http://sub.example.com:8080/path",
			expectErr: false,
		},
		{
			name:      "invalid URL",
			urlString: "://invalid",
			expectErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ObscureHost(tt.urlString)
			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				// Check that subdomains are obscured with asterisks
				if tt.name == "simple host with port" {
					// sub.example.com:8080 should become *.example.com:8080
					if result == tt.urlString {
						t.Errorf("ObscureHost should have modified the URL, got %q", result)
					}
				}
			}
		})
	}
}

func TestMakeSimilarHost(t *testing.T) {
	tests := []struct {
		name      string
		urlString string
		num       int
		expectErr bool
	}{
		{
			name:      "add to port",
			urlString: "http://example.com:8080/path",
			num:       1,
			expectErr: false,
		},
		{
			name:      "no port specified - uses empty port",
			urlString: "http://example.com/path",
			num:       10,
			expectErr: false,
		},
		{
			name:      "invalid URL",
			urlString: "://invalid",
			num:       1,
			expectErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := MakeSimilarHost(tt.urlString, tt.num)
			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				// Just verify we got a non-empty result
				if result == "" {
					t.Errorf("MakeSimilarHost returned empty string")
				}
			}
		})
	}

	// Specific test for port arithmetic
	result, err := MakeSimilarHost("http://example.com:8080/path", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "http://example.com:8090/path" {
		t.Errorf("MakeSimilarHost with num=10 on port 8080 = %q, want http://example.com:8090/path", result)
	}
}
