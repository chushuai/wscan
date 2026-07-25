package crawler

import (
	"testing"
)

func TestParseSourceMap(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr bool
		wantVer int
		wantSrc int
	}{
		{
			name: "valid source map",
			content: `{
				"version": 3,
				"file": "main.js",
				"sourceRoot": "",
				"sources": ["main.ts", "lib.ts"],
				"sourcesContent": ["var a = 1;", "var b = 2;"],
				"names": [],
				"mappings": "AAAA"
			}`,
			wantErr: false,
			wantVer: 3,
			wantSrc: 2,
		},
		{
			name: "valid source map with empty sourcesContent",
			content: `{
				"version": 3,
				"sources": ["app.js"],
				"names": ["foo"],
				"mappings": "AAAA"
			}`,
			wantErr: false,
			wantVer: 3,
			wantSrc: 1,
		},
		{
			name:    "invalid JSON",
			content: `{invalid json}`,
			wantErr: true,
		},
		{
			name:    "empty string",
			content: "",
			wantErr: true,
		},
		{
			name: "minimal valid source map",
			content: `{
				"version": 3,
				"sources": [],
				"mappings": ""
			}`,
			wantErr: false,
			wantVer: 3,
			wantSrc: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm, err := ParseSourceMap(tt.content)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if sm.Version != tt.wantVer {
				t.Errorf("Version = %d, want %d", sm.Version, tt.wantVer)
			}
			if len(sm.Sources) != tt.wantSrc {
				t.Errorf("len(Sources) = %d, want %d", len(sm.Sources), tt.wantSrc)
			}
		})
	}
}

func TestParseSourceMapSourcesContent(t *testing.T) {
	content := `{
		"version": 3,
		"sources": ["a.js", "b.js"],
		"sourcesContent": ["content_a", "content_b"],
		"mappings": "AAAA"
	}`
	sm, err := ParseSourceMap(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sm.SourcesContent) != 2 {
		t.Fatalf("len(SourcesContent) = %d, want 2", len(sm.SourcesContent))
	}
	if sm.SourcesContent[0] != "content_a" {
		t.Errorf("SourcesContent[0] = %s, want content_a", sm.SourcesContent[0])
	}
	if sm.SourcesContent[1] != "content_b" {
		t.Errorf("SourcesContent[1] = %s, want content_b", sm.SourcesContent[1])
	}
}

func TestParseSourceMapFields(t *testing.T) {
	content := `{
		"version": 3,
		"file": "bundle.min.js",
		"sourceRoot": "/src/",
		"sources": ["module1.ts", "module2.ts", "module3.ts"],
		"names": ["add", "subtract", "multiply"],
		"mappings": "AAAA;BBBB;CCCC"
	}`
	sm, err := ParseSourceMap(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sm.File != "bundle.min.js" {
		t.Errorf("File = %s, want bundle.min.js", sm.File)
	}
	if sm.SourceRoot != "/src/" {
		t.Errorf("SourceRoot = %s, want /src/", sm.SourceRoot)
	}
	if len(sm.Names) != 3 {
		t.Errorf("len(Names) = %d, want 3", len(sm.Names))
	}
	if sm.Mappings != "AAAA;BBBB;CCCC" {
		t.Errorf("Mappings = %s, want AAAA;BBBB;CCCC", sm.Mappings)
	}
}
