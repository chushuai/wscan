package {{.PackageName}}

import (
    "github.com/projectdiscovery/utils/memoize"
    
    {{range .Imports}}
        {{.Name}} {{.Path}}
    {{end}}    
)

{{range .Functions}}
    {{ if .WantReturn }}
    type {{ .ResultStructType }} struct {
        {{ range .Results }}
           {{ .ResultName }} {{ .Type }}
        {{ end }}
    }
    {{ end }}
    var (
        {{ if .WantSyncOnce }}
        {{ .SyncOnceVarName }} sync.Once
        
        {{ if .WantReturn }}
        {{ .ResultStructVarName }} {{ .ResultStructType }}
        {{ end }}

        {{ end }}
    )

    {{ .Signature }} {
        {{ if .WantSyncOnce }}

        {{ .SyncOnceVarName }}.Do(func() {
            {{ if .WantReturn }}
            {{ .ResultStructFields }} = {{.SourcePackage}}.{{.Name}}()
            {{ else }}
            {{.SourcePackage}}.{{.Name}}()
            {{ end }}
        })

        {{ if .WantReturn }}
        return {{ .ResultStructFields }}
        {{ end }}
        
        {{ else }}

        h := hash("{{.Name}}", {{.ParamsNames}})
        v, _, _ := cache.Do(h, func() (interface{}, error) {
            {{ if .WantReturn }}
            {{.ResultStructVarName}} := &{{.ResultStructType}}{}
            {{ .ResultStructFields }} = {{.SourcePackage}}.{{.Name}}({{.ParamsNames}})
            return {{.ResultStructVarName}}, nil
            {{else}}
            {{.SourcePackage}}.{{.Name}}({{.ParamsNames}})
            return nil, nil
            {{end}}
        })
        {{ if .WantReturn }}
        {{.ResultStructVarName}} := v.(*{{.ResultStructType}})
        {{else}}
        _ = v
        {{end}}
        
        {{ if .WantReturn }}
        return {{ .ResultStructFields }}
        {{ end }}

        {{ end }}
    }
{{end}}  

func hash(functionName string, args ...any) string {
	var b bytes.Buffer
	b.WriteString(functionName + ":")
	for _, arg := range args {
		b.WriteString(fmt.Sprint(arg))
	}
	h := sha256.Sum256(b.Bytes())
	return hex.EncodeToString(h[:])
}

var cache *memoize.Memoizer

func init() {
	cache, _ = memoize.New(memoize.WithMaxSize(1000))
}

