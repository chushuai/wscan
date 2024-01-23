package sarif

import (
	"encoding/json"
	"os"
)

// Report encapsulates SarifLog Object and generates .sarif Report
type Report struct {
	Sarif *SarifLog // SarifLog Object
	run   Run       // Describes a single run of an analysis tool
}

// RegisterTool registers tool details
func (r *Report) RegisterTool(driver ToolComponent) {
	r.run.Tool.Driver = driver
}

// RegisterToolExtension registers tool plugins/extensions/templates
func (r *Report) RegisterToolExtension(extensions []ToolComponent) {
	r.run.Tool.Extensions = extensions
}

// RegisterToolInvocation registers runtime enviornment when tool was run
func (r *Report) RegisterToolInvocation(invocation Invocation) {
	r.run.Invocations = append(r.run.Invocations, invocation)
}

// RegisterResult registers result
func (r *Report) RegisterResult(result Result) {
	r.run.Result = append(r.run.Result, result)
}

// Export
func (r *Report) Export() ([]byte, error) {
	r.Sarif.Runs = append(r.Sarif.Runs, r.run)
	bin, err := json.MarshalIndent(r.Sarif, "", "\t")
	return bin, err
}

// NewReport Creates New Report Instance
func NewReport() *Report {
	sf := SarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs:    []Run{},
	}

	sarifExporter := Report{
		Sarif: &sf,
	}
	run := Run{
		Invocations: []Invocation{},
		Result:      []Result{},
	}
	sarifExporter.run = run

	return &sarifExporter
}

func OpenReport(filename string) (*Report, error) {
	var sarifObject SarifLog

	bin, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(bin, &sarifObject); err != nil {
		return nil, err
	}
	report := Report{
		Sarif: &sarifObject,
	}
	return &report, nil
}
