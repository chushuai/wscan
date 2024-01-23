package sarif

// PropertyBagis a set of name/value pair that can store extra metadata
type PropertyBag interface{}

// Level specifies severity of the level
type Level string

const (
	None    Level = "none"
	Note    Level = "note"
	Warning Level = "warning"
	Error   Level = "error"
)

type Kind string

const (
	NotApplicable Kind = "notApplicable"
	Pass          Kind = "pass"
	Fail          Kind = "fail"
	Review        Kind = "review"
	Open          Kind = "open"
	Information   Kind = "informational"
)

// SarifLog is top level object that represents the log file as a whole
type SarifLog struct {
	Version string `json:"version"`
	Schema  string `json:"$schema,omitempty"` // URI of SARIF Schema
	Runs    []Run  `json:"runs"`
}

// Run represents a single invocation of a single analysis tool
type Run struct {
	Tool        Tool         `json:"tool"`
	Result      []Result     `json:"results,omitempty"`
	Invocations []Invocation `json:"invocations,omitempty"`
}

// The runtime environment of the analysis tool run
type Invocation struct {
	CommandLine          string             `json:"commandLine,omitempty"`
	Arguments            []string           `json:"arguments,omitempty"`
	ResponseFiles        []ArtifactLocation `json:"responseFiles,omitempty"`
	StartTimeUtc         string             `json:"startTimeUtc,omitempty"` // UTC Time when run started
	EndTimeUtc           string             `json:"endTimeUtc,omitempty"`   // UTC Time when run stopped
	ExecutionSuccessful  bool               `json:"executionSuccessful"`
	ExecutableLocation   ArtifactLocation   `json:"executableLocation,omitempty"`
	WorkingDirectory     ArtifactLocation   `json:"workingDirectory,omitempty"`
	EnvironmentVariables map[string]string  `json:"environmentVariables,omitempty"`
	Stdin                ArtifactLocation   `json:"stdin,omitempty"`
	Stdout               ArtifactLocation   `json:"stdout,omitempty"`
	Stderr               ArtifactLocation   `json:"stderr,omitempty"`
	Properties           PropertyBag        `json:"properties,omitempty"`
}

// Tool describes the analysis tool that produced the run
type Tool struct {
	Driver     ToolComponent   `json:"driver"`               // Tool Driver i.e Actual tool
	Extensions []ToolComponent `json:"extensions,omitempty"` // Tool Extensions/Plugins
	Properties PropertyBag     `json:"properties,omitempty"`
}

// A component of a tool ex: plugin ,template, driver etc
type ToolComponent struct {
	GUID             string                    `json:"guid,omitempty"` //"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
	Name             string                    `json:"name,omitempty"`
	Organization     string                    `json:"organization,omitempty"`
	Product          string                    `json:"product,omitempty"` // A product suite to which the tool component belongs
	ShortDescription *MultiformatMessageString `json:"shortDescription,omitempty"`
	FullDescription  *MultiformatMessageString `json:"fullDescription,omitempty"`
	FullName         string                    `json:"fullName,omitempty"` // Name Along with version
	SemanticVersion  string                    `json:"semanticVersion,omitempty"`
	ReleaseDateUTC   string                    `json:"releaseDateUtc,omitempty"`
	DownloadURI      string                    `json:"downloadUri,omitempty"`
	Notifications    []ReportingDescriptor     `json:"notifications,omitempty"`
	Rules            []ReportingDescriptor     `json:"rules,omitempty"`
	Locations        []ArtifactLocation        `json:"locations,omitempty"`
	Properties       PropertyBag               `json:"properties,omitempty"`
}

// Metadata that describes a specific report produced by the tool
type ReportingDescriptor struct {
	Id               string                    `json:"id,omitempty"`
	Name             string                    `json:"name,omitempty"`
	ShortDescription *MultiformatMessageString `json:"shortDescription,omitempty"`
	FullDescription  *MultiformatMessageString `json:"fullDescription,omitempty"`
	MessageStrings   *MultiformatMessageString `json:"messageStrings,omitempty"`
	Properties       PropertyBag               `json:"properties,omitempty"`
}

// Result contains result produced by analysis tool
type Result struct {
	RuleId         string                       `json:"ruleId,omitempty"`
	RuleIndex      int                          `json:"ruleIndex,omitempty"` //The index within the tool component rules array
	Rank           int                          `json:"rank,omitempty"`      // Specifies the relative priority of the report
	Rule           ReportingDescriptorReference `json:"rule,omitempty"`
	Level          Level                        `json:"level,omitempty"`
	Kind           Kind                         `json:"kind,omitempty"`
	Message        *Message                     `json:"message,omitempty"`
	AnalysisTarget ArtifactLocation             `json:"analysisTarget,omitempty"`
	WebRequest     WebRequest                   `json:"webRequest,omitempty"`
	WebResponse    WebResponse                  `json:"webResponse,omitempty"`
	Properties     PropertyBag                  `json:"properties,omitempty"`
	Locations      []Location                   `json:"locations,omitempty"` // location where result was detected
	// Attachments    interface{}                  `json:"attachments,omitempty"`
}

// Location
type Location struct {
	Id               int              `json:"id,omitempty"`
	Message          *Message         `json:"message,omitempty"`
	PhysicalLocation PhysicalLocation `json:"physicalLocation,omitempty"`
}

// PhysicalLocation
type PhysicalLocation struct {
	Address          Address          `json:"address,omitempty"`
	ArtifactLocation ArtifactLocation `json:"artifactLocation,omitempty"`
	Properties       PropertyBag      `json:"properties,omitempty"`
}

// WebRequest describes http request
type WebRequest struct {
	Protocol   string            `json:"protocol,omitempty"`
	Version    string            `json:"version,omitempty"`
	Target     string            `json:"target,omitempty"`
	Method     string            `json:"method,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Parameters map[string]string `json:"parameters,omitempty"`
	Body       ArtifactContent   `json:"body,omitempty"`
	Properties PropertyBag       `json:"properties,omitempty"`
}

// WebResponse describes http Response
type WebResponse struct {
	Protocol   string            `json:"protocol,omitempty"`
	Version    string            `json:"version,omitempty"`
	StatusCode int               `json:"statusCode,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       ArtifactContent   `json:"body,omitempty"`
	Properties PropertyBag       `json:"properties,omitempty"`
}

// ReportingDescriptorReference contains Information about how to locate a relevant reporting descriptor
type ReportingDescriptorReference struct {
	Id            string        `json:"id,omitempty"`
	Index         int           `json:"index,omitempty"`
	GUID          string        `json:"guid,omitempty"`
	ToolComponent ToolComponent `json:"toolComponent,omitempty"`
	Properties    PropertyBag   `json:"properties,omitempty"`
}

// Encapsulates a message intended to be read by the end user
type Message struct {
	Text       string      `json:"text,omitempty"`
	Markdown   string      `json:"markdown,omitempty"`
	Id         string      `json:"id,omitempty"`
	Arguments  []string    `json:"arguments,omitempty"`
	Properties PropertyBag `json:"properties,omitempty"`
}

// A message string or message format string rendered in multiple formats
type MultiformatMessageString struct {
	Text       string      `json:"text,omitempty"`
	Markdown   string      `json:"markdown,omitempty"`
	Properties PropertyBag `json:"properties,omitempty"`
}

// Specifies Location of the Artifact
type ArtifactLocation struct {
	Uri         string      `json:"uri,omitempty"`
	Description *Message    `json:"description,omitempty"`
	Properties  PropertyBag `json:"properties,omitempty"`
}

// Represents Content of Artifact
type ArtifactContent struct {
	Text       string      `json:"text,omitempty"`   // UTF-8 encoded content
	Binary     string      `json:"binary,omitempty"` // Base64 Encoded String
	Properties PropertyBag `json:"properties,omitempty"`
}

// A physical or virtual address, or a range of addresses, in an 'addressable region' (memory or a binary file)
type Address struct {
	Length             int         `json:"length,omitempty"` // number of bytes of address
	Kind               string      `json:"kind,omitempty"`
	Name               string      `json:"name,omitempty"`
	FullyQualifiedName string      `json:"fullyQualifiedName,omitempty"`
	Properties         PropertyBag `json:"properties,omitempty"`
}
