package ci

import "sync"

// CICDEnvVars format follows the pattern:
// `environment variable`:`expected value`
//
// Note that if the provided expected value is an empty string, it implies that
// the check involves ensuring the environment variable is NOT an empty string.
var CICDEnvVars = map[string]string{
	// GitHub Actions, GitLab CI/CD, Travis CI, CircleCI
	// Bitbucket Pipelines, Drone CI, Heroku CI,
	"CI": "true",

	// Jenkins
	"JENKINS_URL": "",

	// Azure Pipelines
	"BUILD_REASON":    "",
	"AGENT_JOBSTATUS": "",

	// Bitbucket Pipelines
	"BITBUCKET_BUILD_NUMBER": "",

	// TeamCity
	"TEAMCITY_VERSION": "",

	// Bamboo
	"bamboo_buildKey": "",

	// AppVeyor
	"APPVEYOR": "true",

	// Buildkite
	"BUILDKITE": "true",

	// Semaphore
	"SEMAPHORE": "true",

	// Shippable
	"SHIPPABLE": "true",

	// GoCD
	"GO_SERVER_URL": "",

	// AWS CodeBuild
	"CODEBUILD_CI": "true",

	// Wercker
	"WERCKER": "true",

	// Strider
	"STRIDER": "true",
}

var cache = struct {
	m   sync.Mutex
	val map[string]bool
}{val: make(map[string]bool)}
