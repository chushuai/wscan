# go-ci

[![GoDoc](https://pkg.go.dev/static/frontend/badge/badge.svg)](http://pkg.go.dev/github.com/kitabisa/go-ci)
[![tests](https://github.com/kitabisa/go-ci/actions/workflows/tests.yaml/badge.svg)](https://github.com/kitabisa/go-ci/actions/workflows/tests.yaml)

A Go package that provides utilities for detecting and handling CI/CD environments.
It also has testing helper functions to conditionally skip or fail tests/benchmarks/fuzzing based on the CI/CD status.

## Usage

Use [`IsCI`](https://pkg.go.dev/github.com/kitabisa/go-ci#IsCI) or [`IsNotCI`](https://pkg.go.dev/github.com/kitabisa/go-ci#IsNotCI) to check if the current environment is within a CI/CD pipeline.

```bash
go get github.com/kitabisa/go-ci@latest
```

> [!NOTE]
> See [`CICDEnvVars`](https://pkg.go.dev/github.com/kitabisa/go-ci#CICDEnvVars) for currently supported CI/CD pipelines.

### Testing helper function

Import the `go-ci` package into your `*_test.go` files.

```go
import (
	"testing"

	"github.com/kitabisa/go-ci"
	"github.com/stretchr/testify/assert"
)

func shouldSkip(t *testing.T) {
	assert.True(t, t.Skipped())
	t.Logf("Skipping '%s' test in CI/CD environment", t.Name())
}

func TestFuncShoulNotInCI(t *testing.T) {
	defer shouldSkip(t)

	t.Setenv("CI", "true")
	ci.SkipTestIfCI(t)

	// do your test...
}
```

> [!IMPORTANT]
> Please note that the checking mechanism uses a cache, so
> do NOT simulating CI/CD environment variables in actual test cases.

### Available testing helper functions

```go
func FailBenchmarkIfCI(b *testing.B)
func FailBenchmarkIfNotCI(b *testing.B)
func FailFuzzIfCI(f *testing.F)
func FailFuzzIfNotCI(f *testing.F)
func FailTestIfCI(t *testing.T)
func FailTestIfNotCI(t *testing.T)
func SkipBenchmarkIfCI(b *testing.B)
func SkipBenchmarkIfNotCI(b *testing.B)
func SkipFuzzIfCI(f *testing.F)
func SkipFuzzIfNotCI(f *testing.F)
func SkipTestIfCI(t *testing.T)
func SkipTestIfNotCI(t *testing.T)
```

## Benchmark

```console
$ go test -race -run="^$" -bench .
goos: linux
goarch: amd64
pkg: github.com/kitabisa/go-ci
cpu: 11th Gen Intel(R) Core(TM) i9-11900H @ 2.50GHz
BenchmarkIsCI/true-16         	39761295	        28.22 ns/op	       0 B/op	       0 allocs/op
BenchmarkIsCI/false-16        	42846458	        34.67 ns/op	       0 B/op	       0 allocs/op
PASS
ok  	github.com/kitabisa/go-ci	3.680s
```

## License

`go-ci` is released by [**@dwisiswant0**](https://github.com/dwisiswant0) under the Apache 2.0 license. See [LICENSE](/LICENSE).