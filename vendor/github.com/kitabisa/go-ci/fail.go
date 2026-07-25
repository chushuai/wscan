package ci

import "testing"

func failIf[T Testing](f func() bool, t T) {
	if f() {
		t.FailNow()
	}
}

// FailTestIfCI is a testing helper function that fails the execution of a test
// if it is running within a CI/CD pipeline.
func FailTestIfCI(t *testing.T) {
	failIf(IsCI, t)
}

// FailTestIfNotCI is a testing helper function that fails the execution of a
// test if it is not running within a CI/CD pipeline.
func FailTestIfNotCI(t *testing.T) {
	failIf(IsNotCI, t)
}

// FailBenchmarkIfCI is a testing helper function that fails the execution of a
// benchmark if it is running within a CI/CD pipeline.
func FailBenchmarkIfCI(b *testing.B) {
	failIf(IsCI, b)
}

// FailBenchmarkIfNotCI is a testing helper function that fails the execution of
// a benchmark if it is not running within a CI/CD pipeline.
func FailBenchmarkIfNotCI(b *testing.B) {
	failIf(IsNotCI, b)
}

// FailFuzzIfCI is a testing helper function that fails the execution of a fuzz
// test if it is running within a CI/CD pipeline.
func FailFuzzIfCI(f *testing.F) {
	failIf(IsCI, f)
}

// FailFuzzIfNotCI is a testing helper function that fails the execution of a
// fuzz test if it is not running within a CI/CD pipeline.
func FailFuzzIfNotCI(f *testing.F) {
	failIf(IsNotCI, f)
}
