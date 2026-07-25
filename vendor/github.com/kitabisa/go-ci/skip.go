package ci

import "testing"

func skipIf[T Testing](f func() bool, t T) {
	if f() {
		t.SkipNow()
	}
}

// SkipTestIfCI is a testing helper function that skips the execution of a test
// if it is running within a CI/CD pipeline.
//
// Example:
//
//	func TestYourFunc(t *testing.T) {
//		defer func() {
//			println(t.Skipped())
//			// Output: true
//		}()
//
//		t.Setenv("CI", "true")
//		ci.SkipTestIfCI(t)
//
//		// do your test...
//	}
func SkipTestIfCI(t *testing.T) {
	skipIf(IsCI, t)
}

// SkipTestIfNotCI is a testing helper function that skips the execution of a
// test if it is not running within a CI/CD pipeline.
func SkipTestIfNotCI(t *testing.T) {
	skipIf(IsNotCI, t)
}

// SkipBenchmarkIfCI is a testing helper function that skips the execution of a
// benchmark if it is running within a CI/CD pipeline.
func SkipBenchmarkIfCI(b *testing.B) {
	skipIf(IsCI, b)
}

// SkipBenchmarkIfNotCI is a testing helper function that skips the execution of
// a benchmark if it is not running within a CI/CD pipeline.
func SkipBenchmarkIfNotCI(b *testing.B) {
	skipIf(IsNotCI, b)
}

// SkipFuzzIfCI is a testing helper function that skips the execution of a fuzz
// test if it is running within a CI/CD pipeline.
func SkipFuzzIfCI(f *testing.F) {
	skipIf(IsCI, f)
}

// SkipFuzzIfNotCI is a testing helper function that skips the execution of a
// fuzz test if it is not running within a CI/CD pipeline.
func SkipFuzzIfNotCI(f *testing.F) {
	skipIf(IsNotCI, f)
}
