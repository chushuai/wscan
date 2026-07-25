/*
Package ci provides utilities for detecting and handling CI/CD environments.

# Usage

  - Use [IsCI] or [IsNotCI] to check if the current environment is within a
    CI/CD pipeline.

  - Use `SkipTest*`, `SkipBenchmark*`, `SkipFuzz*`, `FailTest*`,
    `FailBenchmark*`, `FailFuzz*`, to conditionally skip or fail
    tests/benchmarks/fuzzing based on the CI/CD status.
*/
package ci
