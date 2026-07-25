package ci

import "os"

// IsCI determines whether the current environment is within a CI/CD pipeline.
func IsCI() bool {
	var isCI bool

	isCI, cached := isCICached()
	if cached {
		return isCI
	}

	isCI = isCIChecks()

	return isCI
}

// IsNotCI negates the result of [IsCI].
// It returns true if the current environment is not within a CI/CD pipeline.
func IsNotCI() bool {
	return !IsCI()
}

func isCICached() (isCI bool, found bool) {
	// Check from cache
	cache.m.Lock()
	isCI, found = cache.val[cacheKey]
	cache.m.Unlock()

	return
}

func isCIChecks() bool {
	var isCI bool

	for env, val := range CICDEnvVars {
		envVal := os.Getenv(env)

		if val == "" && envVal != "" {
			// Only check that the environment variable is not an empty string
			isCI = true
			break
		} else if val != "" && envVal == val {
			// Check for an exact match of environment variable & expected value
			isCI = true
			break
		}
	}

	cache.m.Lock()
	cache.val[cacheKey] = isCI
	cache.m.Unlock()

	return isCI
}
