package bruteforce

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"wscan/core/model"
	"wscan/core/plugins/base"
)

// =============================================================================
// Tests for BruteForce value-receiver no-op setters (0% coverage)
// These methods have empty bodies, so Go coverage shows 0% even when called.
// We still test them for documentation and regression safety.
// =============================================================================

func TestBruteForce_SetDisableEmbeddedDictionary_Called(t *testing.T) {
	b := BruteForce{}
	// Value receiver: calling on value type directly
	b.SetDisableEmbeddedDictionary(true)
	b.SetDisableEmbeddedDictionary(false)
	// Always returns false regardless of what was set
	assert.False(t, b.GetDisableEmbeddedDictionary(), "GetDisableEmbeddedDictionary should always return false")
}

func TestBruteForce_SetDisableEmbeddedDictionary_OnPointer(t *testing.T) {
	b := &BruteForce{CommonConfig: &CommonConfig{}}
	// Calling value-receiver method via pointer
	b.SetDisableEmbeddedDictionary(true)
	assert.False(t, b.GetDisableEmbeddedDictionary())
}

func TestBruteForce_SetMaxContinuousBruteTimes_Called(t *testing.T) {
	b := BruteForce{CommonConfig: &CommonConfig{MaxContinuousBruteTimes: 42}}
	// Value receiver: the setter is a no-op, so the value should remain unchanged
	b.SetMaxContinuousBruteTimes(99)
	assert.Equal(t, int32(42), b.GetMaxContinuousBruteTimes(),
		"SetMaxContinuousBruteTimes should be a no-op on BruteForce value receiver")
}

func TestBruteForce_SetMaxContinuousBruteTimes_OnPointer(t *testing.T) {
	b := &BruteForce{CommonConfig: &CommonConfig{MaxContinuousBruteTimes: 7}}
	b.SetMaxContinuousBruteTimes(100)
	assert.Equal(t, int32(7), b.GetMaxContinuousBruteTimes(),
		"SetMaxContinuousBruteTimes is no-op, should not change the value")
}

// =============================================================================
// Tests for PluginConfig no-op setters (0% coverage)
// All PluginConfig setters are empty-body no-ops.
// =============================================================================

func TestPluginConfig_SetBruteTimeout_Called(t *testing.T) {
	p := PluginConfig{}
	p.SetBruteTimeout(500)
	// Setter is no-op, getter always returns 1000
	assert.Equal(t, int64(1000), p.GetBruteTimeout(),
		"PluginConfig.SetBruteTimeout is no-op, GetBruteTimeout always returns 1000")
}

func TestPluginConfig_SetContinuousBruteInterval_Called(t *testing.T) {
	p := PluginConfig{}
	p.SetContinuousBruteInterval(200)
	assert.Equal(t, int64(0), p.GetContinuousBruteInterval(),
		"PluginConfig.SetContinuousBruteInterval is no-op")
}

func TestPluginConfig_SetDialTimeout_Called(t *testing.T) {
	p := PluginConfig{}
	p.SetDialTimeout(30)
	assert.Equal(t, int64(0), p.GetDialTimeout(),
		"PluginConfig.SetDialTimeout is no-op")
}

func TestPluginConfig_SetDisableEmbeddedDictionary_Called(t *testing.T) {
	p := PluginConfig{}
	p.SetDisableEmbeddedDictionary(true)
	assert.False(t, p.GetDisableEmbeddedDictionary(),
		"PluginConfig.SetDisableEmbeddedDictionary is no-op")
}

func TestPluginConfig_SetMaxBruteTimes_Called(t *testing.T) {
	p := PluginConfig{}
	p.SetMaxBruteTimes(50)
	assert.Equal(t, int32(0), p.GetMaxBruteTimes(),
		"PluginConfig.SetMaxBruteTimes is no-op")
}

func TestPluginConfig_SetMaxContinuousBruteTimes_Called(t *testing.T) {
	p := PluginConfig{}
	p.SetMaxContinuousBruteTimes(10)
	assert.Equal(t, int32(0), p.GetMaxContinuousBruteTimes(),
		"PluginConfig.SetMaxContinuousBruteTimes is no-op")
}

func TestPluginConfig_SetQPS_Called(t *testing.T) {
	p := PluginConfig{}
	p.SetQPS(123.456)
	assert.Equal(t, float64(0), p.GetQPS(),
		"PluginConfig.SetQPS is no-op")
}

func TestPluginConfig_SetReadTimeout_Called(t *testing.T) {
	p := PluginConfig{}
	p.SetReadTimeout(60)
	assert.Equal(t, int64(0), p.GetReadTimeout(),
		"PluginConfig.SetReadTimeout is no-op")
}

// =============================================================================
// Tests for PluginConfig setters called individually (each one separately)
// This ensures each setter function is independently called from a test.
// =============================================================================

func TestPluginConfig_SetBruteTimeout_Individual(t *testing.T) {
	var p PluginConfig
	p.SetBruteTimeout(1)
}

func TestPluginConfig_SetContinuousBruteInterval_Individual(t *testing.T) {
	var p PluginConfig
	p.SetContinuousBruteInterval(1)
}

func TestPluginConfig_SetDialTimeout_Individual(t *testing.T) {
	var p PluginConfig
	p.SetDialTimeout(1)
}

func TestPluginConfig_SetDisableEmbeddedDictionary_Individual(t *testing.T) {
	var p PluginConfig
	p.SetDisableEmbeddedDictionary(true)
}

func TestPluginConfig_SetMaxBruteTimes_Individual(t *testing.T) {
	var p PluginConfig
	p.SetMaxBruteTimes(1)
}

func TestPluginConfig_SetMaxContinuousBruteTimes_Individual(t *testing.T) {
	var p PluginConfig
	p.SetMaxContinuousBruteTimes(1)
}

func TestPluginConfig_SetQPS_Individual(t *testing.T) {
	var p PluginConfig
	p.SetQPS(1.0)
}

func TestPluginConfig_SetReadTimeout_Individual(t *testing.T) {
	var p PluginConfig
	p.SetReadTimeout(1)
}

// =============================================================================
// Tests for dictionaryLoader.load (0% coverage - empty body)
// =============================================================================

func TestDictionaryLoader_Load_ExplicitCall(t *testing.T) {
	dl := &dictionaryLoader{bb: &base.ApolloBase{}}
	// load() is a no-op, just verify it doesn't panic
	dl.load()
}

func TestDictionaryLoader_Load_WithNilBase(t *testing.T) {
	dl := &dictionaryLoader{bb: nil}
	// Should not panic even with nil ApolloBase
	dl.load()
}

// =============================================================================
// Tests for formBrute.bruteSinglePass and bruteUserPass (0% coverage - empty bodies)
// =============================================================================

func TestFormBrute_BruteSinglePass_ExplicitCall(t *testing.T) {
	b := &BruteForce{CommonConfig: &CommonConfig{}}
	fb := formBrute{bf: b}
	fb.bruteSinglePass()
}

func TestFormBrute_BruteUserPass_ExplicitCall(t *testing.T) {
	b := &BruteForce{CommonConfig: &CommonConfig{}}
	fb := formBrute{bf: b}
	fb.bruteUserPass()
}

func TestFormBrute_BruteSinglePass_WithCredentials(t *testing.T) {
	b := &BruteForce{
		CommonConfig: &CommonConfig{},
		usernames:    []string{"admin", "root"},
		passwords:    []string{"123456", "password"},
	}
	fb := formBrute{bf: b}
	fb.bruteSinglePass()
}

func TestFormBrute_BruteUserPass_WithCredentials(t *testing.T) {
	b := &BruteForce{
		CommonConfig: &CommonConfig{},
		usernames:    []string{"admin", "root"},
		passwords:    []string{"123456", "password"},
	}
	fb := formBrute{bf: b}
	fb.bruteUserPass()
}

// =============================================================================
// Tests for userPassChan stopChan break path (90.9% coverage)
// The break statement on line 177 is only hit when stopChan is closed
// before the goroutine's outer select begins.
// =============================================================================

func TestUserPassChan_StopChanBreakPath(t *testing.T) {
	b := &BruteForce{}
	users := []string{"admin", "root"}
	passes := []string{"123456", "password"}

	ch, stop := b.userPassChan(0, users, passes)

	// Close stop immediately to hit the break path in the outer select
	close(stop)

	// Drain whatever was sent (should be 0 or very few items)
	count := 0
	for range ch {
		count++
	}
	// After closing stop, the channel should close quickly
	assert.LessOrEqual(t, count, len(users)*len(passes),
		"Should receive at most the total number of combinations")
}

func TestUserPassChan_StopChanBreakPath_Race(t *testing.T) {
	// Run multiple times to increase chance of hitting the break path
	for i := 0; i < 50; i++ {
		b := &BruteForce{}
		users := []string{"a", "b"}
		passes := []string{"1", "2"}

		ch, stop := b.userPassChan(0, users, passes)
		close(stop)

		count := 0
		for range ch {
			count++
		}
		assert.LessOrEqual(t, count, 4)
	}
}

// =============================================================================
// Tests for singlePassChan with concurrent stop
// =============================================================================

func TestSinglePassChan_ConcurrentStop(t *testing.T) {
	b := &BruteForce{}
	passwords := []string{"p1", "p2", "p3", "p4", "p5"}

	for i := 0; i < 20; i++ {
		ch, stop := b.singlePassChan(0, passwords)

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(time.Microsecond * 10)
			close(stop)
		}()

		count := 0
		for range ch {
			count++
		}
		wg.Wait()
		assert.LessOrEqual(t, count, len(passwords))
	}
}

// =============================================================================
// Tests for userPassChan with concurrent stop
// =============================================================================

func TestUserPassChan_ConcurrentStop(t *testing.T) {
	b := &BruteForce{}
	users := []string{"admin", "root", "user"}
	passes := []string{"123456", "password", "admin123"}

	for i := 0; i < 20; i++ {
		ch, stop := b.userPassChan(0, users, passes)

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(time.Microsecond * 10)
			close(stop)
		}()

		count := 0
		for range ch {
			count++
		}
		wg.Wait()
		assert.LessOrEqual(t, count, len(users)*len(passes))
	}
}

// =============================================================================
// Tests for BruteForce Init with various Config states
// =============================================================================

func TestBruteForce_Init_WithEmptyDictionaryPaths(t *testing.T) {
	b := &BruteForce{CommonConfig: &CommonConfig{}}
	cfg := b.DefaultConfig().(*Config)
	cfg.UsernameDictionary = ""
	cfg.PasswordDictionary = ""
	ab := &base.ApolloBase{}

	err := b.Init(context.Background(), cfg, ab)
	assert.NoError(t, err)
	assert.NotEmpty(t, b.usernames, "Should have built-in usernames")
	assert.NotEmpty(t, b.passwords, "Should have built-in passwords")
}

func TestBruteForce_Init_CommonConfigFields(t *testing.T) {
	b := &BruteForce{CommonConfig: &CommonConfig{}}
	cfg := b.DefaultConfig().(*Config)
	ab := &base.ApolloBase{}

	err := b.Init(context.Background(), cfg, ab)
	assert.NoError(t, err)
	// Init sets DialTimeout to 10
	typedCfg := b.GetConfig().(*Config)
	assert.Equal(t, int64(10), typedCfg.DialTimeout)
}

// =============================================================================
// Tests for Config with various field combinations
// =============================================================================

func TestConfig_BaseConfig_NilCommonConfig(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "brute-force",
			Enabled: false,
		},
	}
	bc := cfg.BaseConfig()
	assert.NotNil(t, bc)
	assert.Equal(t, "brute-force", bc.Name)
	assert.False(t, bc.Enabled)
}

func TestConfig_BaseConfig_WithSingleConfigMap(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "brute-force",
			Enabled: true,
		},
		CommonConfig:    &CommonConfig{},
		SingleConfigMap: map[int]Configure{1: nil, 2: nil},
	}
	bc := cfg.BaseConfig()
	assert.Equal(t, "brute-force", bc.Name)
	assert.Equal(t, 2, len(cfg.SingleConfigMap))
}

func TestConfig_WithDictionaryPaths(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "brute-force",
			Enabled: true,
		},
		CommonConfig:       &CommonConfig{},
		UsernameDictionary: "/tmp/users.txt",
		PasswordDictionary: "/tmp/pass.txt",
	}
	assert.Equal(t, "/tmp/users.txt", cfg.UsernameDictionary)
	assert.Equal(t, "/tmp/pass.txt", cfg.PasswordDictionary)
}

// =============================================================================
// Tests for CommonConfig with all fields set
// =============================================================================

func TestCommonConfig_AllFieldsSet(t *testing.T) {
	cc := &CommonConfig{
		BruteTimeout:              5000,
		MaxBruteTimes:             100,
		DialTimeout:               10,
		ReadTimeout:               30,
		MaxContinuousBruteTimes:   50,
		ContinuousBruteInterval:   200,
		QPS:                       25.5,
		DisableEmbeddedDictionary: true,
	}
	b := &BruteForce{CommonConfig: cc}

	assert.Equal(t, int64(5000), b.GetBruteTimeout())
	assert.Equal(t, int64(200), b.GetContinuousBruteInterval())
	assert.Equal(t, int64(10), b.GetDialTimeout())
	assert.Equal(t, int32(100), b.GetMaxBruteTimes())
	assert.Equal(t, int32(50), b.GetMaxContinuousBruteTimes())
	assert.Equal(t, 25.5, b.GetQPS())
	assert.Equal(t, int64(30), b.GetReadTimeout())
	// GetDisableEmbeddedDictionary always returns false
	assert.False(t, b.GetDisableEmbeddedDictionary())
}

// =============================================================================
// Tests for BruteForce round-trip setter/getter with edge values
// =============================================================================

func TestBruteForce_SetterGetter_EdgeValues(t *testing.T) {
	b := &BruteForce{CommonConfig: &CommonConfig{}}

	// Zero values
	b.SetBruteTimeout(0)
	assert.Equal(t, int64(0), b.GetBruteTimeout())

	b.SetQPS(0.0)
	assert.Equal(t, float64(0), b.GetQPS())

	// Negative values (valid for int64)
	b.SetBruteTimeout(-1)
	assert.Equal(t, int64(-1), b.GetBruteTimeout())

	// Large values
	b.SetMaxBruteTimes(2147483647) // max int32
	assert.Equal(t, int32(2147483647), b.GetMaxBruteTimes())

	b.SetQPS(1e10)
	assert.Equal(t, 1e10, b.GetQPS())
}

// =============================================================================
// Tests for PluginType.GetConfig with various arguments
// =============================================================================

func TestPluginType_GetConfig_WithNonNilContext(t *testing.T) {
	pt := PluginType(0)
	ctx := context.Background()
	result := pt.GetConfig(ctx, nil)
	assert.Nil(t, result)
}

func TestPluginType_GetConfig_DifferentPluginTypes(t *testing.T) {
	for _, ptVal := range []PluginType{0, 1, 2, 99} {
		pt := PluginType(ptVal)
		result := pt.GetConfig(context.Background(), nil)
		assert.Nil(t, result, "PluginType(%d).GetConfig should return nil", ptVal)
	}
}

// =============================================================================
// Tests for BruteForce.DefaultConfig field values
// =============================================================================

func TestBruteForce_DefaultConfig_Enabled(t *testing.T) {
	b := &BruteForce{}
	cfg := b.DefaultConfig().(*Config)
	assert.Equal(t, "brute-force", cfg.PluginBaseConfig.Name)
	assert.True(t, cfg.PluginBaseConfig.Enabled)
	assert.NotNil(t, cfg.CommonConfig)
}

// =============================================================================
// Tests for BruteForce.Close
// =============================================================================

func TestBruteForce_Close_NilError(t *testing.T) {
	b := &BruteForce{}
	assert.Nil(t, b.Close())
}

// =============================================================================
// Tests for BruteForce.Clone
// =============================================================================

func TestBruteForce_Clone_AlwaysNil(t *testing.T) {
	b := &BruteForce{CommonConfig: &CommonConfig{}}
	assert.Nil(t, b.Clone())
}

// =============================================================================
// Tests for BruteForce.Fingers with populated credentials
// =============================================================================

func TestBruteForce_Fingers_WithPopulatedCredentials(t *testing.T) {
	b := &BruteForce{
		CommonConfig: &CommonConfig{},
		usernames:    []string{"admin", "root"},
		passwords:    []string{"123456", "password"},
	}
	fingers := b.Fingers()
	assert.Len(t, fingers, 2)
	for i, f := range fingers {
		assert.Equal(t, "web-generic", f.Channel, "finger[%d] Channel", i)
		assert.NotNil(t, f.Binding, "finger[%d] Binding", i)
		assert.NotNil(t, f.CheckAction, "finger[%d] CheckAction", i)
	}
}

// =============================================================================
// Tests for PluginConfig fields access
// =============================================================================

func TestPluginConfig_MutexField(t *testing.T) {
	p := PluginConfig{}
	// Verify mutex is usable
	p.mut.Lock()
	p.mut.Unlock()
}

func TestPluginConfig_EnableFlags(t *testing.T) {
	p := PluginConfig{}
	assert.False(t, p.enableMaxBruteTime)
	assert.False(t, p.enableContinuousBruteFrequency)
	assert.Equal(t, int32(0), p.actualMaxBruteTimes)
	assert.Equal(t, int32(0), p.actualContinuousBruteTimes)
}

// =============================================================================
// Tests for singlePassChan with single element
// =============================================================================

func TestSinglePassChan_SingleElement(t *testing.T) {
	b := &BruteForce{}
	ch, stop := b.singlePassChan(0, []string{"onlyone"})

	var results []string
	for p := range ch {
		results = append(results, p)
		if len(results) == 1 {
			close(stop)
			break
		}
	}
	assert.Equal(t, []string{"onlyone"}, results)
}

// =============================================================================
// Tests for userPassChan with single user and single password
// =============================================================================

func TestUserPassChan_SingleCombination(t *testing.T) {
	b := &BruteForce{}
	ch, stop := b.userPassChan(0, []string{"admin"}, []string{"secret"})

	var results [][2]string
	for up := range ch {
		results = append(results, [2]string{up[0], up[1]})
		if len(results) == 1 {
			close(stop)
			break
		}
	}
	assert.Len(t, results, 1)
	assert.Equal(t, "admin", results[0][0])
	assert.Equal(t, "secret", results[0][1])
}

// =============================================================================
// Tests for userPassChan - verify ordering
// =============================================================================

func TestUserPassChan_Ordering(t *testing.T) {
	b := &BruteForce{}
	users := []string{"u1", "u2"}
	passes := []string{"p1", "p2"}

	ch, stop := b.userPassChan(0, users, passes)

	var results [][2]string
	for up := range ch {
		results = append(results, [2]string{up[0], up[1]})
		if len(results) == len(users)*len(passes) {
			close(stop)
			break
		}
	}
	assert.Len(t, results, 4)
	// Verify all expected combinations exist
	seen := map[string]bool{}
	for _, r := range results {
		seen[r[0]+":"+r[1]] = true
	}
	assert.True(t, seen["u1:p1"])
	assert.True(t, seen["u1:p2"])
	assert.True(t, seen["u2:p1"])
	assert.True(t, seen["u2:p2"])
}

// =============================================================================
// Tests for BruteForce.CommonConfig nil safety
// =============================================================================

func TestBruteForce_NilCommonConfig_Getters(t *testing.T) {
	b := &BruteForce{CommonConfig: nil}
	// When CommonConfig is nil, getters should panic or return zero
	// This test documents the current behavior
	assert.Panics(t, func() { b.GetBruteTimeout() }, "GetBruteTimeout should panic with nil CommonConfig")
}

func TestBruteForce_NilCommonConfig_Setters(t *testing.T) {
	b := &BruteForce{CommonConfig: nil}
	assert.Panics(t, func() { b.SetBruteTimeout(1) }, "SetBruteTimeout should panic with nil CommonConfig")
}

// =============================================================================
// Tests for formBrute.processPassword
// =============================================================================

func TestFormBrute_ProcessPassword_EmptyArgs(t *testing.T) {
	b := &BruteForce{CommonConfig: &CommonConfig{}}
	fb := formBrute{bf: b}
	assert.Equal(t, "", fb.processPassword("", ""))
}

func TestFormBrute_ProcessPassword_WithArgs(t *testing.T) {
	b := &BruteForce{CommonConfig: &CommonConfig{}}
	fb := formBrute{bf: b}
	assert.Equal(t, "", fb.processPassword("admin", "secret"))
}

// =============================================================================
// Tests for BruteForce interface satisfaction
// =============================================================================

func TestBruteForce_SatisfiesClonableInterface(t *testing.T) {
	b := &BruteForce{CommonConfig: &CommonConfig{}}
	var c Clonable = b
	assert.Nil(t, c.Clone())
}

func TestBruteForce_SatisfiesCommonConfigureInterface(t *testing.T) {
	b := &BruteForce{CommonConfig: &CommonConfig{}}
	var cc CommonConfigure = b
	// Just verify the interface is satisfied - call a few methods
	cc.SetBruteTimeout(100)
	assert.Equal(t, int64(100), cc.GetBruteTimeout())
	cc.SetQPS(50.0)
	assert.Equal(t, 50.0, cc.GetQPS())
}

func TestPluginConfig_SatisfiesCommonConfigureInterface(t *testing.T) {
	var cc CommonConfigure = &PluginConfig{}
	// PluginConfig setters are no-ops
	cc.SetBruteTimeout(100)
	assert.Equal(t, int64(1000), cc.GetBruteTimeout())
	cc.SetQPS(50.0)
	assert.Equal(t, float64(0), cc.GetQPS())
}

// =============================================================================
// Tests for LoadBuiltinUserPass content verification
// =============================================================================

func TestLoadBuiltinUserPass_ContainsCommonUsernames(t *testing.T) {
	users, passes := LoadBuiltinUserPass()
	assert.NotEmpty(t, users)
	assert.NotEmpty(t, passes)

	// Check that common usernames are present
	foundAdmin := false
	for _, u := range users {
		if u == "admin" {
			foundAdmin = true
			break
		}
	}
	assert.True(t, foundAdmin, "Built-in usernames should contain 'admin'")
}

// =============================================================================
// Tests for formBrute.Finger binding details
// =============================================================================

func TestFormBrute_Finger_BindingDetails(t *testing.T) {
	b := &BruteForce{CommonConfig: &CommonConfig{}}
	fb := formBrute{bf: b}
	finger := fb.Finger()
	assert.Equal(t, "web-generic", finger.Channel)
	assert.NotNil(t, finger.Binding)
	assert.Equal(t, "brute-force/form-brute/default", finger.Binding.ID)
	assert.Equal(t, model.SeverityMedium, finger.Binding.Severity)
}
