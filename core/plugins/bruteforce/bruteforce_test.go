package bruteforce

import (
	"context"
	"testing"

	"wscan/core/plugins/base"
)

func TestBruteForce_Close(t *testing.T) {
	b := &BruteForce{}
	if err := b.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestBruteForce_DefaultConfig(t *testing.T) {
	b := &BruteForce{}
	cfg := b.DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	typedCfg, ok := cfg.(*Config)
	if !ok {
		t.Fatal("DefaultConfig() did not return *Config")
	}
	if typedCfg.PluginBaseConfig.Name != "brute-force" {
		t.Errorf("Expected Name='brute-force', got '%s'", typedCfg.PluginBaseConfig.Name)
	}
	if !typedCfg.PluginBaseConfig.Enabled {
		t.Error("Expected Enabled=true")
	}
}

func TestConfig_BaseConfig(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "brute-force",
			Enabled: true,
		},
	}
	bc := cfg.BaseConfig()
	if bc == nil {
		t.Fatal("BaseConfig() returned nil")
	}
	if bc.Name != "brute-force" {
		t.Errorf("Expected Name='brute-force', got '%s'", bc.Name)
	}
}

func TestBruteForce_GetConfig(t *testing.T) {
	b := &BruteForce{}
	// Before Init
	cfg := b.GetConfig()
	if cfg != nil {
		t.Errorf("Expected nil config before Init, got %v", cfg)
	}

	// After Init
	expectedCfg := b.DefaultConfig()
	ab := &base.ApolloBase{}
	b.Init(context.Background(), expectedCfg, ab)

	cfg = b.GetConfig()
	if cfg == nil {
		t.Fatal("Expected non-nil config after Init")
	}
}

func TestBruteForce_Init_DefaultDictionaries(t *testing.T) {
	b := &BruteForce{}
	cfg := b.DefaultConfig()
	ab := &base.ApolloBase{}

	err := b.Init(context.Background(), cfg, ab)
	if err != nil {
		t.Errorf("Init() returned error: %v", err)
	}

	// After init, usernames and passwords should be loaded from built-in dict
	if len(b.usernames) == 0 {
		t.Error("Expected non-empty usernames after Init")
	}
	if len(b.passwords) == 0 {
		t.Error("Expected non-empty passwords after Init")
	}
}

func TestBruteForce_Fingers(t *testing.T) {
	b := &BruteForce{}
	cfg := b.DefaultConfig()
	ab := &base.ApolloBase{}
	b.Init(context.Background(), cfg, ab)

	fingers := b.Fingers()
	if len(fingers) != 2 {
		t.Errorf("Expected 2 fingers (basicAuth + formBrute), got %d", len(fingers))
	}
}

func TestBruteForce_Clone(t *testing.T) {
	b := &BruteForce{}
	result := b.Clone()
	if result != nil {
		t.Errorf("Clone() should return nil, got %v", result)
	}
}

func TestBruteForce_GetterSetters(t *testing.T) {
	b := &BruteForce{}
	b.CommonConfig = &CommonConfig{}

	// Test setters and getters
	b.SetBruteTimeout(5000)
	if b.GetBruteTimeout() != 5000 {
		t.Errorf("GetBruteTimeout() = %d, want 5000", b.GetBruteTimeout())
	}

	b.SetContinuousBruteInterval(100)
	if b.GetContinuousBruteInterval() != 100 {
		t.Errorf("GetContinuousBruteInterval() = %d, want 100", b.GetContinuousBruteInterval())
	}

	b.SetDialTimeout(10)
	if b.GetDialTimeout() != 10 {
		t.Errorf("GetDialTimeout() = %d, want 10", b.GetDialTimeout())
	}

	b.SetMaxBruteTimes(100)
	if b.GetMaxBruteTimes() != 100 {
		t.Errorf("GetMaxBruteTimes() = %d, want 100", b.GetMaxBruteTimes())
	}

	b.SetQPS(50.0)
	if b.GetQPS() != 50.0 {
		t.Errorf("GetQPS() = %f, want 50.0", b.GetQPS())
	}

	b.SetReadTimeout(30)
	if b.GetReadTimeout() != 30 {
		t.Errorf("GetReadTimeout() = %d, want 30", b.GetReadTimeout())
	}

	// SetDisableEmbeddedDictionary is a no-op, just verify it doesn't panic
	b.SetDisableEmbeddedDictionary(true)
	if b.GetDisableEmbeddedDictionary() != false {
		t.Error("GetDisableEmbeddedDictionary() should always return false")
	}

	// SetMaxContinuousBruteTimes is a no-op
	b.SetMaxContinuousBruteTimes(10)
}

func TestPluginConfig_GetterSetters(t *testing.T) {
	p := PluginConfig{}

	if p.GetBruteTimeout() != 1000 {
		t.Errorf("PluginConfig.GetBruteTimeout() = %d, want 1000", p.GetBruteTimeout())
	}
	if p.GetContinuousBruteInterval() != 0 {
		t.Errorf("PluginConfig.GetContinuousBruteInterval() = %d, want 0", p.GetContinuousBruteInterval())
	}
	if p.GetDialTimeout() != 0 {
		t.Errorf("PluginConfig.GetDialTimeout() = %d, want 0", p.GetDialTimeout())
	}
	if p.GetDisableEmbeddedDictionary() != false {
		t.Errorf("PluginConfig.GetDisableEmbeddedDictionary() = %v, want false", p.GetDisableEmbeddedDictionary())
	}
	if p.GetMaxBruteTimes() != 0 {
		t.Errorf("PluginConfig.GetMaxBruteTimes() = %d, want 0", p.GetMaxBruteTimes())
	}
	if p.GetMaxContinuousBruteTimes() != 0 {
		t.Errorf("PluginConfig.GetMaxContinuousBruteTimes() = %d, want 0", p.GetMaxContinuousBruteTimes())
	}
	if p.GetQPS() != 0 {
		t.Errorf("PluginConfig.GetQPS() = %f, want 0", p.GetQPS())
	}
	if p.GetReadTimeout() != 0 {
		t.Errorf("PluginConfig.GetReadTimeout() = %d, want 0", p.GetReadTimeout())
	}

	// Setters are no-ops, verify they don't panic
	p.SetBruteTimeout(100)
	p.SetContinuousBruteInterval(100)
	p.SetDialTimeout(100)
	p.SetDisableEmbeddedDictionary(true)
	p.SetMaxBruteTimes(100)
	p.SetMaxContinuousBruteTimes(100)
	p.SetQPS(100.0)
	p.SetReadTimeout(100)
}

func TestLoadBuiltinUserPass(t *testing.T) {
	users, passwords := LoadBuiltinUserPass()
	if len(users) == 0 {
		t.Error("LoadBuiltinUserPass() returned empty users")
	}
	if len(passwords) == 0 {
		t.Error("LoadBuiltinUserPass() returned empty passwords")
	}
}

func TestLoadDict(t *testing.T) {
	users := LoadDict("dict/username.txt")
	if len(users) == 0 {
		t.Error("LoadDict('dict/username.txt') returned empty list")
	}

	passwords := LoadDict("dict/password.txt")
	if len(passwords) == 0 {
		t.Error("LoadDict('dict/password.txt') returned empty list")
	}
}

func TestSinglePassChan(t *testing.T) {
	b := &BruteForce{}
	passwords := []string{"pass1", "pass2", "pass3"}

	ch, stop := b.singlePassChan(0, passwords)
	defer close(stop)

	var results []string
	for p := range ch {
		results = append(results, p)
		if len(results) == len(passwords) {
			break
		}
	}

	if len(results) != len(passwords) {
		t.Errorf("singlePassChan: expected %d results, got %d", len(passwords), len(results))
	}
}

func TestSingleTokenChan(t *testing.T) {
	b := &BruteForce{}
	ch, stop := b.singleTokenChan("token", []string{"a", "b"})
	if ch != nil {
		t.Error("singleTokenChan should return nil channel")
	}
	if stop != nil {
		t.Error("singleTokenChan should return nil stop channel")
	}
}

func TestUserPassChan(t *testing.T) {
	b := &BruteForce{}
	users := []string{"admin", "root"}
	passwords := []string{"123456", "password"}

	ch, stop := b.userPassChan(0, users, passwords)

	var results [][2]string
	for up := range ch {
		results = append(results, [2]string{up[0], up[1]})
		if len(results) == len(users)*len(passwords) {
			close(stop)
			break
		}
	}

	expectedCount := len(users) * len(passwords)
	if len(results) != expectedCount {
		t.Errorf("userPassChan: expected %d results, got %d", expectedCount, len(results))
	}

	// Verify all combinations are present
	found := map[string]bool{}
	for _, r := range results {
		key := r[0] + ":" + r[1]
		found[key] = true
	}
	for _, u := range users {
		for _, p := range passwords {
			key := u + ":" + p
			if !found[key] {
				t.Errorf("Missing combination: %s", key)
			}
		}
	}
}

func TestBruteForce_Init_WithConfig(t *testing.T) {
	b := &BruteForce{}
	b.CommonConfig = &CommonConfig{}
	cfg := b.DefaultConfig().(*Config)
	ab := &base.ApolloBase{}

	err := b.Init(context.Background(), cfg, ab)
	if err != nil {
		t.Errorf("Init() returned error: %v", err)
	}
	// Verify usernames and passwords were loaded
	if len(b.usernames) == 0 {
		t.Error("Expected non-empty usernames after Init")
	}
	if len(b.passwords) == 0 {
		t.Error("Expected non-empty passwords after Init")
	}
}

func TestCommonConfig(t *testing.T) {
	cc := &CommonConfig{
		BruteTimeout:              5000,
		MaxBruteTimes:             100,
		DialTimeout:               10,
		ReadTimeout:               30,
		MaxContinuousBruteTimes:   50,
		ContinuousBruteInterval:   100,
		QPS:                       25.0,
		DisableEmbeddedDictionary: true,
	}
	if cc.BruteTimeout != 5000 {
		t.Errorf("CommonConfig.BruteTimeout = %d, want 5000", cc.BruteTimeout)
	}
	if cc.QPS != 25.0 {
		t.Errorf("CommonConfig.QPS = %f, want 25.0", cc.QPS)
	}
}

func TestBruteForce_MaxContinuousBruteTimes(t *testing.T) {
	b := &BruteForce{}
	b.CommonConfig = &CommonConfig{
		MaxContinuousBruteTimes: 50,
	}
	got := b.GetMaxContinuousBruteTimes()
	if got != 50 {
		t.Errorf("GetMaxContinuousBruteTimes() = %d, want 50", got)
	}
}

func TestPluginConfig_AllNoOps(t *testing.T) {
	p := PluginConfig{}
	// These are all no-op setters, just verify they don't panic and return expected values
	p.SetBruteTimeout(100)
	p.SetContinuousBruteInterval(100)
	p.SetDialTimeout(100)
	p.SetDisableEmbeddedDictionary(true)
	p.SetMaxBruteTimes(100)
	p.SetMaxContinuousBruteTimes(100)
	p.SetQPS(100.0)
	p.SetReadTimeout(100)

	// Verify the getters still return default values (setters are no-ops)
	if p.GetBruteTimeout() != 1000 {
		t.Errorf("GetBruteTimeout() = %d, want 1000", p.GetBruteTimeout())
	}
}

func TestBruteForce_GetterSetters_All(t *testing.T) {
	b := &BruteForce{}
	b.CommonConfig = &CommonConfig{}

	// Test all setters and getters
	b.SetBruteTimeout(5000)
	if b.GetBruteTimeout() != 5000 {
		t.Errorf("GetBruteTimeout() = %d, want 5000", b.GetBruteTimeout())
	}

	b.SetContinuousBruteInterval(100)
	if b.GetContinuousBruteInterval() != 100 {
		t.Errorf("GetContinuousBruteInterval() = %d, want 100", b.GetContinuousBruteInterval())
	}

	b.SetDialTimeout(10)
	if b.GetDialTimeout() != 10 {
		t.Errorf("GetDialTimeout() = %d, want 10", b.GetDialTimeout())
	}

	b.SetMaxBruteTimes(100)
	if b.GetMaxBruteTimes() != 100 {
		t.Errorf("GetMaxBruteTimes() = %d, want 100", b.GetMaxBruteTimes())
	}

	b.SetQPS(50.0)
	if b.GetQPS() != 50.0 {
		t.Errorf("GetQPS() = %f, want 50.0", b.GetQPS())
	}

	b.SetReadTimeout(30)
	if b.GetReadTimeout() != 30 {
		t.Errorf("GetReadTimeout() = %d, want 30", b.GetReadTimeout())
	}

	// These are no-op or return defaults
	b.SetDisableEmbeddedDictionary(true)
	if b.GetDisableEmbeddedDictionary() != false {
		t.Error("GetDisableEmbeddedDictionary() should always return false")
	}

	b.SetMaxContinuousBruteTimes(10)
}

func TestPluginType_GetConfig(t *testing.T) {
	pt := PluginType(0)
	cfg := pt.GetConfig(context.Background(), nil)
	if cfg != nil {
		t.Errorf("PluginType.GetConfig() should return nil, got %v", cfg)
	}
}

func TestDictionaryLoader_Load(t *testing.T) {
	dl := &dictionaryLoader{bb: &base.ApolloBase{}}
	dl.load() // no-op, just verify it doesn't panic
}
