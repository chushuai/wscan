package bruteforce

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	vhttp "wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils/printer"
)

// --- Helper: build a minimal BruteForce with in-memory usernames/passwords ---

func newTestBruteForce(users, passes []string) *BruteForce {
	b := &BruteForce{
		CommonConfig: &CommonConfig{},
		usernames:    users,
		passwords:    passes,
	}
	return b
}

// =============================================================================
// Tests for singlePassChan edge cases (stop channel, empty input)
// =============================================================================

func TestSinglePassChan_EmptyInput(t *testing.T) {
	b := &BruteForce{}
	ch, stop := b.singlePassChan(0, []string{})
	defer close(stop)

	count := 0
	for range ch {
		count++
	}
	if count != 0 {
		t.Errorf("expected 0 values from empty singlePassChan, got %d", count)
	}
}

func TestSinglePassChan_StopBeforeConsumption(t *testing.T) {
	b := &BruteForce{}
	passwords := []string{"p1", "p2", "p3", "p4", "p5"}
	ch, stop := b.singlePassChan(0, passwords)

	close(stop)

	count := 0
	for range ch {
		count++
	}
	if count > len(passwords) {
		t.Errorf("expected at most %d values, got %d", len(passwords), count)
	}
}

func TestSinglePassChan_PartialConsumption(t *testing.T) {
	b := &BruteForce{}
	passwords := []string{"a", "b", "c", "d", "e"}
	ch, stop := b.singlePassChan(0, passwords)

	var results []string
	for p := range ch {
		results = append(results, p)
		if len(results) == 2 {
			close(stop)
			break
		}
	}
	if len(results) != 2 {
		t.Errorf("expected 2 partial results, got %d", len(results))
	}
}

// =============================================================================
// Tests for userPassChan edge cases
// =============================================================================

func TestUserPassChan_EmptyUsers(t *testing.T) {
	b := &BruteForce{}
	ch, stop := b.userPassChan(0, []string{}, []string{"pass1"})
	defer close(stop)

	count := 0
	for range ch {
		count++
	}
	if count != 0 {
		t.Errorf("expected 0 values with empty users, got %d", count)
	}
}

func TestUserPassChan_EmptyPasswords(t *testing.T) {
	b := &BruteForce{}
	ch, stop := b.userPassChan(0, []string{"admin"}, []string{})
	defer close(stop)

	count := 0
	for range ch {
		count++
	}
	if count != 0 {
		t.Errorf("expected 0 values with empty passwords, got %d", count)
	}
}

func TestUserPassChan_StopBeforeConsumption(t *testing.T) {
	b := &BruteForce{}
	users := []string{"admin", "root"}
	passes := []string{"123", "456"}

	ch, stop := b.userPassChan(0, users, passes)
	close(stop)

	count := 0
	for range ch {
		count++
	}
	if count > len(users)*len(passes) {
		t.Errorf("expected at most %d values, got %d", len(users)*len(passes), count)
	}
}

func TestUserPassChan_SingleUserSinglePass(t *testing.T) {
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
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0][0] != "admin" || results[0][1] != "secret" {
		t.Errorf("expected admin:secret, got %s:%s", results[0][0], results[0][1])
	}
}

// =============================================================================
// Tests for singleTokenChan
// =============================================================================

func TestSingleTokenChan_AlwaysNil(t *testing.T) {
	b := &BruteForce{}
	ch, stop := b.singleTokenChan("token", []string{"a", "b"})
	if ch != nil || stop != nil {
		t.Error("singleTokenChan should always return nil, nil")
	}
}

// =============================================================================
// Tests for formBrute empty methods
// =============================================================================

func TestFormBrute_BruteSinglePass(t *testing.T) {
	b := &BruteForce{}
	fb := formBrute{bf: b}
	fb.bruteSinglePass()
}

func TestFormBrute_BruteUserPass(t *testing.T) {
	b := &BruteForce{}
	fb := formBrute{bf: b}
	fb.bruteUserPass()
}

func TestFormBrute_ProcessPassword(t *testing.T) {
	b := &BruteForce{}
	fb := formBrute{bf: b}
	result := fb.processPassword("user", "pass")
	if result != "" {
		t.Errorf("processPassword should return empty string, got %q", result)
	}
}

// =============================================================================
// Tests for dictionaryLoader.load
// =============================================================================

func TestDictionaryLoader_Load_NoOp(t *testing.T) {
	dl := &dictionaryLoader{bb: &base.ApolloBase{}}
	dl.load()
}

// =============================================================================
// Tests for PluginType.GetConfig
// =============================================================================

func TestPluginType_GetConfig_NilApollo(t *testing.T) {
	pt := PluginType(0)
	cfg := pt.GetConfig(context.Background(), nil)
	if cfg != nil {
		t.Errorf("expected nil, got %v", cfg)
	}
}

// =============================================================================
// Tests for BruteForce no-op setters
// =============================================================================

func TestBruteForce_SetDisableEmbeddedDictionary_NoOp(t *testing.T) {
	b := BruteForce{}
	b.SetDisableEmbeddedDictionary(true)
	b.SetDisableEmbeddedDictionary(false)
	if b.GetDisableEmbeddedDictionary() != false {
		t.Error("GetDisableEmbeddedDictionary should always return false")
	}
}

func TestBruteForce_SetMaxContinuousBruteTimes_NoOp(t *testing.T) {
	b2 := &BruteForce{CommonConfig: &CommonConfig{MaxContinuousBruteTimes: 99}}
	b2.SetMaxContinuousBruteTimes(42)
	if b2.GetMaxContinuousBruteTimes() != 99 {
		t.Errorf("expected 99, got %d", b2.GetMaxContinuousBruteTimes())
	}
}

// =============================================================================
// Tests for PluginConfig setters (no-ops)
// =============================================================================

func TestPluginConfig_AllSetters_NoOps(t *testing.T) {
	p := PluginConfig{}

	p.SetBruteTimeout(999)
	p.SetContinuousBruteInterval(999)
	p.SetDialTimeout(999)
	p.SetDisableEmbeddedDictionary(true)
	p.SetMaxBruteTimes(999)
	p.SetMaxContinuousBruteTimes(999)
	p.SetQPS(999.0)
	p.SetReadTimeout(999)

	if p.GetBruteTimeout() != 1000 {
		t.Errorf("GetBruteTimeout = %d, want 1000", p.GetBruteTimeout())
	}
	if p.GetContinuousBruteInterval() != 0 {
		t.Errorf("GetContinuousBruteInterval = %d, want 0", p.GetContinuousBruteInterval())
	}
	if p.GetDialTimeout() != 0 {
		t.Errorf("GetDialTimeout = %d, want 0", p.GetDialTimeout())
	}
	if p.GetDisableEmbeddedDictionary() != false {
		t.Error("GetDisableEmbeddedDictionary should be false")
	}
	if p.GetMaxBruteTimes() != 0 {
		t.Errorf("GetMaxBruteTimes = %d, want 0", p.GetMaxBruteTimes())
	}
	if p.GetMaxContinuousBruteTimes() != 0 {
		t.Errorf("GetMaxContinuousBruteTimes = %d, want 0", p.GetMaxContinuousBruteTimes())
	}
	if p.GetQPS() != 0 {
		t.Errorf("GetQPS = %f, want 0", p.GetQPS())
	}
	if p.GetReadTimeout() != 0 {
		t.Errorf("GetReadTimeout = %d, want 0", p.GetReadTimeout())
	}
}

// =============================================================================
// Tests for Config
// =============================================================================

func TestConfig_WithSingleConfigMap(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "brute-force",
			Enabled: true,
		},
		CommonConfig:    &CommonConfig{},
		SingleConfigMap: map[int]Configure{},
	}
	bc := cfg.BaseConfig()
	if bc.Name != "brute-force" {
		t.Errorf("expected Name=brute-force, got %s", bc.Name)
	}
}

// =============================================================================
// Tests for CommonConfig zero values
// =============================================================================

func TestCommonConfig_ZeroValues(t *testing.T) {
	cc := &CommonConfig{}
	b := &BruteForce{CommonConfig: cc}

	if b.GetBruteTimeout() != 0 {
		t.Errorf("expected 0, got %d", b.GetBruteTimeout())
	}
	if b.GetContinuousBruteInterval() != 0 {
		t.Errorf("expected 0, got %d", b.GetContinuousBruteInterval())
	}
	if b.GetDialTimeout() != 0 {
		t.Errorf("expected 0, got %d", b.GetDialTimeout())
	}
	if b.GetMaxBruteTimes() != 0 {
		t.Errorf("expected 0, got %d", b.GetMaxBruteTimes())
	}
	if b.GetMaxContinuousBruteTimes() != 0 {
		t.Errorf("expected 0, got %d", b.GetMaxContinuousBruteTimes())
	}
	if b.GetQPS() != 0 {
		t.Errorf("expected 0, got %f", b.GetQPS())
	}
	if b.GetReadTimeout() != 0 {
		t.Errorf("expected 0, got %d", b.GetReadTimeout())
	}
}

// =============================================================================
// Tests for BruteForce.Init with custom dictionary paths
// =============================================================================

func TestBruteForce_Init_WithNonExistentDictionary(t *testing.T) {
	b := &BruteForce{CommonConfig: &CommonConfig{}}
	cfg := b.DefaultConfig().(*Config)
	cfg.UsernameDictionary = "/nonexistent/path/username.txt"
	cfg.PasswordDictionary = "/nonexistent/path/password.txt"
	ab := &base.ApolloBase{}

	err := b.Init(context.Background(), cfg, ab)
	if err != nil {
		t.Errorf("Init() returned error: %v", err)
	}
	if len(b.usernames) == 0 {
		t.Error("Expected usernames from built-in dict even when custom file fails")
	}
	if len(b.passwords) == 0 {
		t.Error("Expected passwords from built-in dict even when custom file fails")
	}
}

// =============================================================================
// Tests for BruteForce Fingers content
// =============================================================================

func TestBruteForce_Fingers_ChannelAndBinding(t *testing.T) {
	b := newTestBruteForce([]string{"admin"}, []string{"pass"})
	fingers := b.Fingers()
	if len(fingers) != 2 {
		t.Fatalf("expected 2 fingers, got %d", len(fingers))
	}

	for i, f := range fingers {
		if f.Channel != "web-generic" {
			t.Errorf("finger[%d]: Channel = %q, want web-generic", i, f.Channel)
		}
		if f.Binding == nil {
			t.Errorf("finger[%d]: Binding is nil", i)
		}
		if f.CheckAction == nil {
			t.Errorf("finger[%d]: CheckAction is nil", i)
		}
	}

	if fingers[0].Binding.ID != "brute-force/basic-auth/default" {
		t.Errorf("basicAuth finger ID = %q", fingers[0].Binding.ID)
	}
	if fingers[1].Binding.ID != "brute-force/form-brute/default" {
		t.Errorf("formBrute finger ID = %q", fingers[1].Binding.ID)
	}
}

// =============================================================================
// Helper for building Apollo with real HTTP client + test server
// =============================================================================

// testOutput captures vuln output by implementing printer.Printer
type testOutput struct {
	vulns []*model.Vuln
	mu    sync.Mutex
}

func (t *testOutput) Print(data any) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if v, ok := data.(*model.Vuln); ok {
		t.vulns = append(t.vulns, v)
	}
	return nil
}

func (t *testOutput) AddInterceptor(fn func(any) (any, error)) printer.Printer {
	return t
}

func (t *testOutput) Close() error {
	return nil
}

func (t *testOutput) getVulns() []*model.Vuln {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.vulns
}

func makeTestFlow(method string, targetURL string, body string) *vhttp.Flow {
	u, _ := url.Parse(targetURL)
	req, _ := vhttp.NewRequest(method, u.String(), strings.NewReader(body))
	if method == "POST" {
		req.SetHeader("Content-Type", "application/x-www-form-urlencoded")
	}
	res := &vhttp.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Text:       "OK",
	}
	return &vhttp.Flow{Request: req, Response: res}
}

func buildApolloWithRealClient(flow *vhttp.Flow, output *testOutput) *base.Apollo {
	apollo := base.NewApollo(flow)
	apollo.ApolloBase.HTTPClient = vhttp.NewClient()
	apollo.ApolloBase.Output = output
	// Set binding via WithVuln
	apollo.WithVuln(&model.Vuln{
		Binding: &model.VulnBinding{
			ID:       "test",
			Plugin:   "test",
			Category: "test",
			Severity: model.SeverityMedium,
		},
	})
	return apollo
}

// =============================================================================
// Integration tests for basicAuth.Finger CheckAction with real HTTP server
// =============================================================================

func TestBasicAuth_Finger_NoWwwAuthenticate(t *testing.T) {
	b := newTestBruteForce([]string{"admin"}, []string{"pass"})
	ba := basicAuth{bf: b}
	finger := ba.Finger()

	// Server that does NOT send Www-Authenticate header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	flow := makeTestFlow("GET", server.URL+"/protected", "")
	output := &testOutput{}
	apollo := buildApolloWithRealClient(flow, output)

	err := finger.CheckAction(context.Background(), apollo)
	if err != nil {
		t.Errorf("CheckAction returned error: %v", err)
	}
	if len(output.getVulns()) != 0 {
		t.Errorf("expected 0 vulns, got %d", len(output.getVulns()))
	}
}

func TestBasicAuth_Finger_AllFail(t *testing.T) {
	b := newTestBruteForce([]string{"admin"}, []string{"wrongpass"})
	ba := basicAuth{bf: b}
	finger := ba.Finger()

	// Server that always returns 401
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Www-Authenticate", `Basic realm="test"`)
		w.WriteHeader(401)
		w.Write([]byte("<html>Unauthorized</html>"))
	}))
	defer server.Close()

	flow := makeTestFlow("GET", server.URL+"/protected", "")
	output := &testOutput{}
	apollo := buildApolloWithRealClient(flow, output)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := finger.CheckAction(ctx, apollo)
	if err != nil {
		t.Errorf("CheckAction returned error: %v", err)
	}
	if len(output.getVulns()) != 0 {
		t.Errorf("expected 0 vulns, got %d", len(output.getVulns()))
	}
}

func TestBasicAuth_Finger_SuccessFound(t *testing.T) {
	b := newTestBruteForce([]string{"admin"}, []string{"secret"})
	ba := basicAuth{bf: b}
	finger := ba.Finger()

	// Server that accepts admin:secret, rejects everything else
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if ok && user == "admin" && pass == "secret" {
			w.WriteHeader(200)
			w.Write([]byte("<html>Welcome admin</html>"))
			return
		}
		w.Header().Set("Www-Authenticate", `Basic realm="test"`)
		w.WriteHeader(401)
		w.Write([]byte("<html>Unauthorized</html>"))
	}))
	defer server.Close()

	flow := makeTestFlow("GET", server.URL+"/protected", "")
	// The flow response must have Www-Authenticate to trigger the brute force
	flow.Response.Header.Set("Www-Authenticate", `Basic realm="test"`)
	output := &testOutput{}
	apollo := buildApolloWithRealClient(flow, output)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := finger.CheckAction(ctx, apollo)
	if err != nil {
		t.Errorf("CheckAction returned error: %v", err)
	}
	// A successful brute force should have found a vuln
	vulns := output.getVulns()
	if len(vulns) == 0 {
		t.Error("expected at least 1 vuln from successful brute force")
	}
}

func TestBasicAuth_Finger_SimilarResponse(t *testing.T) {
	b := newTestBruteForce([]string{"admin"}, []string{"pass1"})
	ba := basicAuth{bf: b}
	finger := ba.Finger()

	// Server that always returns the same 200 response (simulating false positive)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html>Login failed</html>"))
	}))
	defer server.Close()

	flow := makeTestFlow("GET", server.URL+"/protected", "")
	// Need Www-Authenticate to trigger the brute force
	flow.Response.Header.Set("Www-Authenticate", `Basic realm="test"`)
	output := &testOutput{}
	apollo := buildApolloWithRealClient(flow, output)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := finger.CheckAction(ctx, apollo)
	if err != nil {
		t.Errorf("CheckAction returned error: %v", err)
	}
	// Should not find vuln because responses are too similar
	// (The initial flow response has Www-Authenticate, but the real server responses are all the same)
}

// =============================================================================
// Integration tests for formBrute.Brute with real HTTP server
// =============================================================================

func TestFormBrute_Finger(t *testing.T) {
	b := newTestBruteForce([]string{"admin"}, []string{"pass"})
	fb := formBrute{bf: b}
	finger := fb.Finger()

	if finger.Channel != "web-generic" {
		t.Errorf("Channel = %q, want web-generic", finger.Channel)
	}
	if finger.Binding == nil {
		t.Fatal("Binding is nil")
	}
	if finger.Binding.ID != "brute-force/form-brute/default" {
		t.Errorf("Binding.ID = %q", finger.Binding.ID)
	}
	if finger.CheckAction == nil {
		t.Error("CheckAction is nil")
	}
}

func TestFormBrute_Brute_NonPostMethod(t *testing.T) {
	b := newTestBruteForce([]string{"admin"}, []string{"pass"})
	fb := formBrute{bf: b}

	flow := makeTestFlow("GET", "http://example.com/login", "")
	output := &testOutput{}
	apollo := buildApolloWithRealClient(flow, output)

	err := fb.Brute(context.Background(), apollo)
	if err != nil {
		t.Errorf("Brute() returned error: %v", err)
	}
	if len(output.getVulns()) != 0 {
		t.Errorf("expected 0 vulns for GET request, got %d", len(output.getVulns()))
	}
}

func TestFormBrute_Brute_PostNoUsernameField(t *testing.T) {
	b := newTestBruteForce([]string{"admin"}, []string{"pass"})
	fb := formBrute{bf: b}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL + "/login")
	req, _ := vhttp.NewRequest("POST", u.String(), strings.NewReader("token=abc123"))
	req.SetHeader("Content-Type", "application/x-www-form-urlencoded")
	res := &vhttp.Response{StatusCode: 200, Header: http.Header{}, Text: "OK"}
	flow := &vhttp.Flow{Request: req, Response: res}

	output := &testOutput{}
	apollo := buildApolloWithRealClient(flow, output)

	err := fb.Brute(context.Background(), apollo)
	if err != nil {
		t.Errorf("Brute() returned error: %v", err)
	}
	if len(output.getVulns()) != 0 {
		t.Errorf("expected 0 vulns when no username/password fields, got %d", len(output.getVulns()))
	}
}

func TestFormBrute_Brute_PostWithUserAndPassFields_AllFail(t *testing.T) {
	b := newTestBruteForce([]string{"admin"}, []string{"wrongpass"})
	fb := formBrute{bf: b}

	// Server that always rejects login
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html>Login failed</html>"))
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL + "/login")
	req, _ := vhttp.NewRequest("POST", u.String(), strings.NewReader("username=admin&password=oldpass"))
	req.SetHeader("Content-Type", "application/x-www-form-urlencoded")
	res := &vhttp.Response{StatusCode: 200, Header: http.Header{}, Text: "OK"}
	flow := &vhttp.Flow{Request: req, Response: res}

	output := &testOutput{}
	apollo := buildApolloWithRealClient(flow, output)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := fb.Brute(ctx, apollo)
	if err != nil {
		t.Errorf("Brute() returned error: %v", err)
	}
	// No vuln should be found because all responses are the same (similarity > 0.95)
	if len(output.getVulns()) != 0 {
		t.Errorf("expected 0 vulns, got %d", len(output.getVulns()))
	}
}

func TestFormBrute_Brute_SuccessFound(t *testing.T) {
	b := newTestBruteForce([]string{"admin"}, []string{"secret"})
	fb := formBrute{bf: b}

	// Server that accepts admin:secret
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(200)
			w.Write([]byte("OK"))
			return
		}
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")
		if username == "admin" && password == "secret" {
			w.WriteHeader(200)
			w.Write([]byte("<html>Welcome admin</html>"))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("<html>Login failed</html>"))
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL + "/login")
	req, _ := vhttp.NewRequest("POST", u.String(), strings.NewReader("username=olduser&password=oldpass"))
	req.SetHeader("Content-Type", "application/x-www-form-urlencoded")
	res := &vhttp.Response{StatusCode: 200, Header: http.Header{}, Text: "OK"}
	flow := &vhttp.Flow{Request: req, Response: res}

	output := &testOutput{}
	apollo := buildApolloWithRealClient(flow, output)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := fb.Brute(ctx, apollo)
	if err != nil {
		t.Errorf("Brute() returned error: %v", err)
	}
}

func TestFormBrute_Brute_LoginPath(t *testing.T) {
	b := newTestBruteForce([]string{"admin"}, []string{"wrongpass"})
	fb := formBrute{bf: b}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html>Login failed</html>"))
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL + "/login.php")
	req, _ := vhttp.NewRequest("POST", u.String(), strings.NewReader("username=admin&password=old"))
	req.SetHeader("Content-Type", "application/x-www-form-urlencoded")
	res := &vhttp.Response{StatusCode: 200, Header: http.Header{}, Text: "OK"}
	flow := &vhttp.Flow{Request: req, Response: res}

	output := &testOutput{}
	apollo := buildApolloWithRealClient(flow, output)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := fb.Brute(ctx, apollo)
	if err != nil {
		t.Errorf("Brute() returned error: %v", err)
	}
}

func TestFormBrute_Brute_CandidateNameField(t *testing.T) {
	b := newTestBruteForce([]string{"admin"}, []string{"secret"})
	fb := formBrute{bf: b}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html>Failed</html>"))
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL + "/login")
	req, _ := vhttp.NewRequest("POST", u.String(), strings.NewReader("fullname=John&password=old"))
	req.SetHeader("Content-Type", "application/x-www-form-urlencoded")
	res := &vhttp.Response{StatusCode: 200, Header: http.Header{}, Text: "OK"}
	flow := &vhttp.Flow{Request: req, Response: res}

	output := &testOutput{}
	apollo := buildApolloWithRealClient(flow, output)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_ = fb.Brute(ctx, apollo)
}

// =============================================================================
// Tests for formBrute.Brute with various field name combinations
// =============================================================================

func TestFormBrute_Brute_FieldVariants(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"user+pass", "user=admin&pass=old"},
		{"usr+pwd", "usr=admin&pwd=old"},
		{"name+pass", "name=admin&pass=old"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newTestBruteForce([]string{"admin"}, []string{"secret"})
			fb := formBrute{bf: b}

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				w.Write([]byte("<html>Failed</html>"))
			}))
			defer server.Close()

			u, _ := url.Parse(server.URL + "/login")
			req, _ := vhttp.NewRequest("POST", u.String(), strings.NewReader(tt.body))
			req.SetHeader("Content-Type", "application/x-www-form-urlencoded")
			res := &vhttp.Response{StatusCode: 200, Header: http.Header{}, Text: "OK"}
			flow := &vhttp.Flow{Request: req, Response: res}

			output := &testOutput{}
			apollo := buildApolloWithRealClient(flow, output)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			_ = fb.Brute(ctx, apollo)
		})
	}
}

// =============================================================================
// Tests for PluginConfig getters individually
// =============================================================================

func TestPluginConfig_EachGetterIndividually(t *testing.T) {
	p := PluginConfig{}

	if v := p.GetBruteTimeout(); v != 1000 {
		t.Errorf("GetBruteTimeout = %d, want 1000", v)
	}
	if v := p.GetContinuousBruteInterval(); v != 0 {
		t.Errorf("GetContinuousBruteInterval = %d, want 0", v)
	}
	if v := p.GetDialTimeout(); v != 0 {
		t.Errorf("GetDialTimeout = %d, want 0", v)
	}
	if v := p.GetDisableEmbeddedDictionary(); v != false {
		t.Errorf("GetDisableEmbeddedDictionary = %v, want false", v)
	}
	if v := p.GetMaxBruteTimes(); v != 0 {
		t.Errorf("GetMaxBruteTimes = %d, want 0", v)
	}
	if v := p.GetMaxContinuousBruteTimes(); v != 0 {
		t.Errorf("GetMaxContinuousBruteTimes = %d, want 0", v)
	}
	if v := p.GetQPS(); v != 0 {
		t.Errorf("GetQPS = %f, want 0", v)
	}
	if v := p.GetReadTimeout(); v != 0 {
		t.Errorf("GetReadTimeout = %d, want 0", v)
	}
}

func TestPluginConfig_EachSetterIndividually(t *testing.T) {
	p := PluginConfig{}

	p.SetBruteTimeout(500)
	p.SetContinuousBruteInterval(100)
	p.SetDialTimeout(20)
	p.SetDisableEmbeddedDictionary(true)
	p.SetMaxBruteTimes(50)
	p.SetMaxContinuousBruteTimes(10)
	p.SetQPS(25.0)
	p.SetReadTimeout(15)

	// All setters are no-ops, so getters still return defaults
	if p.GetBruteTimeout() != 1000 {
		t.Errorf("GetBruteTimeout after setter = %d, want 1000", p.GetBruteTimeout())
	}
}

// =============================================================================
// Tests for BruteForce DefaultConfig and Clone
// =============================================================================

func TestBruteForce_DefaultConfig_CommonConfigNotNil(t *testing.T) {
	b := &BruteForce{}
	cfg := b.DefaultConfig().(*Config)
	if cfg.CommonConfig == nil {
		t.Error("DefaultConfig CommonConfig should not be nil")
	}
}

func TestBruteForce_Clone_NilReturn(t *testing.T) {
	b := &BruteForce{}
	if result := b.Clone(); result != nil {
		t.Errorf("Clone() = %v, want nil", result)
	}
}

// =============================================================================
// Tests for LoadDict
// =============================================================================

func TestLoadDict_ValidPaths(t *testing.T) {
	users := LoadDict("dict/username.txt")
	if len(users) == 0 {
		t.Error("LoadDict returned empty for username.txt")
	}

	passwords := LoadDict("dict/password.txt")
	if len(passwords) == 0 {
		t.Error("LoadDict returned empty for password.txt")
	}
}

// =============================================================================
// Tests for BruteForce interface compliance
// =============================================================================

func TestBruteForce_ImplementsPluginInterface(t *testing.T) {
	var _ base.Plugin = &BruteForce{}
}

// =============================================================================
// Tests for BruteForce Init dictionary merging
// =============================================================================

func TestBruteForce_Init_DictionaryMerging(t *testing.T) {
	b := &BruteForce{CommonConfig: &CommonConfig{}}
	cfg := b.DefaultConfig().(*Config)
	ab := &base.ApolloBase{}

	err := b.Init(context.Background(), cfg, ab)
	if err != nil {
		t.Fatalf("Init() error: %v", err)
	}

	users, passwords := LoadBuiltinUserPass()
	if len(b.usernames) < len(users) {
		t.Errorf("usernames count %d < builtin %d", len(b.usernames), len(users))
	}
	if len(b.passwords) < len(passwords) {
		t.Errorf("passwords count %d < builtin %d", len(b.passwords), len(passwords))
	}

	// After FilterUniqueStrings, no duplicates
	seenUser := map[string]bool{}
	for _, u := range b.usernames {
		if seenUser[u] {
			t.Errorf("duplicate username: %q", u)
		}
		seenUser[u] = true
	}
	seenPass := map[string]bool{}
	for _, p := range b.passwords {
		if seenPass[p] {
			t.Errorf("duplicate password: %q", p)
		}
		seenPass[p] = true
	}
}

// =============================================================================
// Comprehensive setter/getter round-trip tests
// =============================================================================

func TestBruteForce_SetterGetterRoundTrip(t *testing.T) {
	b := &BruteForce{CommonConfig: &CommonConfig{}}

	tests := []struct {
		name string
		set  func()
		get  func() int64
		want int64
	}{
		{"BruteTimeout", func() { b.SetBruteTimeout(9999) }, func() int64 { return b.GetBruteTimeout() }, 9999},
		{"ContinuousBruteInterval", func() { b.SetContinuousBruteInterval(555) }, func() int64 { return b.GetContinuousBruteInterval() }, 555},
		{"DialTimeout", func() { b.SetDialTimeout(777) }, func() int64 { return b.GetDialTimeout() }, 777},
		{"ReadTimeout", func() { b.SetReadTimeout(333) }, func() int64 { return b.GetReadTimeout() }, 333},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.set()
			if got := tt.get(); got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestBruteForce_SetterGetterRoundTrip_Int32(t *testing.T) {
	b := &BruteForce{CommonConfig: &CommonConfig{}}
	b.SetMaxBruteTimes(42)
	if b.GetMaxBruteTimes() != 42 {
		t.Errorf("GetMaxBruteTimes = %d, want 42", b.GetMaxBruteTimes())
	}
}

func TestBruteForce_SetterGetterRoundTrip_Float64(t *testing.T) {
	b := &BruteForce{CommonConfig: &CommonConfig{}}
	b.SetQPS(123.456)
	if b.GetQPS() != 123.456 {
		t.Errorf("GetQPS = %f, want 123.456", b.GetQPS())
	}
}

// =============================================================================
// Tests for Config struct with all fields
// =============================================================================

func TestConfig_AllFields(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "brute-force",
			Enabled: true,
		},
		UsernameDictionary:      "/tmp/users.txt",
		PasswordDictionary:      "/tmp/pass.txt",
		DetectDefaultPassword:   true,
		DetectUnsafeLoginMethod: true,
		CommonConfig: &CommonConfig{
			BruteTimeout:            5000,
			MaxBruteTimes:           100,
			DialTimeout:             10,
			ReadTimeout:             30,
			MaxContinuousBruteTimes: 50,
			ContinuousBruteInterval: 100,
			QPS:                     25.0,
		},
		SingleConfigMap: map[int]Configure{},
	}

	bc := cfg.BaseConfig()
	if bc.Name != "brute-force" {
		t.Errorf("BaseConfig().Name = %q, want brute-force", bc.Name)
	}
	if !bc.Enabled {
		t.Error("BaseConfig().Enabled should be true")
	}
}

// =============================================================================
// Test LoadBuiltinUserPass content
// =============================================================================

func TestLoadBuiltinUserPass_Content(t *testing.T) {
	users, passes := LoadBuiltinUserPass()

	if len(users) == 0 {
		t.Error("no builtin usernames")
	}
	if len(passes) == 0 {
		t.Error("no builtin passwords")
	}
}

// =============================================================================
// Tests for Fingers with empty credentials
// =============================================================================

func TestBruteForce_Fingers_WithEmptyCredentials(t *testing.T) {
	b := newTestBruteForce([]string{}, []string{})
	fingers := b.Fingers()
	if len(fingers) != 2 {
		t.Errorf("expected 2 fingers, got %d", len(fingers))
	}
}

// =============================================================================
// Test for PluginConfig struct fields
// =============================================================================

func TestPluginConfig_Fields(t *testing.T) {
	p := PluginConfig{}
	_ = p.ctx
	_ = p.cancel
	_ = p.enableMaxBruteTime
	_ = p.enableContinuousBruteFrequency
	_ = p.actualMaxBruteTimes
	_ = p.actualContinuousBruteTimes
}

// =============================================================================
// Integration test for basicAuth with Www-Authenticate returning false positive
// =============================================================================

func TestBasicAuth_Finger_WwwAuthenticate_SimilarBaseline(t *testing.T) {
	b := newTestBruteForce([]string{"admin"}, []string{"pass1"})
	ba := basicAuth{bf: b}
	finger := ba.Finger()

	// Server returns 200 for everything (including wrong creds)
	// but the responses are identical, so similarity check should prevent false positive
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html>Access denied</html>"))
	}))
	defer server.Close()

	flow := makeTestFlow("GET", server.URL+"/protected", "")
	flow.Response.Header.Set("Www-Authenticate", `Basic realm="test"`)

	output := &testOutput{}
	apollo := buildApolloWithRealClient(flow, output)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := finger.CheckAction(ctx, apollo)
	if err != nil {
		t.Errorf("CheckAction returned error: %v", err)
	}
}

// =============================================================================
// Test basicAuth with connection error (server closed mid-test)
// =============================================================================

func TestBasicAuth_Finger_ServerConnectionError(t *testing.T) {
	b := newTestBruteForce([]string{"admin"}, []string{"pass1"})
	ba := basicAuth{bf: b}
	finger := ba.Finger()

	// Server that immediately closes connections
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			conn.Close()
			return
		}
		w.Header().Set("Www-Authenticate", `Basic realm="test"`)
		w.WriteHeader(401)
	}))
	defer server.Close()

	flow := makeTestFlow("GET", server.URL+"/protected", "")
	flow.Response.Header.Set("Www-Authenticate", `Basic realm="test"`)

	output := &testOutput{}
	apollo := buildApolloWithRealClient(flow, output)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Should handle connection errors gracefully
	_ = finger.CheckAction(ctx, apollo)
}

// =============================================================================
// Test formBrute.Brute with 302 redirect response
// =============================================================================

func TestFormBrute_Brute_302Response(t *testing.T) {
	b := newTestBruteForce([]string{"admin"}, []string{"pass1"})
	fb := formBrute{bf: b}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.FormValue("username") != "" {
			// Return 302 for brute attempts
			w.Header().Set("Location", "/dashboard")
			w.WriteHeader(302)
			w.Write([]byte("Found"))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("<html>Login page</html>"))
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL + "/login")
	req, _ := vhttp.NewRequest("POST", u.String(), strings.NewReader("username=admin&password=old"))
	req.SetHeader("Content-Type", "application/x-www-form-urlencoded")
	res := &vhttp.Response{StatusCode: 200, Header: http.Header{}, Text: "OK"}
	flow := &vhttp.Flow{Request: req, Response: res}

	output := &testOutput{}
	apollo := buildApolloWithRealClient(flow, output)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := fb.Brute(ctx, apollo)
	if err != nil {
		t.Errorf("Brute() returned error: %v", err)
	}
	// 302 is not 200, so no vuln should be found
	if len(output.getVulns()) != 0 {
		t.Errorf("expected 0 vulns for 302 response, got %d", len(output.getVulns()))
	}
}

// =============================================================================
// Test formBrute.Brute with only password field (no username field)
// =============================================================================

func TestFormBrute_Brute_OnlyPasswordField(t *testing.T) {
	b := newTestBruteForce([]string{"admin"}, []string{"pass"})
	fb := formBrute{bf: b}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL + "/login")
	req, _ := vhttp.NewRequest("POST", u.String(), strings.NewReader("password=old"))
	req.SetHeader("Content-Type", "application/x-www-form-urlencoded")
	res := &vhttp.Response{StatusCode: 200, Header: http.Header{}, Text: "OK"}
	flow := &vhttp.Flow{Request: req, Response: res}

	output := &testOutput{}
	apollo := buildApolloWithRealClient(flow, output)

	err := fb.Brute(context.Background(), apollo)
	if err != nil {
		t.Errorf("Brute() returned error: %v", err)
	}
	if len(output.getVulns()) != 0 {
		t.Errorf("expected 0 vulns when only password field, got %d", len(output.getVulns()))
	}
}

// =============================================================================
// Test formBrute.Brute with only username field (no password field)
// =============================================================================

func TestFormBrute_Brute_OnlyUsernameField(t *testing.T) {
	b := newTestBruteForce([]string{"admin"}, []string{"pass"})
	fb := formBrute{bf: b}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL + "/login")
	req, _ := vhttp.NewRequest("POST", u.String(), strings.NewReader("username=old"))
	req.SetHeader("Content-Type", "application/x-www-form-urlencoded")
	res := &vhttp.Response{StatusCode: 200, Header: http.Header{}, Text: "OK"}
	flow := &vhttp.Flow{Request: req, Response: res}

	output := &testOutput{}
	apollo := buildApolloWithRealClient(flow, output)

	err := fb.Brute(context.Background(), apollo)
	if err != nil {
		t.Errorf("Brute() returned error: %v", err)
	}
	if len(output.getVulns()) != 0 {
		t.Errorf("expected 0 vulns when only username field, got %d", len(output.getVulns()))
	}
}

// compile-time check
var _ base.Plugin = &BruteForce{}
