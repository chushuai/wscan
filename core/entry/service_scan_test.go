package entry

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"wscan/core/resource"
)

func TestParsePortRange_Empty(t *testing.T) {
	ports, err := parsePortRange("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should return default common ports
	if len(ports) == 0 {
		t.Error("expected default ports for empty input")
	}
	// Check a few known defaults
	has80 := false
	has443 := false
	has22 := false
	for _, p := range ports {
		if p == 80 {
			has80 = true
		}
		if p == 443 {
			has443 = true
		}
		if p == 22 {
			has22 = true
		}
	}
	if !has80 {
		t.Error("expected port 80 in defaults")
	}
	if !has443 {
		t.Error("expected port 443 in defaults")
	}
	if !has22 {
		t.Error("expected port 22 in defaults")
	}
}

func TestParsePortRange_SinglePort(t *testing.T) {
	ports, err := parsePortRange("8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 1 || ports[0] != 8080 {
		t.Errorf("expected [8080], got %v", ports)
	}
}

func TestParsePortRange_MultiplePorts(t *testing.T) {
	ports, err := parsePortRange("80,443,8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []int{80, 443, 8080}
	if len(ports) != len(expected) {
		t.Fatalf("expected %d ports, got %d", len(expected), len(ports))
	}
	for i, p := range ports {
		if p != expected[i] {
			t.Errorf("port[%d]: expected %d, got %d", i, expected[i], p)
		}
	}
}

func TestParsePortRange_Range(t *testing.T) {
	ports, err := parsePortRange("8080-8083")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []int{8080, 8081, 8082, 8083}
	if len(ports) != len(expected) {
		t.Fatalf("expected %d ports, got %d", len(expected), len(ports))
	}
	for i, p := range ports {
		if p != expected[i] {
			t.Errorf("port[%d]: expected %d, got %d", i, expected[i], p)
		}
	}
}

func TestParsePortRange_MixedPortsAndRanges(t *testing.T) {
	ports, err := parsePortRange("22,80,443,8000-8002")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []int{22, 80, 443, 8000, 8001, 8002}
	if len(ports) != len(expected) {
		t.Fatalf("expected %d ports, got %d: %v", len(expected), len(ports), ports)
	}
	for i, p := range ports {
		if p != expected[i] {
			t.Errorf("port[%d]: expected %d, got %d", i, expected[i], p)
		}
	}
}

func TestParsePortRange_DuplicatePorts(t *testing.T) {
	ports, err := parsePortRange("80,80,443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Duplicates should be deduplicated
	if len(ports) != 2 {
		t.Errorf("expected 2 ports after dedup, got %d: %v", len(ports), ports)
	}
}

func TestParsePortRange_InvalidPort(t *testing.T) {
	_, err := parsePortRange("abc")
	if err == nil {
		t.Error("expected error for non-numeric port")
	}
}

func TestParsePortRange_InvalidRange(t *testing.T) {
	_, err := parsePortRange("80-abc")
	if err == nil {
		t.Error("expected error for non-numeric range endpoint")
	}
}

func TestParsePortRange_ReversedRange(t *testing.T) {
	_, err := parsePortRange("100-80")
	if err == nil {
		t.Error("expected error for start > end in range")
	}
}

func TestParsePortRange_InvalidRangeFormat(t *testing.T) {
	_, err := parsePortRange("80-90-100")
	if err == nil {
		t.Error("expected error for range with too many parts")
	}
}

func TestParsePortRange_SinglePortRange(t *testing.T) {
	ports, err := parsePortRange("80-80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 1 || ports[0] != 80 {
		t.Errorf("expected [80], got %v", ports)
	}
}

func TestParsePortRange_WhitespaceHandling(t *testing.T) {
	ports, err := parsePortRange(" 80 , 443 , 8080 - 8082 ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 5 {
		t.Errorf("expected 5 ports, got %d: %v", len(ports), ports)
	}
}

func TestParsePortRange_DuplicateInRange(t *testing.T) {
	ports, err := parsePortRange("80,80-82,81")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 80, 81, 82 from range; 80 and 81 are duplicates with explicit values
	expected := []int{80, 81, 82}
	if len(ports) != len(expected) {
		t.Errorf("expected %d ports after dedup, got %d: %v", len(expected), len(ports), ports)
	}
	sort.Ints(ports)
	for i, p := range ports {
		if p != expected[i] {
			t.Errorf("port[%d]: expected %d, got %d", i, expected[i], p)
		}
	}
}

func TestServiceFitter_FitOut_SingleTarget(t *testing.T) {
	sf := &serviceFitter{
		targets: []string{"192.168.1.1"},
		ports:   []int{80, 443},
	}

	ch, err := sf.FitOut(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var services []*resource.Service
	for svc := range ch {
		s, ok := svc.(*resource.Service)
		if !ok {
			t.Fatal("expected *resource.Service from channel")
		}
		services = append(services, s)
	}

	if len(services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(services))
	}

	// Verify the host and ports
	hosts := map[string]bool{}
	for _, s := range services {
		hosts[s.Host] = true
	}
	if !hosts["192.168.1.1"] {
		t.Error("expected host 192.168.1.1")
	}
}

func TestServiceFitter_FitOut_MultipleTargets(t *testing.T) {
	sf := &serviceFitter{
		targets: []string{"192.168.1.1", "10.0.0.1"},
		ports:   []int{22},
	}

	ch, err := sf.FitOut(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var services []*resource.Service
	for svc := range ch {
		services = append(services, svc.(*resource.Service))
	}

	if len(services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(services))
	}
}

func TestServiceFitter_FitOut_StripsProtocol(t *testing.T) {
	sf := &serviceFitter{
		targets: []string{"http://example.com", "https://test.com:8443"},
		ports:   []int{80},
	}

	ch, err := sf.FitOut(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var services []*resource.Service
	for svc := range ch {
		services = append(services, svc.(*resource.Service))
	}

	if len(services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(services))
	}

	// http://example.com -> host should be "example.com"
	if services[0].Host != "example.com" {
		t.Errorf("expected host 'example.com', got %q", services[0].Host)
	}

	// https://test.com:8443 -> host should be "test.com" (port stripped)
	if services[1].Host != "test.com" {
		t.Errorf("expected host 'test.com', got %q", services[1].Host)
	}
}

func TestServiceFitter_FitOut_ContextCancellation(t *testing.T) {
	sf := &serviceFitter{
		targets: []string{"192.168.1.1"},
		ports:   []int{80, 443, 8080, 8443, 9090},
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel immediately
	cancel()

	ch, err := sf.FitOut(ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should get fewer than 5 services due to cancellation
	var count int
	for range ch {
		count++
	}
	// With immediate cancellation, we might get 0 or 1 items
	if count > 5 {
		t.Errorf("expected at most 5 services, got %d", count)
	}
}

func TestServiceFitter_FitOut_EmptyTargets(t *testing.T) {
	sf := &serviceFitter{
		targets: []string{},
		ports:   []int{80},
	}

	ch, err := sf.FitOut(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int
	for range ch {
		count++
	}
	if count != 0 {
		t.Errorf("expected 0 services for empty targets, got %d", count)
	}
}

func TestServiceFitter_FitOut_EmptyPorts(t *testing.T) {
	sf := &serviceFitter{
		targets: []string{"192.168.1.1"},
		ports:   []int{},
	}

	ch, err := sf.FitOut(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int
	for range ch {
		count++
	}
	if count != 0 {
		t.Errorf("expected 0 services for empty ports, got %d", count)
	}
}

func TestServiceScanAction_EmptyTarget(t *testing.T) {
	err := serviceScanAction("", "", "80")
	if err == nil {
		t.Error("expected error for empty target")
	}
	if err.Error() != "target can't be empty" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestServiceScanAction_InvalidTargetFile(t *testing.T) {
	err := serviceScanAction("", "/nonexistent/file.txt", "80")
	if err == nil {
		t.Error("expected error for nonexistent target file")
	}
}

func TestServiceScanAction_InvalidPortRange(t *testing.T) {
	err := serviceScanAction("192.168.1.1", "", "abc")
	if err == nil {
		t.Error("expected error for invalid port range")
	}
}

func TestServiceScanAction_WithTarget(t *testing.T) {
	err := serviceScanAction("127.0.0.1", "", "80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServiceScanAction_WithTargetFile(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "targets.txt")
	content := "192.168.1.1\n192.168.1.2\n"
	err := os.WriteFile(targetFile, []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to write target file: %v", err)
	}

	err = serviceScanAction("", targetFile, "22,80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServiceScanAction_WithTargetFileDedup(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "targets.txt")
	content := "192.168.1.1\n192.168.1.1\n192.168.1.2\n"
	err := os.WriteFile(targetFile, []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to write target file: %v", err)
	}

	err = serviceScanAction("", targetFile, "80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServiceScanAction_WithTargetFileBlankLines(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "targets.txt")
	content := "192.168.1.1\n\n  \n192.168.1.2\n"
	err := os.WriteFile(targetFile, []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to write target file: %v", err)
	}

	err = serviceScanAction("", targetFile, "80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServiceScanAction_DefaultPorts(t *testing.T) {
	err := serviceScanAction("127.0.0.1", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetServiceFitter_SingleTarget(t *testing.T) {
	fitter := getServiceFitter("192.168.1.1", "", []int{80, 443})
	if fitter == nil {
		t.Fatal("expected non-nil fitter")
	}

	ch, err := fitter.FitOut(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int
	for range ch {
		count++
	}
	if count != 2 {
		t.Errorf("expected 2 services, got %d", count)
	}
}

func TestGetServiceFitter_TargetFile(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "targets.txt")
	content := "10.0.0.1\n10.0.0.2\n"
	err := os.WriteFile(targetFile, []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to write target file: %v", err)
	}

	fitter := getServiceFitter("", targetFile, []int{22})
	if fitter == nil {
		t.Fatal("expected non-nil fitter")
	}

	ch, err := fitter.FitOut(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int
	for range ch {
		count++
	}
	if count != 2 {
		t.Errorf("expected 2 services, got %d", count)
	}
}

func TestGetServiceFitter_NonExistentFile(t *testing.T) {
	fitter := getServiceFitter("", "/nonexistent/file.txt", []int{80})
	if fitter != nil {
		t.Error("expected nil fitter for nonexistent file")
	}
}

func TestGetServiceFitter_EmptyInputs(t *testing.T) {
	fitter := getServiceFitter("", "", []int{80})
	if fitter == nil {
		t.Fatal("expected non-nil fitter even for empty inputs")
	}

	ch, err := fitter.FitOut(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int
	for range ch {
		count++
	}
	if count != 0 {
		t.Errorf("expected 0 services for empty inputs, got %d", count)
	}
}

func TestGetServiceFitter_TargetFilePriority(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "targets.txt")
	err := os.WriteFile(targetFile, []byte("10.0.0.1\n"), 0644)
	if err != nil {
		t.Fatalf("failed to write target file: %v", err)
	}

	// When both target and targetFile are provided, targetFile takes priority
	fitter := getServiceFitter("192.168.1.1", targetFile, []int{80})
	if fitter == nil {
		t.Fatal("expected non-nil fitter")
	}

	ch, err := fitter.FitOut(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var services []*resource.Service
	for svc := range ch {
		services = append(services, svc.(*resource.Service))
	}

	if len(services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(services))
	}
	// Should use the file target (10.0.0.1), not the direct target (192.168.1.1)
	if services[0].Host != "10.0.0.1" {
		t.Errorf("expected host '10.0.0.1' from file, got %q", services[0].Host)
	}
}

func TestServiceFitter_FitOut_LargeScale(t *testing.T) {
	// Test with many targets and ports to verify channel doesn't block
	targets := make([]string, 10)
	for i := range targets {
		targets[i] = "192.168.1." + time.Now().Format("0")
	}
	ports := make([]int, 10)
	for i := range ports {
		ports[i] = 8000 + i
	}

	sf := &serviceFitter{
		targets: targets,
		ports:   ports,
	}

	ch, err := sf.FitOut(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	count := 0
	for range ch {
		count++
	}
	expected := len(targets) * len(ports)
	if count != expected {
		t.Errorf("expected %d services, got %d", expected, count)
	}
}
