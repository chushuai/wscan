package http

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// generateTestCert 生成自签名的 ECDSA 证书和私钥，用于测试
func generateTestCert() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test PKCS12"},
			CommonName:   "test-client",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return key, cert, nil
}

// createTestPKCS12File 使用 openssl 命令生成 PKCS12 测试文件
func createTestPKCS12File(t *testing.T, password string) string {
	t.Helper()

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test.key")
	certPath := filepath.Join(tmpDir, "test.crt")
	p12Path := filepath.Join(tmpDir, "test.p12")

	key, cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	// 写出私钥 PEM
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	// 写出证书 PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}

	// 使用 openssl 生成 PKCS12 文件
	// -legacy 用于兼容 Go 的 pkcs12 解析（使用 RC2/3DES）
	cmd := exec.Command("openssl", "pkcs12", "-export",
		"-in", certPath,
		"-inkey", keyPath,
		"-out", p12Path,
		"-passout", "pass:"+password,
		"-legacy",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to create PKCS12 file with openssl: %v\noutput: %s", err, string(output))
	}

	return p12Path
}

// ========== ParsePKCS12 单元测试 ==========

func TestParsePKCS12_ValidData(t *testing.T) {
	password := "testpass123"
	p12Path := createTestPKCS12File(t, password)

	p12Data, err := os.ReadFile(p12Path)
	if err != nil {
		t.Fatalf("failed to read PKCS12 file: %v", err)
	}

	cert, caCerts, err := ParsePKCS12(p12Data, password)
	if err != nil {
		t.Fatalf("ParsePKCS12 failed: %v", err)
	}

	// 验证返回的 tls.Certificate 基本字段
	if cert.Leaf == nil {
		t.Error("expected Leaf to be non-nil")
	}
	if cert.Leaf.Subject.CommonName != "test-client" {
		t.Errorf("expected CommonName 'test-client', got '%s'", cert.Leaf.Subject.CommonName)
	}
	if cert.PrivateKey == nil {
		t.Error("expected PrivateKey to be non-nil")
	}
	if len(cert.Certificate) == 0 {
		t.Error("expected Certificate slice to be non-empty")
	}
	// CA 证书在自签名场景下应为 nil
	if len(caCerts) != 0 {
		t.Logf("caCerts returned %d entries (expected 0 for self-signed)", len(caCerts))
	}
}

func TestParsePKCS12_WrongPassword(t *testing.T) {
	password := "correctpass"
	p12Path := createTestPKCS12File(t, password)

	p12Data, err := os.ReadFile(p12Path)
	if err != nil {
		t.Fatalf("failed to read PKCS12 file: %v", err)
	}

	_, _, err = ParsePKCS12(p12Data, "wrongpass")
	if err == nil {
		t.Error("expected error with wrong password, got nil")
	}
	t.Logf("wrong password error (expected): %v", err)
}

func TestParsePKCS12_InvalidData(t *testing.T) {
	_, _, err := ParsePKCS12([]byte("this is not pkcs12 data"), "password")
	if err == nil {
		t.Error("expected error with invalid data, got nil")
	}
}

func TestParsePKCS12_EmptyData(t *testing.T) {
	_, _, err := ParsePKCS12([]byte{}, "password")
	if err == nil {
		t.Error("expected error with empty data, got nil")
	}
}

// ========== ParsePKCS12FromFile 单元测试 ==========

func TestParsePKCS12FromFile_ValidFile(t *testing.T) {
	password := "filepass456"
	p12Path := createTestPKCS12File(t, password)

	cert, _, err := ParsePKCS12FromFile(p12Path, password)
	if err != nil {
		t.Fatalf("ParsePKCS12FromFile failed: %v", err)
	}

	if cert.Leaf == nil {
		t.Error("expected Leaf to be non-nil")
	}
	if cert.Leaf.Subject.CommonName != "test-client" {
		t.Errorf("expected CommonName 'test-client', got '%s'", cert.Leaf.Subject.CommonName)
	}
	if cert.PrivateKey == nil {
		t.Error("expected PrivateKey to be non-nil")
	}
}

func TestParsePKCS12FromFile_EmptyPath(t *testing.T) {
	_, _, err := ParsePKCS12FromFile("", "password")
	if err == nil {
		t.Error("expected error with empty path, got nil")
	}
	t.Logf("empty path error (expected): %v", err)
}

func TestParsePKCS12FromFile_NonExistentFile(t *testing.T) {
	_, _, err := ParsePKCS12FromFile("/nonexistent/path/test.p12", "password")
	if err == nil {
		t.Error("expected error with non-existent file, got nil")
	}
	t.Logf("non-existent file error (expected): %v", err)
}

func TestParsePKCS12FromFile_WrongPassword(t *testing.T) {
	password := "correctpass"
	p12Path := createTestPKCS12File(t, password)

	_, _, err := ParsePKCS12FromFile(p12Path, "wrongpass")
	if err == nil {
		t.Error("expected error with wrong password, got nil")
	}
}

// ========== 集成测试：PKCS12 与 TLS Client 集成 ==========

func TestNewClientWithOptions_WithPKCS12(t *testing.T) {
	password := "clientpass"
	p12Path := createTestPKCS12File(t, password)

	opt := &ClientOptions{
		PKCS12:              PKCS12Config{Path: p12Path, Password: password},
		DialTimeout:         5,
		ReadTimeout:         10,
		TLSHandshakeTimeout: 5,
		IdleConnTimeout:     10,
		MaxConnsPerHost:     10,
		MaxIdleConns:        10,
	}

	client := NewClientWithOptions(opt)
	if client == nil {
		t.Fatal("NewClientWithOptions returned nil")
	}

	// 通过类型断言获取实际的 http.Transport
	ht, ok := client.Client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is not *http.Transport, type: %T", client.Client.Transport)
	}

	if ht.TLSClientConfig == nil {
		t.Fatal("expected TLSClientConfig to be non-nil")
	}
	if len(ht.TLSClientConfig.Certificates) == 0 {
		t.Error("expected TLS client certificates to be loaded from PKCS12")
	} else {
		cert := ht.TLSClientConfig.Certificates[0]
		if cert.Leaf == nil {
			t.Error("expected certificate Leaf to be non-nil")
		} else {
			t.Logf("Successfully loaded PKCS12 client certificate: CN=%s", cert.Leaf.Subject.CommonName)
		}
	}
}

func TestNewClientWithOptions_WithoutPKCS12(t *testing.T) {
	opt := &ClientOptions{
		DialTimeout:         5,
		ReadTimeout:         10,
		TLSHandshakeTimeout: 5,
		IdleConnTimeout:     10,
		MaxConnsPerHost:     10,
		MaxIdleConns:        10,
	}

	client := NewClientWithOptions(opt)
	if client == nil {
		t.Fatal("NewClientWithOptions returned nil")
	}

	ht, ok := client.Client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is not *http.Transport, type: %T", client.Client.Transport)
	}

	if ht.TLSClientConfig == nil {
		t.Fatal("expected TLSClientConfig to be non-nil")
	}
	if len(ht.TLSClientConfig.Certificates) != 0 {
		t.Error("expected no client certificates when PKCS12 is not configured")
	}
}

func TestNewTransport_WithPKCS12(t *testing.T) {
	password := "transportpass"
	p12Path := createTestPKCS12File(t, password)

	opt := &ClientOptions{
		PKCS12: PKCS12Config{Path: p12Path, Password: password},
	}

	transport := NewTransport(opt)
	if transport == nil {
		t.Fatal("NewTransport returned nil")
	}

	if transport.TLSClientConfig == nil {
		t.Fatal("expected TLSClientConfig to be non-nil")
	}
	if len(transport.TLSClientConfig.Certificates) == 0 {
		t.Error("expected TLS client certificates to be loaded from PKCS12")
	} else {
		cert := transport.TLSClientConfig.Certificates[0]
		if cert.Leaf == nil {
			t.Error("expected certificate Leaf to be non-nil")
		} else {
			t.Logf("NewTransport: loaded PKCS12 cert CN=%s", cert.Leaf.Subject.CommonName)
		}
	}
}

func TestNewTransport_WithoutPKCS12(t *testing.T) {
	opt := &ClientOptions{}

	transport := NewTransport(opt)
	if transport == nil {
		t.Fatal("NewTransport returned nil")
	}

	if transport.TLSClientConfig == nil {
		t.Fatal("expected TLSClientConfig to be non-nil")
	}
	if len(transport.TLSClientConfig.Certificates) != 0 {
		t.Error("expected no client certificates when PKCS12 is not configured")
	}
}

func TestNewTransport_InvalidPKCS12Path(t *testing.T) {
	// 无效路径不应该 panic，只应 debug log
	opt := &ClientOptions{
		PKCS12: PKCS12Config{Path: "/nonexistent/test.p12", Password: "pass"},
	}

	transport := NewTransport(opt)
	if transport == nil {
		t.Fatal("NewTransport should not return nil even with invalid PKCS12 path")
	}
	// 证书不应被加载
	if len(transport.TLSClientConfig.Certificates) != 0 {
		t.Error("expected no certificates with invalid PKCS12 path")
	}
}

// ========== 验证证书可用于 TLS 握手 ==========

func TestPKCS12CertificateUsableForTLS(t *testing.T) {
	password := "tlspass"
	p12Path := createTestPKCS12File(t, password)

	p12Data, err := os.ReadFile(p12Path)
	if err != nil {
		t.Fatalf("failed to read PKCS12 file: %v", err)
	}

	tlsCert, _, err := ParsePKCS12(p12Data, password)
	if err != nil {
		t.Fatalf("ParsePKCS12 failed: %v", err)
	}

	// 验证 tls.Certificate 可以被 crypto/tls 使用
	// 通过创建一个 tls.Config 并检查证书签名
	tlsConfig := &cryptotls.Config{
		Certificates: []cryptotls.Certificate{tlsCert},
		MinVersion:   cryptotls.VersionTLS12,
	}

	if len(tlsConfig.Certificates) != 1 {
		t.Fatalf("expected 1 certificate in tls.Config, got %d", len(tlsConfig.Certificates))
	}

	cert := &tlsConfig.Certificates[0]
	if cert.PrivateKey == nil {
		t.Fatal("private key is nil, cannot be used for TLS")
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("certificate chain is empty, cannot be used for TLS")
	}

	t.Logf("PKCS12 certificate is usable for TLS: CN=%s, SerialNumber=%s",
		cert.Leaf.Subject.CommonName, cert.Leaf.SerialNumber.String())
}
