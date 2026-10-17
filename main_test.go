package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rob121/cannon/extension"
)

func TestCapabilitiesAndMeta(t *testing.T) {
	setupExtensionDB(t)
	server := newServer().Handler()
	postWire(t, server, "/install", extension.WireRequest{Method: http.MethodPost, URL: "/install", SiteID: "example"})

	req := httptest.NewRequest(http.MethodGet, "/capabilities", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	var caps struct {
		Capabilities map[string]string `json:"capabilities"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&caps); err != nil {
		t.Fatalf("decode capabilities: %v", err)
	}
	if caps.Capabilities["captcha"] != "/captcha" {
		t.Fatalf("expected captcha capability, got %#v", caps.Capabilities)
	}
	if caps.Capabilities["configuration"] != "/configuration" {
		t.Fatalf("expected configuration capability, got %#v", caps.Capabilities)
	}
	if caps.Capabilities["help"] != "/help" {
		t.Fatalf("expected help capability, got %#v", caps.Capabilities)
	}

	req = httptest.NewRequest(http.MethodGet, "/meta", nil)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	var meta struct {
		Name        string `json:"name"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Version     string `json:"version"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&meta); err != nil {
		t.Fatalf("decode meta: %v", err)
	}
	if meta.Name != extensionName || meta.Title != extensionTitle || meta.Description != extensionDescription || meta.Version != extensionVersion {
		t.Fatalf("unexpected meta: %+v", meta)
	}

	req = httptest.NewRequest(http.MethodGet, "/help", nil)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	var help struct {
		Help []string `json:"help"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&help); err != nil {
		t.Fatalf("decode help: %v", err)
	}
	if len(help.Help) != 1 || help.Help[0] != "/help/overview" {
		t.Fatalf("unexpected help list: %#v", help.Help)
	}
}

func TestConfigurationAndProviderInfo(t *testing.T) {
	setupExtensionDB(t)
	server := newServer().Handler()
	postWire(t, server, "/install", extension.WireRequest{Method: http.MethodPost, URL: "/install", SiteID: "example"})

	saveBody := bytes.NewReader([]byte(`{"section":"general","data":{"site_key":"site-123","secret_key":"secret-456"}}`))
	req := httptest.NewRequest(http.MethodPost, "/configuration", saveBody)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("save configuration: status %d body %s", rec.Code, rec.Body.String())
	}
	data, err := (configStore{table: settingsTableName()}).Load(configSection)
	if err != nil {
		t.Fatal(err)
	}
	if data["site_key"] != "site-123" || data["secret_key"] != "secret-456" {
		t.Fatalf("unexpected settings: %#v", data)
	}

	req = httptest.NewRequest(http.MethodGet, "/captcha", nil)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	var info extension.CaptchaProviderInfo
	if err := json.NewDecoder(rec.Body).Decode(&info); err != nil {
		t.Fatalf("decode provider info: %v", err)
	}
	if info.ID != extensionName || info.Client["site_key"] != "site-123" {
		t.Fatalf("unexpected provider info: %+v", info)
	}
	if _, ok := info.Client["secret_key"]; ok {
		t.Fatal("secret key must not be exposed in provider client config")
	}
}

func TestSettingsCacheInvalidatesOnSave(t *testing.T) {
	setupExtensionDB(t)
	server := newServer().Handler()
	postWire(t, server, "/install", extension.WireRequest{Method: http.MethodPost, URL: "/install", SiteID: "example"})

	saveConfigHTTP(t, server, "site-a", "secret-a")
	req := httptest.NewRequest(http.MethodGet, "/captcha", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	var info extension.CaptchaProviderInfo
	if err := json.NewDecoder(rec.Body).Decode(&info); err != nil {
		t.Fatal(err)
	}
	if info.Client["site_key"] != "site-a" {
		t.Fatalf("first site_key = %q", info.Client["site_key"])
	}

	saveConfigHTTP(t, server, "site-b", "secret-b")
	req = httptest.NewRequest(http.MethodGet, "/captcha", nil)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if err := json.NewDecoder(rec.Body).Decode(&info); err != nil {
		t.Fatal(err)
	}
	if info.Client["site_key"] != "site-b" {
		t.Fatalf("cache not invalidated, site_key = %q", info.Client["site_key"])
	}
}

func TestActiveKeysRespectsDevelopmentMode(t *testing.T) {
	cfg := turnstileSettings{
		SiteKey:       "live-site",
		SecretKey:     "live-secret",
		TestSiteKey:   "test-site",
		TestSecretKey: "test-secret",
	}
	site, secret, err := cfg.activeKeys(extension.WireRequest{})
	if err != nil || site != "live-site" || secret != "live-secret" {
		t.Fatalf("live: site=%q secret=%q err=%v", site, secret, err)
	}
	site, secret, err = cfg.activeKeys(extension.WireRequest{
		Settings: map[string]string{extension.SettingDevelopmentMode: "true"},
	})
	if err != nil || site != "test-site" || secret != "test-secret" {
		t.Fatalf("test: site=%q secret=%q err=%v", site, secret, err)
	}
	_, _, err = turnstileSettings{SiteKey: "live-site", SecretKey: "live-secret"}.activeKeys(extension.WireRequest{
		Settings: map[string]string{extension.SettingDevelopmentMode: "true"},
	})
	if err == nil {
		t.Fatal("expected error when test keys missing in development mode")
	}
}

func TestRender(t *testing.T) {
	setupExtensionDB(t)
	server := newServer().Handler()
	postWire(t, server, "/install", extension.WireRequest{Method: http.MethodPost, URL: "/install", SiteID: "example"})
	saveConfig(t, "site-123", "secret-456", "test-site", "test-secret")

	body := `{"captcha_context":"login","captcha_action":"login.submit"}`
	req := httptest.NewRequest(http.MethodPost, "/captcha/render", strings.NewReader(body))
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("render status %d body %s", rec.Code, rec.Body.String())
	}
	var render extension.CaptchaRenderResult
	if err := json.NewDecoder(rec.Body).Decode(&render); err != nil {
		t.Fatalf("decode render: %v", err)
	}
	if render.FieldName != fieldName {
		t.Fatalf("field name: got %q", render.FieldName)
	}
	for _, want := range []string{`class="cf-turnstile"`, `data-sitekey="site-123"`, `data-action="loginsubmit"`} {
		if !strings.Contains(render.HTML, want) {
			t.Fatalf("expected render HTML to contain %q, got %q", want, render.HTML)
		}
	}
	if !strings.Contains(render.HeadHTML, turnstileScriptURL) {
		t.Fatalf("expected head script, got %q", render.HeadHTML)
	}

	body = `{"captcha_context":"login","captcha_action":"login.submit","settings":{"development_mode":"true"}}`
	req = httptest.NewRequest(http.MethodPost, "/captcha/render", strings.NewReader(body))
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dev render status %d body %s", rec.Code, rec.Body.String())
	}
	if err := json.NewDecoder(rec.Body).Decode(&render); err != nil {
		t.Fatalf("decode dev render: %v", err)
	}
	if !strings.Contains(render.HTML, `data-sitekey="test-site"`) {
		t.Fatalf("expected test site key in development mode, got %q", render.HTML)
	}
}

func TestVerify(t *testing.T) {
	setupExtensionDB(t)
	saveConfig(t, "site-123", "secret-456", "test-site", "test-secret")
	var seenForm map[string][]string
	verifyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		seenForm = map[string][]string(r.PostForm)
		if r.PostForm.Get("response") == "good-token" {
			_, _ = w.Write([]byte(`{"success":true}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":false,"error-codes":["invalid-input-response"]}`))
	}))
	defer verifyServer.Close()
	server := newServerWithHTTP(verifyServer.URL, verifyServer.Client()).Handler()

	body := `{"captcha_context":"login","captcha_token":"bad-token","captcha_remote_ip":"203.0.113.10"}`
	req := httptest.NewRequest(http.MethodPost, "/captcha/verify", strings.NewReader(body))
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bad verify status = %d body %s", rec.Code, rec.Body.String())
	}
	var bad extension.CaptchaVerifyResult
	if err := json.NewDecoder(rec.Body).Decode(&bad); err != nil {
		t.Fatalf("decode bad verify: %v", err)
	}
	if bad.Valid || !strings.Contains(bad.Error, "invalid-input-response") {
		t.Fatalf("unexpected bad verify: %+v", bad)
	}

	body = `{"captcha_context":"login","captcha_token":"good-token","captcha_remote_ip":"203.0.113.10"}`
	req = httptest.NewRequest(http.MethodPost, "/captcha/verify", strings.NewReader(body))
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("good verify status = %d body %s", rec.Code, rec.Body.String())
	}
	var good extension.CaptchaVerifyResult
	if err := json.NewDecoder(rec.Body).Decode(&good); err != nil {
		t.Fatalf("decode good verify: %v", err)
	}
	if !good.Valid {
		t.Fatalf("expected good token valid, got %+v", good)
	}
	if seenForm["secret"][0] != "secret-456" || seenForm["response"][0] != "good-token" || seenForm["remoteip"][0] != "203.0.113.10" {
		t.Fatalf("unexpected verify form: %#v", seenForm)
	}
}

func setupExtensionDB(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sites.json")
	dbPath := filepath.Join(dir, "example.sqlite")
	raw := fmt.Sprintf(`{
  "install_enabled": false,
  "data_root": %q,
  "sites": [{
    "id": "example",
    "name": "Example",
    "host": "http://localhost:8001",
    "database": {"type": "sqlite", "dsn": %q},
    "template_dir": %q,
    "assets_dir": %q,
    "tmp_dir": %q,
    "language_dir": %q
  }]
}`, dir, dbPath, filepath.Join(dir, "templates"), filepath.Join(dir, "assets"), filepath.Join(dir, "tmp"), filepath.Join(dir, "language"))
	if err := os.WriteFile(cfgPath, []byte(raw), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CANNON_CONFIG", cfgPath)
	oldArgs := os.Args
	os.Args = []string{"cfturnstile-extension", "--site=example", "--socket=/tmp/cfturnstile.sock"}
	t.Cleanup(func() { os.Args = oldArgs })
}

func postWire(t *testing.T, handler http.Handler, path string, wire extension.WireRequest) extension.WireResponse {
	t.Helper()
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	var resp extension.WireResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode wire response: %v", err)
	}
	return resp
}

func saveConfig(t *testing.T, siteKey, secretKey, testSiteKey, testSecretKey string) {
	t.Helper()
	db, _, err := extension.OpenDB()
	if err != nil {
		t.Fatal(err)
	}
	if err := extension.MigrateConfigurationStore(db, settingsTableName()); err != nil {
		t.Fatal(err)
	}
	store := extension.DBConfigurationStore(db, settingsTableName())
	if err := store.Save(configSection, map[string]any{
		"site_key":        siteKey,
		"secret_key":      secretKey,
		"test_site_key":   testSiteKey,
		"test_secret_key": testSecretKey,
	}); err != nil {
		t.Fatal(err)
	}
}

func saveConfigHTTP(t *testing.T, handler http.Handler, siteKey, secretKey string) {
	t.Helper()
	body := fmt.Sprintf(`{"section":"general","data":{"site_key":%q,"secret_key":%q}}`, siteKey, secretKey)
	req := httptest.NewRequest(http.MethodPost, "/configuration", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("save configuration: status %d body %s", rec.Code, rec.Body.String())
	}
}

func settingsTableName() string {
	return extension.TableName(extension.Info{Name: extensionName}.TablePrefix(), "settings")
}
