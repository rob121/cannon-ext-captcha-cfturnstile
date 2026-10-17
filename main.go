package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rob121/cannon/extension"
)

//go:embed help/*.md
var helpFiles embed.FS

const (
	extensionName        = "cannon-ext-captcha-cfturnstile"
	extensionTitle       = "Cloudflare Turnstile"
	extensionDescription = "Provides Cloudflare Turnstile captcha rendering and verification for Cannon protected forms."
	extensionVersion     = "0.2.2"
	updateURLBase        = "https://github.com/rob121/cannon-ext-captcha-cfturnstile/releases/download"
	configSection        = "general"
	fieldName            = "cf-turnstile-response"
	turnstileScriptURL   = "https://challenges.cloudflare.com/turnstile/v0/api.js"
	turnstileVerifyURL   = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
)

var turnstileConfigSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "site_key": {
      "type": "string",
      "title": "Live Site Key",
      "description": "Cloudflare Turnstile site key used when Cannon Development Mode is off."
    },
    "secret_key": {
      "type": "string",
      "title": "Live Secret Key",
      "description": "Cloudflare Turnstile secret key used when Cannon Development Mode is off."
    },
    "test_site_key": {
      "type": "string",
      "title": "Test Site Key",
      "description": "Used when Cannon Development Mode is on. Use Cloudflare dummy keys (e.g. always-pass 1x00000000000000000000AA)."
    },
    "test_secret_key": {
      "type": "string",
      "title": "Test Secret Key",
      "description": "Used when Cannon Development Mode is on. Pair with the test site key (e.g. 1x0000000000000000000000000000000AA)."
    }
  },
  "required": ["site_key", "secret_key"]
}`)

var turnstileConfigUI = json.RawMessage(`{
  "type": "VerticalLayout",
  "elements": [
    {"type": "Group", "label": "Live Keys", "elements": [
      {"type": "Control", "scope": "#/properties/site_key"},
      {"type": "Control", "scope": "#/properties/secret_key"}
    ]},
    {"type": "Group", "label": "Test Keys (Development Mode)", "elements": [
      {"type": "Control", "scope": "#/properties/test_site_key"},
      {"type": "Control", "scope": "#/properties/test_secret_key"}
    ]}
  ]
}`)

type turnstileApp struct {
	info          extension.Info
	settingsTable string
	verifyURL     string
	client        *http.Client

	settingsMu     sync.RWMutex
	settingsCache  turnstileSettings
	settingsCached bool
}

type turnstileSettings struct {
	SiteKey       string `json:"site_key"`
	SecretKey     string `json:"secret_key"`
	TestSiteKey   string `json:"test_site_key"`
	TestSecretKey string `json:"test_secret_key"`
}

type cloudflareVerifyResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
}

func main() {
	if err := newServer().Run(); err != nil {
		log.Fatal(err)
	}
}

func newServer() *extension.Server {
	return newServerWithHTTP(turnstileVerifyURL, &http.Client{Timeout: 10 * time.Second})
}

func newServerWithHTTP(verifyURL string, client *http.Client) *extension.Server {
	info := extension.Info{
		Name:          extensionName,
		Title:         extensionTitle,
		Description:   extensionDescription,
		Version:       extensionVersion,
		UpdateURLBase: updateURLBase,
	}
	app := &turnstileApp{
		info:          info,
		settingsTable: extension.TableName(info.TablePrefix(), "settings"),
		verifyURL:     verifyURL,
		client:        client,
	}

	s := extension.New(info)
	s.EmbedHelp(helpFiles, "help")
	s.OnInstall(app.install)
	s.OnConfiguration(extension.MapConfiguration([]extension.ConfigurationDefinition{
		{
			ID:       configSection,
			Title:    "Cloudflare Turnstile",
			Schema:   turnstileConfigSchema,
			UISchema: turnstileConfigUI,
		},
	}, configStore{table: app.settingsTable, app: app}))
	s.RegisterCaptcha(extension.CaptchaRegistration{
		ProviderInfo: app.providerInfo,
		Render:       app.render,
		Verify:       app.verify,
	})
	return s
}

func (app *turnstileApp) install(req extension.WireRequest) error {
	db, _, err := extension.OpenDB()
	if err != nil {
		return err
	}
	return extension.MigrateConfigurationStore(db, app.settingsTable)
}

func (app *turnstileApp) providerInfo(req extension.WireRequest) (extension.CaptchaProviderInfo, error) {
	settings, err := app.loadSettings()
	if err != nil {
		return extension.CaptchaProviderInfo{}, err
	}
	siteKey, _, err := settings.activeKeys(req)
	if err != nil {
		return extension.CaptchaProviderInfo{}, err
	}
	return extension.CaptchaProviderInfo{
		ID:    app.info.Name,
		Title: app.info.Title,
		Contexts: []string{
			extension.CaptchaContextLogin,
			extension.CaptchaContextRegister,
			extension.CaptchaContextComment,
			extension.CaptchaContextForm,
		},
		Client: map[string]string{
			"site_key": siteKey,
		},
	}, nil
}

func (app *turnstileApp) render(req extension.WireRequest) (extension.CaptchaRenderResult, error) {
	settings, err := app.loadSettings()
	if err != nil {
		return extension.CaptchaRenderResult{}, err
	}
	siteKey, _, err := settings.activeKeys(req)
	if err != nil {
		return extension.CaptchaRenderResult{}, err
	}
	attrs := []string{
		`class="cf-turnstile"`,
		`data-sitekey="` + html.EscapeString(siteKey) + `"`,
	}
	if action := sanitizeAction(extension.CaptchaAction(req)); action != "" {
		attrs = append(attrs, `data-action="`+html.EscapeString(action)+`"`)
	}
	return extension.CaptchaRenderResult{
		HTML:      `<div ` + strings.Join(attrs, " ") + `></div>`,
		HeadHTML:  `<script src="` + turnstileScriptURL + `" async defer></script>`,
		FieldName: fieldName,
	}, nil
}

func (app *turnstileApp) verify(req extension.WireRequest) (extension.CaptchaVerifyResult, error) {
	settings, err := app.loadSettings()
	if err != nil {
		return extension.CaptchaVerifyResult{}, err
	}
	_, secretKey, err := settings.activeKeys(req)
	if err != nil {
		return extension.CaptchaVerifyResult{Valid: false, Error: err.Error()}, nil
	}
	form := url.Values{}
	form.Set("secret", secretKey)
	form.Set("response", extension.CaptchaToken(req))
	if remoteIP := extension.CaptchaRemoteIP(req); remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}
	httpReq, err := http.NewRequest(http.MethodPost, app.verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return extension.CaptchaVerifyResult{}, err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := app.client.Do(httpReq)
	if err != nil {
		return extension.CaptchaVerifyResult{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return extension.CaptchaVerifyResult{}, err
	}
	if resp.StatusCode >= 300 {
		return extension.CaptchaVerifyResult{}, fmt.Errorf("turnstile verify: status %d", resp.StatusCode)
	}
	var out cloudflareVerifyResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return extension.CaptchaVerifyResult{}, err
	}
	if out.Success {
		return extension.CaptchaVerifyResult{Valid: true}, nil
	}
	errMsg := "captcha verification failed"
	if len(out.ErrorCodes) > 0 {
		errMsg = errMsg + ": " + strings.Join(out.ErrorCodes, ", ")
	}
	return extension.CaptchaVerifyResult{Valid: false, Error: errMsg}, nil
}

func (cfg turnstileSettings) activeKeys(req extension.WireRequest) (siteKey, secretKey string, err error) {
	if extension.DevelopmentMode(req) {
		siteKey = strings.TrimSpace(cfg.TestSiteKey)
		secretKey = strings.TrimSpace(cfg.TestSecretKey)
		if siteKey == "" || secretKey == "" {
			return "", "", fmt.Errorf("turnstile test keys are not configured (enable Development Mode requires test_site_key and test_secret_key)")
		}
		return siteKey, secretKey, nil
	}
	siteKey = strings.TrimSpace(cfg.SiteKey)
	secretKey = strings.TrimSpace(cfg.SecretKey)
	if siteKey == "" {
		return "", "", fmt.Errorf("turnstile site key is not configured")
	}
	if secretKey == "" {
		return "", "", fmt.Errorf("turnstile secret key is not configured")
	}
	return siteKey, secretKey, nil
}

func (app *turnstileApp) loadSettings() (turnstileSettings, error) {
	app.settingsMu.RLock()
	if app.settingsCached {
		cfg := app.settingsCache
		app.settingsMu.RUnlock()
		return cfg, nil
	}
	app.settingsMu.RUnlock()

	data, err := (configStore{table: app.settingsTable, app: app}).Load(configSection)
	if err != nil {
		return turnstileSettings{}, err
	}
	settings := turnstileSettings{}
	if v, ok := data["site_key"].(string); ok {
		settings.SiteKey = strings.TrimSpace(v)
	}
	if v, ok := data["secret_key"].(string); ok {
		settings.SecretKey = strings.TrimSpace(v)
	}
	if v, ok := data["test_site_key"].(string); ok {
		settings.TestSiteKey = strings.TrimSpace(v)
	}
	if v, ok := data["test_secret_key"].(string); ok {
		settings.TestSecretKey = strings.TrimSpace(v)
	}
	app.settingsMu.Lock()
	app.settingsCache = settings
	app.settingsCached = true
	app.settingsMu.Unlock()
	return settings, nil
}

func (app *turnstileApp) invalidateSettings() {
	app.settingsMu.Lock()
	app.settingsCached = false
	app.settingsCache = turnstileSettings{}
	app.settingsMu.Unlock()
}

func sanitizeAction(action string) string {
	action = strings.TrimSpace(action)
	if action == "" {
		return ""
	}
	var out strings.Builder
	for _, r := range action {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			out.WriteRune(r)
		}
	}
	return out.String()
}

type configStore struct {
	table string
	app   *turnstileApp
}

func (s configStore) Load(section string) (map[string]any, error) {
	db, _, err := extension.OpenDB()
	if err != nil {
		return nil, err
	}
	return extension.DBConfigurationStore(db, s.table).Load(section)
}

func (s configStore) Save(section string, data map[string]any) error {
	db, _, err := extension.OpenDB()
	if err != nil {
		return err
	}
	if err := extension.DBConfigurationStore(db, s.table).Save(section, data); err != nil {
		return err
	}
	if s.app != nil {
		s.app.invalidateSettings()
	}
	return nil
}
