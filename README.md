# Cannon Cloudflare Turnstile Extension

Provides Cloudflare Turnstile rendering and verification for Cannon's captcha capability.

## Features

- Renders Cloudflare Turnstile widgets for Cannon forms.
- Verifies submitted Turnstile tokens server-side.
- Keeps the secret key in extension configuration storage.
- Can be used by Cannon forms that render captcha placeholders.

## Cannon Capabilities

This extension exposes:

- `/meta`: extension name, description, version, and update URL base.
- `/capabilities`: captcha, configuration, and help capabilities.
- `/captcha`: provider metadata and public client configuration.
- `/captcha/render`: Turnstile widget HTML and script.
- `/captcha/verify`: server-side token verification.
- `/configuration`: Cloudflare Turnstile settings.
- `/help`: extension help content.
- `/install`: creates the extension settings table.

## Configuration

Use Cannon's extension configuration screen to set:

- `site_key`: public Cloudflare Turnstile site key.
- `secret_key`: private Cloudflare Turnstile secret key.

## Usage

Install and activate `cannon-ext-captcha-cfturnstile`, then configure the Cloudflare keys. Cannon can render captcha placeholders such as:

```html
<captcha context="form" provider="any"></captcha>
```

or template calls such as:

```go
{{captcha "login"}}
```

The rendered token field is `cf-turnstile-response`.

## Releases

The extension reports:

- Name: `cannon-ext-captcha-cfturnstile`
- Version: `0.1.0`
- Update URL base: `https://github.com/rob121/cannon-ext-captcha-cfturnstile/releases/download`

GitHub releases should include a `cannon-extension.json` manifest plus platform binaries.
