# Cannon Cloudflare Turnstile Extension

Provides Cloudflare Turnstile captcha rendering and verification for Cannon's captcha capability.

## Configuration

Use **Configuration -> Extensions -> Cloudflare Turnstile** to set:

- `site_key`: public Turnstile site key.
- `secret_key`: private Turnstile secret key for server-side verification.

The secret key is stored in the extension configuration table and is never returned from `GET /captcha`.

## Capability

This extension exposes:

- `GET /captcha`: provider metadata and public client config.
- `POST /captcha/render`: Turnstile widget HTML and script.
- `POST /captcha/verify`: server-side verification against Cloudflare.
- `GET/POST /configuration`: JSON Forms settings.

Cannon renders placeholders such as:

```html
<captcha context="form" provider="any"></captcha>
```

or:

```go
{{captcha "login"}}
```

The rendered token field is `cf-turnstile-response`.
