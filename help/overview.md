# Cloudflare Turnstile

This extension provides Cloudflare Turnstile captcha support for Cannon protected forms.

Configure **Live Keys** and optional **Test Keys** under the extension settings, then select Cloudflare Turnstile as the active captcha provider in Cannon's global captcha settings.

When **Development Mode** is enabled in Cannon General settings, this extension uses the test site/secret keys (Cloudflare dummy keys work well for local work). When Development Mode is off, live keys are used.

Forms can render the active provider with:

```html
<captcha context="form" provider="any"></captcha>
```

Cannon handles placeholder expansion and token verification through the captcha capability. This extension does not need hook-based placement.
