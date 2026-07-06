# Cloudflare Turnstile

This extension provides Cloudflare Turnstile captcha support for Cannon protected forms.

Configure the extension with the Turnstile site key and secret key from Cloudflare, then select Cloudflare Turnstile as the active captcha provider in Cannon's global captcha settings.

Forms can render the active provider with:

```html
<captcha context="form" provider="any"></captcha>
```

Cannon handles placeholder expansion and token verification through the captcha capability. This extension does not need hook-based placement.
