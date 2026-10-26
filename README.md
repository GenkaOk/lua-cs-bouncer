# lua-cs-bouncer

> Lua module to allow ip (or not) from CrowdSec API.

:warning: This library will only work with [lua-nginx-module](https://github.com/openresty/lua-nginx-module) 

This library is used by different bouncers : 

* [Nginx Bouncer](https://docs.crowdsec.net/docs/next/bouncers/nginx)
* [OpenResty Bouncer](https://docs.crowdsec.net/docs/next/bouncers/openresty)
* [Ingress Nginx Bouncer](https://docs.crowdsec.net/docs/next/bouncers/ingress-nginx)

## This fork: Yandex SmartCaptcha

This is a fork of `crowdsecurity/lua-cs-bouncer` based on tag **v1.0.19** that adds
`smartcaptcha` as a captcha provider (branch `smartcaptcha`, patch confined to
`lib/plugins/crowdsec/captcha.lua`).

Configure it in the bouncer config file:

```ini
CAPTCHA_PROVIDER=smartcaptcha
SITE_KEY=ysc1_...   # client key
SECRET_KEY=ysc2_... # server key
```

What the patch changes:

| | upstream | this fork |
|---|---|---|
| frontend JS | per provider | `https://smartcaptcha.cloud.yandex.ru/captcha.js` |
| widget container class | per provider | `smart-captcha` |
| posted field read from the form | `<frontend>-response` | `smart-token` |
| validation endpoint | `.../siteverify` | `https://smartcaptcha.cloud.yandex.ru/validate` |
| validation body | `secret/response/remoteip` | `secret/token/ip` (form-encoded, the token may contain `+`, `/`, `=`) |
| success condition | `success == true` | `status == "ok"` |

Fail-open behaviour is the same as upstream: a transport error, an empty or
undecodable answer, or an invalid secret key is logged and the request is let
through (a broken captcha must not lock every visitor out). `status: "ok"` with an
empty `host` (Yandex-side failure) is logged and let through as well.

No changes are required to `templates/captcha.html`: the Yandex widget mounts into
the container `div`, fills the hidden `smart-token` input **inside** it (so the
token is part of the form POST) and calls `data-callback` only after the input is
populated, which is exactly what the template does for the other providers.

### Unit tests

The validation logic can be tested without a running OpenResty (plain Lua; it stubs
`ngx`, `resty.http` and `cjson`, and renders the real `templates/captcha.html`):

```bash
# run from the root of this repository
lua tests/smartcaptcha_unit.lua
```

Also run in CI by `.github/workflows/smartcaptcha-unit.yml`.
