#!/usr/bin/env lua
-- Standalone unit tests for plugins/crowdsec/captcha.lua
--
-- The captcha plugin talks to ngx.* and to lua-resty-http, so the module is loaded
-- with small stubs instead of a real OpenResty worker. This keeps the validation
-- logic (request shape, provider-specific parsing, fail-open rules) testable with
-- nothing but a plain Lua interpreter:
--
--   lua tests/smartcaptcha_unit.lua
--
-- exit code 0 on success, 1 on the first failed assertion.

package.path = "lib/?.lua;lib/?/init.lua;" .. package.path

-- ---------------------------------------------------------------------------
-- stubs
-- ---------------------------------------------------------------------------

local json_decode

local ngx_log = {}
local ngx = {
  HTTP_OK = 200,
  ERR = 4,
  ALERT = 1,
  WARN = 2,
  DEBUG = 8,
  header = {},
  log = function(level, msg) ngx_log[#ngx_log + 1] = { level = level, msg = msg } end,
  -- nginx semantics: percent-encode everything outside [A-Za-z0-9-_.~], space as %20
  escape_uri = function(s)
    return (tostring(s):gsub("[^%w%-%._~]", function(c)
      return string.format("%%%02X", string.byte(c))
    end))
  end,
}
ngx.encode_args = function(args)
  local parts = {}
  for k, v in pairs(args) do
    if type(v) == "table" then
      for _, item in ipairs(v) do
        parts[#parts + 1] = ngx.escape_uri(k) .. "=" .. ngx.escape_uri(item)
      end
    elseif v ~= nil then
      parts[#parts + 1] = ngx.escape_uri(k) .. "=" .. ngx.escape_uri(v)
    end
  end
  table.sort(parts)
  return table.concat(parts, "&")
end
_G.ngx = ngx

-- queued fake HTTP responses
local http_queue = {}
local http_requests = {}
package.preload["resty.http"] = function()
  return {
    new = function()
      return {
        set_timeout = function() end,
        close = function() end,
        request_uri = function(_, url, opts)
          http_requests[#http_requests + 1] = { url = url, opts = opts }
          local next_resp = table.remove(http_queue, 1)
          if next_resp == nil then
            error("no queued http response")
          end
          return next_resp.res, next_resp.err
        end,
      }
    end,
  }
end

package.preload["cjson"] = function()
  return { decode = function(body) return json_decode(body) end }
end

package.preload["plugins.crowdsec.template"] = function()
  return { compile = function(tpl, data) return tpl .. "\n--" .. tostring(data.captcha_frontend_js or "") end }
end

package.preload["plugins.crowdsec.template"] = nil -- use the real template module

local template_file = "templates/captcha.html"

package.preload["plugins.crowdsec.utils"] = function()
  return {
    HTTP_CODE = { ["200"] = 200, ok = 200 },
    file_exist = function(path) return path == template_file end,
    read_file = function(path)
      local f = assert(io.open(path, "r"))
      local data = f:read("*a")
      f:close()
      return data
    end,
  }
end

-- minimal JSON decoder, enough for the payloads the captcha providers return
json_decode = function(str)
  local pos = 1
  local function skip() pos = str:find("[^ \t\r\n]", pos) or (#str + 1) end
  local parse_value
  local function parse_string()
    assert(str:sub(pos, pos) == '"', "expected string at " .. pos)
    pos = pos + 1
    local out = {}
    while true do
      local c = str:sub(pos, pos)
      if c == '"' then pos = pos + 1; return table.concat(out) end
      if c == "" then error("unterminated string") end
      if c == "\\" then
        local esc = str:sub(pos + 1, pos + 1)
        local map = { n = "\n", t = "\t", r = "\r", b = "\b", f = "\f", ['"'] = '"', ["\\"] = "\\", ["/"] = "/" }
        if map[esc] then out[#out + 1] = map[esc]; pos = pos + 2
        elseif esc == "u" then out[#out + 1] = "?"; pos = pos + 6
        else error("bad escape") end
      else out[#out + 1] = c; pos = pos + 1 end
    end
  end
  function parse_value()
    skip()
    local c = str:sub(pos, pos)
    if c == "{" then
      local obj = {}
      pos = pos + 1
      skip()
      if str:sub(pos, pos) == "}" then pos = pos + 1; return obj end
      while true do
        skip()
        local key = parse_string()
        skip()
        assert(str:sub(pos, pos) == ":", "expected ':'")
        pos = pos + 1
        obj[key] = parse_value()
        skip()
        local sep = str:sub(pos, pos)
        pos = pos + 1
        if sep == "}" then return obj end
        assert(sep == ",", "expected ',' or '}'")
      end
    elseif c == "[" then
      local arr = {}
      pos = pos + 1
      skip()
      if str:sub(pos, pos) == "]" then pos = pos + 1; return arr end
      while true do
        arr[#arr + 1] = parse_value()
        skip()
        local sep = str:sub(pos, pos)
        pos = pos + 1
        if sep == "]" then return arr end
        assert(sep == ",", "expected ',' or ']'")
      end
    elseif c == '"' then
      return parse_string()
    elseif str:sub(pos, pos + 3) == "true" then pos = pos + 4; return true
    elseif str:sub(pos, pos + 4) == "false" then pos = pos + 5; return false
    elseif str:sub(pos, pos + 3) == "null" then pos = pos + 4; return nil
    else
      local num = str:match("^-?%d+%.?%d*[eE]?[-+]?%d*", pos)
      assert(num, "unexpected token at " .. pos)
      pos = pos + #num
      return tonumber(num)
    end
  end
  local value = parse_value()
  return value
end

local captcha = require "plugins.crowdsec.captcha"

-- ---------------------------------------------------------------------------
-- helpers
-- ---------------------------------------------------------------------------

local failures = 0

local function check(name, ok, detail)
  if ok then
    io.write("ok   - ", name, "\n")
  else
    failures = failures + 1
    io.write("FAIL - ", name, "\n")
    if detail ~= nil then io.write("       ", tostring(detail), "\n") end
  end
end

local function eq(name, got, want)
  check(name, got == want, "got " .. tostring(got) .. ", want " .. tostring(want))
end

local function queue_response(res, err)
  http_queue[#http_queue + 1] = { res = res, err = err }
end

local function decode_form(body)
  local out = {}
  for pair in body:gmatch("[^&]+") do
    local k, v = pair:match("^([^=]*)=(.*)$")
    -- application/x-www-form-urlencoded: '+' is a space, decoded before %XX escapes
    local function unescape(s)
      s = s:gsub("%+", " ")
      return (s:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end))
    end
    out[unescape(k)] = unescape(v)
  end
  return out
end

local function reset()
  http_queue = {}
  http_requests = {}
  ngx_log = {}
  ngx.encode_args = ngx.encode_args
end

local function new_provider(provider, secret)
  local err = captcha.New("ysc1_site", secret or "ysc2_secret", template_file, provider, nil)
  eq("New() accepts provider " .. provider, err, nil)
end

-- ---------------------------------------------------------------------------
-- provider table
-- ---------------------------------------------------------------------------

reset()
captcha.New("site", "secret", template_file, "turnstile", nil)
eq("turnstile backend key is unchanged", captcha.GetCaptchaBackendKey(), "cf-turnstile-response")

reset()
new_provider("smartcaptcha")
eq("smartcaptcha backend key is smart-token", captcha.GetCaptchaBackendKey(), "smart-token")

reset()
eq("unknown provider is rejected", (captcha.New("k", "s", template_file, "nope", nil) or ""):match("not supported") ~= nil, true)
eq("empty provider is rejected", (captcha.New("k", "s", template_file, "", nil) or ""):match("not supported") ~= nil, true)

-- ---------------------------------------------------------------------------
-- smartcaptcha validation
-- ---------------------------------------------------------------------------

-- a token with every character that breaks a naive k=v concatenation
local TOKEN = "dD0xNjYyNDU3NDMzO2k9MmEwMjo2Yjg6+/==&x=1%zz"

reset()
new_provider("smartcaptcha")
queue_response({ status = 200, body = '{"status":"ok","message":"","host":"example.com"}' })
local valid, err = captcha.Validate(TOKEN, "203.0.113.7")
eq("smartcaptcha ok -> valid", valid, true)
eq("smartcaptcha ok -> no error", err, nil)

local req = http_requests[1]
eq("smartcaptcha posts to the Yandex validate endpoint", req.url, "https://smartcaptcha.cloud.yandex.ru/validate")
eq("smartcaptcha uses POST", req.opts.method, "POST")
eq("smartcaptcha sends a form body", req.opts.headers["Content-Type"], "application/x-www-form-urlencoded")

local form = decode_form(req.opts.body)
eq("smartcaptcha body has secret", form.secret, "ysc2_secret")
eq("smartcaptcha body has ip", form.ip, "203.0.113.7")
eq("smartcaptcha body has an untouched token", form.token, TOKEN)
eq("smartcaptcha body has no recaptcha fields", form.response, nil)

-- robot
reset()
new_provider("smartcaptcha")
queue_response({ status = 200, body = '{"status":"failed","message":""}' })
valid, err = captcha.Validate("tok", "203.0.113.7")
eq("smartcaptcha failed -> invalid", valid, false)
eq("robot failure is not an error", err, nil)

-- expired / reused token
reset()
new_provider("smartcaptcha")
queue_response({ status = 200, body = '{"status":"failed","message":"Invalid or expired Token."}' })
valid = captcha.Validate("tok", "203.0.113.7")
eq("expired token -> invalid", valid, false)
check("expired token is logged",
  ngx_log[#ngx_log] ~= nil and tostring(ngx_log[#ngx_log].msg):find("Invalid or expired Token", 1, true) ~= nil,
  ngx_log[#ngx_log] and ngx_log[#ngx_log].msg)

-- invalid secret: HTTP 403 with a JSON body, fail open like the recaptcha path
reset()
new_provider("smartcaptcha")
queue_response({ status = 403, body = '{"status":"failed","message":"Authentication failed. Invalid secret."}' })
valid, err = captcha.Validate("tok", "203.0.113.7")
eq("smartcaptcha invalid secret -> fail open", valid, true)
eq("smartcaptcha invalid secret -> no error", err, nil)
check("smartcaptcha invalid secret is logged",
  ngx_log[#ngx_log] ~= nil and tostring(ngx_log[#ngx_log].msg):find("secret key is invalid", 1, true) ~= nil)

-- empty host
reset()
new_provider("smartcaptcha")
queue_response({ status = 200, body = '{"status":"ok","message":"","host":""}' })
valid = captcha.Validate("tok", "203.0.113.7")
eq("smartcaptcha ok with empty host -> fail open", valid, true)

-- transport failure
reset()
new_provider("smartcaptcha")
queue_response(nil, "timeout")
valid, err = captcha.Validate("tok", "203.0.113.7")
eq("smartcaptcha transport error -> fail open", valid, true)
eq("smartcaptcha transport error is reported", err, "timeout")

-- empty body
reset()
new_provider("smartcaptcha")
queue_response({ status = 502, body = "" })
valid, err = captcha.Validate("tok", "203.0.113.7")
eq("smartcaptcha empty body -> fail open", valid, true)
check("smartcaptcha empty body is reported", err ~= nil, tostring(err))

-- garbage body
reset()
new_provider("smartcaptcha")
queue_response({ status = 200, body = "<html>oops</html>" })
valid, err = captcha.Validate("tok", "203.0.113.7")
eq("smartcaptcha garbage body -> fail open", valid, true)
check("smartcaptcha garbage body is reported", err ~= nil, tostring(err))

-- ---------------------------------------------------------------------------
-- non-smartcaptcha providers keep the old behaviour
-- ---------------------------------------------------------------------------

reset()
new_provider("hcaptcha")
queue_response({ status = 200, body = '{"success":true}' })
valid = captcha.Validate("tok", "203.0.113.7")
eq("hcaptcha success -> valid", valid, true)
req = http_requests[1]
local legacy_form = decode_form(req.opts.body)
eq("hcaptcha still posts secret", legacy_form.secret, "ysc2_secret")
eq("hcaptcha still posts response", legacy_form.response, "tok")
eq("hcaptcha still posts remoteip", legacy_form.remoteip, "203.0.113.7")
eq("hcaptcha does not post a smartcaptcha token", legacy_form.token, nil)

reset()
new_provider("hcaptcha")
queue_response({ status = 200, body = '{"success":false,"error-codes":["invalid-input-secret"]}' })
valid = captcha.Validate("tok", "203.0.113.7")
eq("hcaptcha invalid secret -> fail open", valid, true)

reset()
new_provider("recaptcha")
queue_response({ status = 200, body = '{"success":false,"error-codes":["invalid-input-response"]}' })
valid = captcha.Validate("tok", "203.0.113.7")
eq("recaptcha rejected answer -> invalid", valid, false)

-- ---------------------------------------------------------------------------
-- template wiring
-- ---------------------------------------------------------------------------

reset()
new_provider("smartcaptcha")
check("template gets the SmartCaptcha js",
  tostring(captcha.Template):find("https://smartcaptcha.cloud.yandex.ru/captcha.js", 1, true) ~= nil,
  captcha.Template)

-- the widget contract: the container class has to be "smart-captcha", it has to carry
-- the site key and it has to sit inside the form that gets submitted, otherwise the
-- hidden smart-token input is not posted back to the bouncer
local rendered = captcha.Template
local form_start = rendered:find('<form', 1, true)
local form_end = rendered:find('</form>', 1, true)
local container = rendered:find('<div id="captcha" class="smart-captcha"', 1, true)
check("rendered template has the smart-captcha container", container ~= nil)
check("the site key is injected into the container",
  rendered:find('data-sitekey="ysc1_site"', 1, true) ~= nil)
check("the container is inside the submitted form",
  form_start ~= nil and form_end ~= nil and container ~= nil
    and form_start < container and container < form_end)
check("the callback the widget calls is defined",
  rendered:find("function captchaCallback", 1, true) ~= nil)
check("the rendered template has no leftover placeholders",
  rendered:find("{{", 1, true) == nil)

if failures > 0 then
  io.write(("\n%d check(s) failed\n"):format(failures))
  os.exit(1)
end
io.write("\nall checks passed\n")
