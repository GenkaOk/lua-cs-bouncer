local http = require "resty.http"
local cjson = require "cjson"
local template = require "plugins.crowdsec.template"
local utils = require "plugins.crowdsec.utils"

local M = {_TYPE='module', _NAME='recaptcha.funcs', _VERSION='1.0-0'}

local captcha_backend_url = {}
captcha_backend_url["recaptcha"] = "https://www.recaptcha.net/recaptcha/api/siteverify"
captcha_backend_url["hcaptcha"] = "https://hcaptcha.com/siteverify"
captcha_backend_url["turnstile"] = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
-- Yandex SmartCaptcha: unlike the other providers its endpoint is not a "<key>-response"
-- style verifier, the form fields are secret/token/ip and the answer is {"status":"ok"|"failed"}
captcha_backend_url["smartcaptcha"] = "https://smartcaptcha.cloud.yandex.ru/validate"

local captcha_frontend_js = {}
captcha_frontend_js["recaptcha"] = "https://www.recaptcha.net/recaptcha/api.js"
captcha_frontend_js["hcaptcha"] = "https://js.hcaptcha.com/1/api.js"
captcha_frontend_js["turnstile"] = "https://challenges.cloudflare.com/turnstile/v0/api.js"
captcha_frontend_js["smartcaptcha"] = "https://smartcaptcha.cloud.yandex.ru/captcha.js"

local captcha_frontend_key = {}
captcha_frontend_key["recaptcha"] = "g-recaptcha"
captcha_frontend_key["hcaptcha"] = "h-captcha"
captcha_frontend_key["turnstile"] = "cf-turnstile"
-- class of the container div the Yandex widget is mounted into
captcha_frontend_key["smartcaptcha"] = "smart-captcha"

-- name of the hidden input the Yandex widget fills with the one-time token inside
-- the container div (i.e. inside the captcha form), so it is posted back to us as is
local captcha_backend_key = {}
captcha_backend_key["smartcaptcha"] = "smart-token"

M.SecretKey = ""
M.SiteKey = ""
M.Template = ""
M.ret_code = ngx.HTTP_OK

function M.New(siteKey, secretKey, TemplateFilePath, captcha_provider, ret_code)

    if captcha_backend_url[captcha_provider] == nil then
      return "CAPTCHA_PROVIDER '" .. tostring(captcha_provider) .. "' is not supported, valid providers are recaptcha, hcaptcha, turnstile, smartcaptcha"
    end

    if siteKey == nil or siteKey == "" then
      return "no recaptcha site key provided, can't use recaptcha"
    end
    M.SiteKey = siteKey

    if secretKey == nil or secretKey == "" then
      return "no recaptcha secret key provided, can't use recaptcha"
    end

    M.SecretKey = secretKey

    if TemplateFilePath == nil then
      return "CAPTCHA_TEMPLATE_PATH variable is empty, will ban without template"
    end
    if utils.file_exist(TemplateFilePath) == false then
      return "captcha template file doesn't exist, can't use recaptcha"
    end

    local captcha_template = utils.read_file(TemplateFilePath)
    if captcha_template == nil then
        return "Template file " .. TemplateFilePath .. "not found."
    end

    M.CaptchaProvider = captcha_provider

    local ret_code_ok = false
    if ret_code ~= nil and ret_code ~= 0 and ret_code ~= "" then
        for k, v in pairs(utils.HTTP_CODE) do
            if k == ret_code then
                M.ret_code = utils.HTTP_CODE[ret_code]
                ret_code_ok = true
                break
            end
        end
        if ret_code_ok == false then
            ngx.log(ngx.ERR, "CAPTCHA_RET_CODE '" .. ret_code .. "' is not supported, using default HTTP code " .. M.ret_code)
        end
    end

    local template_data = {}
    template_data["captcha_site_key"] =  M.SiteKey
    template_data["captcha_frontend_js"] = captcha_frontend_js[M.CaptchaProvider]
    template_data["captcha_frontend_key"] = captcha_frontend_key[M.CaptchaProvider]
    local view = template.compile(captcha_template, template_data)
    M.Template = view

    return nil
end

function M.apply()
    ngx.header.content_type = "text/html"
    ngx.header.cache_control = "no-cache"
    ngx.status = M.ret_code
    ngx.say(M.Template)
    ngx.exit(M.ret_code)
end

function M.GetCaptchaBackendKey()
    if captcha_backend_key[M.CaptchaProvider] ~= nil then
        return captcha_backend_key[M.CaptchaProvider]
    end
    return captcha_frontend_key[M.CaptchaProvider] .. "-response"
end

function table_to_encoded_url(args)
    local params = {}
    for k, v in pairs(args) do table.insert(params, k .. '=' .. v) end
    return table.concat(params, "&")
end

--- SmartCaptcha answers 403 with a JSON body when the secret key is missing or invalid.
--- Like the recaptcha "invalid-input-secret" case below we fail open: a broken captcha
--- configuration must not lock every visitor out, the error is only logged.
--- @return boolean: true if the failure is a misconfiguration of the secret key
local function is_secret_error(result)
    return result.status ~= "ok"
        and type(result.message) == "string"
        and string.find(result.message, "Authentication failed", 1, true) ~= nil
end

function M.Validate(captcha_res, remote_ip)
    local data
    if M.CaptchaProvider == "smartcaptcha" then
        -- the token is opaque base64 and may contain '+', '/' or '=' : it has to be
        -- escaped, a raw "k..'='..v" concatenation would corrupt the body
        data = ngx.encode_args({
            secret = M.SecretKey,
            token  = captcha_res,
            ip     = remote_ip,
        })
    else
        data = table_to_encoded_url({
            secret   = M.SecretKey,
            response = captcha_res,
            remoteip = remote_ip,
        })
    end

    local httpc = http.new()
    httpc:set_timeout(2000)
    local res, err = httpc:request_uri(captcha_backend_url[M.CaptchaProvider], {
      method = "POST",
      body = data,
      headers = {
          ["Content-Type"] = "application/x-www-form-urlencoded",
      },
    })
    httpc:close()
    if err ~= nil then
      return true, err
    end
    if res == nil or res.body == nil or res.body == "" then
      return true, "empty response from " .. tostring(captcha_backend_url[M.CaptchaProvider])
    end

    local decoded, result = pcall(cjson.decode, res.body)
    if decoded == false or type(result) ~= "table" then
      return true, "cannot decode captcha provider response: " .. tostring(res.body)
    end

    if M.CaptchaProvider == "smartcaptcha" then
      if result.status ~= "ok" then
        if is_secret_error(result) then
          ngx.log(ngx.ERR, "SmartCaptcha secret key is invalid: " .. tostring(result.message))
          return true, nil
        end
        ngx.log(ngx.ERR, "SmartCaptcha validation failed: " .. tostring(result.message) .. " (http " .. tostring(res.status) .. ")")
        return false, nil
      end
      -- "status":"ok" with an empty host means the verification did not really land on a
      -- website (cloud access blocked or an internal failure on Yandex's side). We keep
      -- the fail-open behaviour of the other providers for this anomalous case and only
      -- log it, the service itself recommends treating it as ok.
      if result.host == nil or result.host == "" then
        ngx.log(ngx.ERR, "SmartCaptcha returned status 'ok' with an empty host, letting the request through")
      end
      return true, nil
    end

    if result.success == false then
      for k, v in pairs(result["error-codes"]) do
        if v == "invalid-input-secret" then
          ngx.log(ngx.ERR, "reCaptcha secret key is invalid")
          return true, nil
        end
      end 
    end

    return result.success, nil
end


return M
