
import encode_query_string, parse_query_string from require "lapis.util"
http = require "lapis.nginx.http"
json = require "cjson"

class GitHub
  login_prefix: "https://github.com"
  api_prefix: "https://api.github.com"

  new: (@client_id, @client_secret) =>

  login_url: (state) =>
    params = encode_query_string {
      client_id: @client_id
      scope: "user:email"
      :state
    }

    "#{@login_prefix}/login/oauth/authorize?#{params}"

  access_token: (code) =>
    params = encode_query_string {
      client_id: @client_id
      client_secret: @client_secret
      :code
    }

    res, status = http.simple {
      url: "#{@login_prefix}/login/oauth/access_token?#{params}"
      method: "POST"
    }

    if status != 200
      return nil, "unexpected status from github #{status}"

    out = parse_query_string res

    if out.error
      return nil, out.error

    out

  delete_access_token: (access_token) =>
    @_api_request "DELETE", "/applications/#{@client_id}/tokens/#{access_token}", {}, true

  -- for requests to api prefix
  _api_request: (method="GET", url, params={}, auth=false) =>
    if next params
      params = encode_query_string params
      url = "#{url}?#{params}"

    auth = if auth
      ngx.encode_base64 "#{@client_id}:#{@client_secret}"

    req = {
      :method
      url: "#{@api_prefix}#{url}"
      headers: {
        "User-agent": "luarocks.org"
        "Authorization": auth and "Basic #{auth}" or nil
      }
    }

    res, status = http.simple req

    if status != 200
      return nil, "unexpected status from github #{status} - #{res}"

    json.decode res

  user: (access_token) =>
    response = @_api_request "GET", "/user", { :access_token }

    unless response.email
      response.email = primary_email(access_token)

    return response

  primary_email: (acess_token) =>
    response = @_api_request "GET", "/user/emails", { :access_token }

    primary_email = nil

    for email in response do
      if email.primary
        primary_email = email.email

    return primary_email

  orgs: (user) =>
    @_api_request "GET", "/users/#{user}/orgs"

config = require("lapis.config").get!
GitHub config.github_client_id, config.github_client_secret
