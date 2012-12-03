
uri = ngx.var.request_uri

-- manifests are served by the app
return ngx.exec "/" if uri\match "manifest/?$"

import Users, Modules, Versions, Rocks, Manifests from require "models"

assert = (thing) ->
  ngx.exit 404 unless thing
  thing

should_increment = ->
  if agent = ngx.var.http_user_agent
    agent = agent\lower!
    if agent\match"luasocket" or agent\match"wget"
      true

is_rockspec = ->
  (uri\match "%.rockspec$")

object = if uri\match "^/manifests"
  slug = ngx.var[1]
  file = ngx.var[2]
  user = assert Users\find(:slug)

  key = "#{user.id}/#{file}"

  if is_rockspec!
    Versions\find rockspec_key: key
  else
    Rocks\find rock_key: key
else
  file = ngx.var[1]
  manifest = Manifests\root!

  -- TODO: do this with less complex query
  if is_rockspec!
    unpack Versions\select [[
      INNER JOIN manifest_modules
        ON (manifest_modules.module_id = versions.module_id and manifest_modules.manifest_id = ?)
      WHERE rockspec_fname = ?
    ]], manifest.id, file
  else
    unpack Rocks\select [[
      INNER JOIN versions
        ON (versions.id = rocks.version_id)
      INNER JOIN manifest_modules
        ON (manifest_modules.module_id = versions.module_id and manifest_modules.manifest_id = ?)
      WHERE rock_fname = ?
    ]], manifest.id, file

assert object
object\increment_download! if object.increment_download
ngx.var._url = object\url!

