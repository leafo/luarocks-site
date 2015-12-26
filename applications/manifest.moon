-- app responsible for rendering manifests

MANIFEST_LUA_VERSIONS = { "5.1", "5.2", "5.3" }

lapis = require "lapis"

import redis_cache from require "helpers.redis_cache"

import
  assert_error
  capture_errors
  from require "lapis.application"

import assert_valid from require "lapis.validate"

import
  Manifests
  Modules
  Users
  Versions
  Rocks
  from require "models"

import build_manifest, preload_modules, serve_lua_table from require "helpers.manifests"
import get_all_pages from require "helpers.models"
import capture_errors_404, assert_page from require "helpers.app"
import zipped_file from require "helpers.zip"

import cached from require "lapis.cache"

config = require("lapis.config").get!

-- XXX: This is totally wrong, RESTful APIs should use Content negotiation
-- (header Accept) to specify the desired media type. This approach is used
-- only for backward compatibility.
with_format = (fn) ->
  =>
    if format = (@params.version or '')\match "%.(%a+)$"
      @format = format
      @params.version = @params.version\sub 1, -format\len! - 2
    else
      @format = "lua"

    fn @

zipable = (fn) ->
  =>
    @write fn @

    if @format == "zip" and (@options.status or 200) == 200 and @req.cmd_mth == "GET"
      @version or= @params.version

      fname = "manifest"
      if @version
        fname ..= "-#{@version}"

      @options.content_type = "application/zip"
      @buffer = { zipped_file fname, table.concat @buffer }

    nil

serve_manifest = capture_errors_404 =>
  if @params.version
    assert_valid @params, {
      { "version", one_of: MANIFEST_LUA_VERSIONS }
    }

    @version = @params.version

  -- find what we are fetching modules from
  thing = if @params.user
    assert_error Users\find(slug: @params.user), "invalid user"
  else
    Manifests\root!

  if thing.__class == Manifests
    date = require "date"
    @res\add_header "Last-Modified", date(thing.updated_at)\fmt "${http}"

    -- on HEAD just return last modified
    if @req.cmd_mth == "HEAD"
      return { layout: false }

  -- get the modules
  pager = thing\find_modules {
    fields: "id, name"
    per_page: 50
    prepare_results: preload_modules
  }

  modules = get_all_pages pager
  manifest = build_manifest modules, @version, @development

  if @format == "json"
    json: manifest
  else
    serve_lua_table @, manifest

cached_manifest = (fn) ->
  cached {
    dict: redis_cache "manifest"
    cache_key: (path) -> path\gsub "%.zip$", ""
    exptime: 60 * 10
    when: =>
      return false unless @req.cmd_mth == "GET"
      config._name == "production"

    fn
  }

is_dev = (fn) ->
  =>
    @development = true
    fn @

is_stable = (fn) ->
  =>
    @development = false
    fn @

class MoonRocksManifest extends lapis.Application
  [root_manifest: "/manifest"]: cached_manifest is_stable serve_manifest

  [root_manifest_dev: "/dev/manifest"]: cached_manifest is_dev serve_manifest

  "/manifest-:version": with_format zipable cached_manifest is_stable serve_manifest

  "/dev/manifest-:version": with_format zipable cached_manifest is_dev serve_manifest

  [user_manifest: "/manifests/:user/manifest"]: serve_manifest

  "/manifests/:user/manifest-:version": with_format serve_manifest

  "/dev": => redirect_to: @url_for "root_manifest_dev"
  "/manifests/:user": => redirect_to: @url_for("user_manifest", user: @params.user)

  [manifests: "/manifests"]: capture_errors_404 =>
    @title = "All manifests"
    import ManifestAdmins from require "models"

    assert_page @

    @pager = Manifests\paginated [[
      order by id asc
    ]], prepare_results: (manifests) ->
      ManifestAdmins\include_in manifests, "manifest_id", flip: true, many: true
      mas = {}

      for m in *manifests
        if admins = m.manifest_admins
          for a in *admins
            table.insert mas, a

      Users\include_in mas, "user_id"
      manifests

    @manifests = @pager\get_page @page
    render: true

