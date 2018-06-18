lapis = require "lapis"
db = require "lapis.db"

import
  capture_errors
  respond_to
  assert_error
  from require "lapis.application"

import assert_valid from require "lapis.validate"
import trim_filter from require "lapis.util"

import
  assert_csrf
  assert_editable
  require_login
  capture_errors_404
  from require "helpers.app"

import load_module from require "helpers.loaders"

import
  Versions
  Rocks
  Dependencies
  Modules
  Followings
  from require "models"

delete_module = capture_errors_404 respond_to {
  before: =>
    load_module @
    @title = "Delete #{@module\name_for_display!}?"

  GET: require_login =>
    assert_editable @, @module

    if @version and @module\count_versions! == 1
      return redirect_to: @url_for "delete_module", @params

    render: true

  POST: require_login capture_errors =>
    assert_csrf @
    assert_editable @, @module

    assert_valid @params, {
      { "module_name", equals: @module.name }
    }

    if @version
      if @module\count_versions! == 1
        error "can not delete only version"

      @version\delete!
      redirect_to: @url_for "module", @params
    else
      @module\delete!
      redirect_to: @url_for "index"
}


class MoonRocksModules extends lapis.Application
  [module: "/modules/:user/:module"]: capture_errors_404 =>
    return unless load_module @

    @title = "#{@module\name_for_display!}"
    @page_description = @module.summary if @module.summary

    @versions = @module\get_versions!
    @manifests = @module\get_manifests!
    @depended_on = @module\find_depended_on!

    @module_following = @current_user and @current_user\follows @module
    @module_starring = @current_user and @current_user\stars @module

    Versions\sort_versions @versions

    for v in *@versions
      if v.id == @module.current_version_id
        @current_version = v

    unless @current_version
      vs = [v for v in *@versions]
      table.sort vs, (a, b) -> b.id < a.id
      @current_version = vs[1]

    if @current_version
      @dependencies = @current_version\get_dependencies!
      Dependencies\preload_modules @dependencies, @module\get_primary_manifest!

    render: true

  [edit_module: "/edit/modules/:user/:module"]: capture_errors_404 respond_to {
    before: =>
      load_module @
      assert_editable @, @module

      @title = "Edit #{@module\name_for_display!}"
      import ApprovedLabels from require "models"
      @suggested_labels = ApprovedLabels\select "order by name asc"

    GET: =>
      render: true

    POST: =>
      changes = @params.m

      assert_valid @params, {
        {"labels", type: "string", optional: true}
      }

      labels = Modules\parse_labels changes.labels or ""

      trim_filter changes, {
        "license", "description", "display_name", "homepage", "summary"
      }, db.NULL


      @module\update changes
      @module\set_labels labels or {}

      redirect_to: @url_for("module", @)
  }

  [edit_module_version: "/edit/modules/:user/:module/:version"]: capture_errors_404 respond_to {
    before: =>
      return unless load_module @
      assert_editable @, @module

      @title = "Edit #{@module\name_for_display!} #{@version.version_name}"
      @rocks = @version\get_rocks!

    GET: =>
      render: true

    POST: capture_errors =>
      assert_csrf @

      @params.v or= {}

      assert_valid @params, {
        {"v", type: "table"}
      }

      version_update = trim_filter @params.v
      development = not not version_update.development
      archived = not not version_update.archived

      external_rockspec_url = if @current_user\is_admin!
        assert_valid version_update, {
          {"external_rockspec_url", type: "string", optional: true}
        }

        if url = version_update.external_rockspec_url
          unless url\match "%w+://"
            url = "http://" .. url
          url
        else
          db.NULL


      @version\update {
        :development
        :archived
        :external_rockspec_url
      }

      redirect_to: @url_for("module_version", @)
  }

  [module_version: "/modules/:user/:module/:version"]: capture_errors_404 =>
    return unless load_module @

    @title = "#{@module\name_for_display!} #{@version.version_name}"
    @rocks = Rocks\select "where version_id = ? order by arch asc", @version.id

    @module_following = @current_user and @current_user\follows @module

    render: true

  [delete_module: "/delete/:user/:module"]: delete_module
  [delete_module_version: "/delete/:user/:module/:version"]: delete_module

  [delete_rock: "/delete/:user/:module/:version/:arch"]: require_login capture_errors_404 respond_to {
    before: =>
      load_module @
      assert_editable @, @rock

      @title = "Delete #{@module\name_for_display!}?"

    GET: =>
      render: true

    POST: capture_errors =>
      assert_csrf @

      @rock\delete!
      redirect_to: @url_for @version
  }


  [follow_module: "/module/:module_id/follow/:type"]: require_login capture_errors_404 =>
    assert_valid @params, {
      {"module_id", is_integer: true}
      {"type", one_of: {"subscription", "bookmark"} }
    }

    @module = assert_error Modules\find(@params.module_id),
      "invalid module"

    @flow("followings")\follow_object @module, @params.type
    @flow("events")\create_event_and_deliver @module, @params.type

    redirect_to: @url_for @module

  [unfollow_module: "/module/:module_id/unfollow/:type"]: require_login capture_errors_404 =>
    assert_valid @params, {
      {"module_id", is_integer: true}
      {"type", one_of: {"subscription", "bookmark"} }
    }

    @module = assert_error Modules\find(@params.module_id),
      "invalid module"

    @flow("followings")\unfollow_object @module, @params.type
    @flow("events")\remove_from_timeline @module, @params.type

    redirect_to: @url_for @module
