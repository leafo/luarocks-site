-- User management actions not related to modules

lapis = require "lapis"
db = require "lapis.db"

import
  respond_to
  assert_error
  yield_error
  capture_errors_json
  from require "lapis.application"

import assert_valid from require "lapis.validate"
import trim_filter from require "lapis.util"

shapes = require "helpers.shapes"
import types from require "tableshape"

password_shape = shapes.valid_text * types.string\length 2, 150

import
  ApiKeys
  Users
  Manifests
  ManifestModules
  Followings
  from require "models"

import
  assert_csrf
  require_login
  ensure_https
  capture_errors_404
  assert_editable
  verify_return_to
  capture_errors
  from require "helpers.app"

import
  transfer_endorsements
  from require "helpers.toolbox"

import load_module, load_manifest from require "helpers.loaders"
import paginated_modules from require "helpers.modules"

import preload from require "lapis.db.model"

assert_table = (val) ->
  assert_error type(val) == "table", "malformed input, expecting table"
  val

validate_reset_token = =>
  if @params.token
    assert_valid @params, {
      { "id", is_integer: true }
    }

    @user = assert_error Users\find(@params.id), "invalid token"
    @user\get_data!
    assert_error @user.data.password_reset_token == @params.token, "invalid token"
    @token = @params.token
    true

class MoonRocksUser extends lapis.Application
  [user_profile: "/modules/:user"]: capture_errors_404 =>
    @user = assert_error Users\find(slug: @params.user), "invalid user"

    @title = "#{@user\name_for_display!}'s Modules"
    @user_following = @current_user and @current_user\find_follow @user

    paginated_modules @, @user, (mods) ->
      for mod in *mods
        mod.user = @user
      mods

    render: true

  [user_login: "/login"]: ensure_https respond_to {
    before: =>
      @canonical_url = @build_url @url_for "user_login"
      @title = "Login"

    GET: =>
      render: true

    POST: capture_errors =>
      assert_csrf @

      params = shapes.assert_params @params, {
        username: shapes.limited_text 25
        password: shapes.valid_text * types.string\length 1, 150
      }

      user = assert_error Users\login params.username, params.password
      user\write_session @, type: "login_password"

      redirect_to: verify_return_to(@params.return_to) or @url_for "index"
  }

  [user_register: "/register"]: ensure_https respond_to {
    before: =>
      @canonical_url = @build_url @url_for "user_register"
      @title = "Register Account"

    GET: =>
      render: true

    POST: capture_errors =>
      assert_csrf @

      params = shapes.assert_params @params, {
        username: shapes.limited_text 25
        password: password_shape
        password_repeat: password_shape
        email: shapes.email
      }

      assert_error params.password == params.password_repeat, "Password repeat does not match"

      {:username, :password, :email } = params
      user = assert_error Users\create username, password, email

      user\write_session @, type: "register"
      redirect_to: verify_return_to(@params.return_to) or @url_for"index"
  }

  -- TODO: make this post
  [user_logout: "/logout"]: =>
    @session.user = false

    if @current_user_session
      @current_user_session\revoke!

    redirect_to: "/"

  [user_forgot_password: "/user/forgot_password"]: ensure_https respond_to {
    GET: capture_errors =>
      validate_reset_token @
      render: true

    POST: capture_errors =>
      assert_csrf @

      if validate_reset_token @
        params = shapes.assert_params @params, {
          password: password_shape
          password_repeat: password_shape
        }

        assert_error params.password == params.password_repeat, "Password repeat does not match"

        @user\update_password params.password, @
        @user.data\update { password_reset_token: db.NULL }
        redirect_to: @url_for"index"
      else
        params = shapes.assert_params @params, {
          email: shapes.email / string.lower
        }

        user = assert_error Users\find([db.raw "lower(email)"]: params.email),
          "don't know anyone with that email"

        token = user\generate_password_reset!

        reset_url = @build_url @url_for"user_forgot_password",
          query: "token=#{token}&id=#{user.id}"

        UserPasswordResetEmail = require "emails.user_password_reset"
        UserPasswordResetEmail\send @, user.email, { :user, :reset_url }

        redirect_to: @url_for"user_forgot_password" .. "?sent=true"
  }

  ["user_settings.link_github": "/settings/link-github"]: ensure_https require_login respond_to {
    GET: =>
      @user = @current_user
      @title = "Link GitHub - User Settings"
      @github_accounts = @user\get_github_accounts!
      render: true
  }

  ["user_settings.import_toolbox": "/settings/import-toolbox"]: ensure_https require_login respond_to {
    before: =>
      @user = @current_user

      import ToolboxImport from require "helpers.toolbox"
      import Modules from require "models"
      @to_import = ToolboxImport!\modules_endorsed_by_user @user

      if @to_import
        Modules\preload_relation @to_import, "user"
        Modules\preload_follows @to_import, @user
        @already_following = [m for m in *@to_import when m.current_user_following]
        @to_import = [m for m in *@to_import when not m.current_user_following]

    GET: =>
      @title = "Import Lua Toolbox - User Settings"
      render: true

    POST: =>
      assert_csrf @
      assert_error @to_import and next(@to_import), "missing modules to follow"

      for m in *@to_import
        @flow("followings")\follow_object m, "subscription"

      redirect_to: @url_for("user_settings.import_toolbox")
  }

  ["user_settings.reset_password": "/settings/reset-password"]: ensure_https require_login respond_to {
    before: =>
      @user = @current_user
      @title = "Reset Password - User Settings"

    GET: =>
      render: true

    POST: capture_errors =>
      import UserActivityLogs from require "models"

      assert_csrf @

      passwords = shapes.assert_params @params.password, {
        current_password: password_shape
        new_password: password_shape
        new_password_repeat: password_shape
      }

      assert_error passwords.new_password == passwords.new_password_repeat,
        "Password repeat does not match"

      unless @user\check_password passwords.current_password
        UserActivityLogs\create_from_request @, {
          user_id: @user.id
          source: "web"
          action: "account.update_password_attempt"
          data: { reason: "incorrect old password" }
        }

        yield_error "Incorrect old password"
        error "Incorrect old password (not captured)"

      old_pword = @user.encrypted_password
      @user\update_password passwords.new_password, @

      UserActivityLogs\create_from_request @, {
        user_id: @user.id
        source: "web"
        action: "account.update_password"
        data: {
          encrypted_password: {
            before: old_pword
            after: @user.encrypted_password
          }
        }
      }

      redirect_to: @url_for "user_settings.reset_password", nil, reset_password: "true"
  }

  ["user_settings.api_keys": "/settings/api-keys"]: ensure_https require_login respond_to {
    before: =>
      @user = @current_user
      @title = "Api Keys - User Settings"
      @api_keys = if @params.revoked
        @show_revoked = true
        @user\get_revoked_api_keys!
      else
        @user\get_api_keys!

    GET: =>
      render: true

    POST: capture_errors =>
      assert_csrf @
      trim_filter @params
      assert_valid @params, {
        {"api_key", exists: true, type: "string"}
        {"comment", optional: true, max_length: 255}
      }

      key = ApiKeys\find @current_user.id, assert @params.api_key
      assert_error key and key.user_id == @current_user.id, "invalid key"
      assert_error not key.revoked, "invalid key"

      key\update {
        comment: @params.comment or db.NULL
      }

      redirect_to: @url_for "user_settings.api_keys"
  }

  ["user_settings.profile": "/settings/profile"]: ensure_https require_login respond_to {
    before: =>
      @user = @current_user
      @title = "Profile - User Settings"

    GET: =>
      render: true

    POST: capture_errors =>
      assert_csrf @

      profile_update = shapes.assert_params @params.profile, {
        website: shapes.url + shapes.empty / db.NULL
        twitter: shapes.twitter_username + shapes.empty / db.NULL
        github: shapes.limited_text(120) + shapes.empty / db.NULL
        profile: shapes.limited_text(1024*4) + shapes.empty / db.NULL
      }

      difference = shapes.difference profile_update, @user\get_data!

      if next difference
        @user\get_data!\update profile_update
        import UserActivityLogs from require "models"

        UserActivityLogs\create_from_request @, {
          user_id: @user.id
          source: "web"
          action: "account.update_profile"
          data: difference
        }

      redirect_to: @url_for "user_settings.profile"

  }

  ["user_settings.security_audit": "/settings/security-audit"]: ensure_https require_login respond_to {
    before: =>
      @user = @current_user
      @title = "Security Audit"

    GET: =>
      import UserServerLogs from require "models"
      @server_logs = UserServerLogs\select "where user_id = ? order by log_date asc", @current_user.id

      if @params.download
        ngx.header["Content-Type"] = "text/plain"
        for log in *@server_logs
          ngx.say log.log

        return layout: false

      render: true
  }

  ["user_settings.sessions": "/settings/sessions"]: ensure_https require_login respond_to {
    POST: capture_errors_json =>
      assert_csrf @
      assert_valid @params, {
        {"action", one_of: {"disable_session"}}
      }

      switch @params.action
        when "disable_session"
          assert_valid @params, {
            {"session_id", exists: true, is_integer: true}
          }

          import UserSessions from require "models"

          session = UserSessions\find {
            user_id: assert @current_user.id
            id: assert @params.session_id
          }

          if session
            session\revoke!

          return redirect_to: @url_for "user_settings.sessions"

    GET: =>
      import UserSessions from require "models"

      pager = UserSessions\paginated "
        where user_id = ?
        order by coalesce(last_active_at, created_at) desc
      ", @current_user.id, {
        per_page: 20
      }

      @sessions = pager\get_page!

      render: true
  }

  ["user_settings.activity": "/settings/activity"]: ensure_https require_login respond_to {
    GET: =>
      import UserActivityLogs from require "models"
      pager = UserActivityLogs\paginated "
        where user_id = ?
        order by created_at desc
      ", @current_user.id, {
        per_page: 40
        prepare_results: (logs) ->
          preload logs, "object", "user"
          logs
      }

      @user_activity_logs = pager\get_page!

      render: true
  }


  -- old settings url goes to api keys page since that's where tool points to
  "/settings": ensure_https require_login =>
    redirect_to: @url_for "user_settings.api_keys"

  [add_to_manifest: "/add-to-manifest/:user/:module"]: capture_errors_404 require_login respond_to {
    before: =>
      load_module @
      assert_editable @, @module

      @title = "Add Module To Manifest"

      already_in = { m.id, true for m in *@module\get_manifests! }
      @manifests = for m in *Manifests\select!
        continue if already_in[m.id]
        m

    GET: =>
      render: true

    POST: capture_errors =>
      assert_csrf @

      assert_valid @params, {
        { "manifest_id", is_integer: true }
      }

      manifest = assert_error Manifests\find(id: @params.manifest_id), "Invalid manifest id"

      unless manifest\allowed_to_add @current_user
        yield_error "Don't have permission to add to manifest"

      assert_error ManifestModules\create manifest, @module
      redirect_to: @url_for("module", @)
  }


  [remove_from_manifest: "/remove-from-manifest/:user/:module/:manifest"]: capture_errors_404 require_login respond_to {
    before: =>
      load_module @
      load_manifest @

      assert_editable @, @module

    GET: =>
      @title = "Remove Module From Manifest"

      assert_error ManifestModules\find({
        manifest_id: @manifest.id
        module_id: @module.id
      }), "Module is not in manifest"

      render: true

    POST: =>
      assert_csrf @

      ManifestModules\remove @manifest, @module
      redirect_to: @url_for("module", @)
  }


  [notifications: "/notifications"]: require_login =>
    import Notifications from require "models"
    @unseen_notifications = Notifications\select "
      where user_id = ? and not seen
      order by id desc
    ", @current_user.id

    @seen_notifications = Notifications\select "
      where user_id = ? and seen
      order by id desc
      limit 20
    ", @current_user.id

    if next(@unseen_notifications) and not @params.keep_notifications
      db.update Notifications\table_name!, {
        seen: true
      }, id: db.list [n.id for n in *@unseen_notifications]

    all = [n for n in *@unseen_notifications]
    for n in *@seen_notifications
      table.insert all, n

    Notifications\preload_for_display all
    @title = "Notifications"
    render: true

  [follow_user: "/users/:slug/follow"]: require_login capture_errors_404 =>
    followed_user = assert_error Users\find(slug: @params.slug),
      "Invalid User"

    assert_error @current_user.id != followed_user.id,
      "You can't follow yourself"

    @flow("followings")\follow_object followed_user, "subscription"

    redirect_to: @url_for followed_user

  [unfollow_user: "/users/:slug/unfollow"]: require_login capture_errors_404 =>
    unfollowed_user = assert_error Users\find(slug: @params.slug),
      "Invalid User"

    @flow("followings")\unfollow_object unfollowed_user, "subscription"

    redirect_to: @url_for unfollowed_user

  [weekly_digest: "/users/weekly_digest"]: require_login capture_errors_404 =>
    import Modules from require "models"

    weekly_favorites_followings_query = db.query "select object_id, count(*) from followings
      where object_type = 1 and created_at >= current_date - interval '7' day
      group by object_id order by count(*) desc limit 5"

    @weekly_favorites = {}

    for following in *weekly_favorites_followings_query
      table.insert @weekly_favorites, Modules\find following.object_id

    Users\include_in @weekly_favorites, "user_id"

--    render: true

    UserDigest = require "emails.user_digest"
    UserDigest\send @, @current_user.email, {
      current_user: @current_user,
      weekly_favorites: @weekly_favorites
    }
