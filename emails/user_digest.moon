WeeklyFavoriteModules = require "widgets.base"

class UserDigest extends require "emails.base"
  subject: => "LuaRocks Digest"
  content: =>
    h2 "Hello #{@current_user\name_for_display!}, here is your weekly digest from LuaRocks, enjoy!"

    p "The more popular modules from this week!"
    WeeklyFavoriteModules weekly_favorites: @weekly_favorites

