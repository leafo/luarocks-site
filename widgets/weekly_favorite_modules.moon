class WeeklyFavoriteModules extends require "widgets.page"
  inner_content: =>
    p "The more popular modules from this week!"
    @render_modules @weekly_favorites

