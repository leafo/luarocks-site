
class extends require "widgets.base"
  content: =>
    h2 ->
      text "#{@user.username}'s Modules"
      text " "
      span class: "header_count", "(#{#@modules})"
    
    @render_modules @modules

