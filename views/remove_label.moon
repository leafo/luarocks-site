class RemoveLabel require "widgets.page"
  inner_content: =>
    h2 "Remove Label: #{@module.name}"
    @render_modules { @module }
    @render_errors!

    form action: @req.cmd_url, method: "POST", ->
      input type: "hidden", name: "csrf_token", value: @csrf_token
      div ->
        text "Are you sure you want to remove this label from "
        a href: "", @module.name
        text "? "
        input type: "submit", value: "Yes, Remove"

    div ->
      a href: @url_for("module", @), ->
        raw "&laquo; No, Return to module"

