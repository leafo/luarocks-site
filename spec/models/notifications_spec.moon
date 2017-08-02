import use_test_env from require "lapis.spec"
import truncate_tables from require "lapis.spec.db"


factory = require "spec.factory"

import
  Users
  Modules
  Manifests
  Versions
  Notifications
  NotificationObjects
  from require "models"


describe "models.notifications", ->
  use_test_env!

  before_each ->
    truncate_tables Users, Modules, Manifests, Versions, Notifications,
      NotificationObjects

  it "creates a notification for following module", ->
    user = factory.Users!
    mod = factory.Modules user_id: user.id

    action, notification = Notifications\notify_for user, mod, "subscription", factory.Users!
    assert.same "insert", action
    assert.same { notification }, Notifications\select!

    action, notification = Notifications\notify_for user, mod, "subscription", factory.Users!
    assert.same "update", action
    assert.same {notification}, Notifications\select!

    -- unrelated user
    action, notification = Notifications\notify_for factory.Users!, factory.Modules!, "subscription", factory.Users!
    assert.same "insert", action
    assert.same 2, Notifications\count!

    assert.same 3, NotificationObjects\count!

  it "creates a notification for starring module", ->
    user = factory.Users!
    mod = factory.Modules user_id: user.id

    action, notification = Notifications\notify_for user, mod, "bookmark", factory.Users!
    assert.same "insert", action
    assert.same { notification }, Notifications\select!

    action, notification = Notifications\notify_for user, mod, "bookmark", factory.Users!
    assert.same "update", action
    assert.same {notification}, Notifications\select!

    -- unrelated user
    action, notification = Notifications\notify_for factory.Users!, factory.Modules!, "bookmark", factory.Users!
    assert.same "insert", action
    assert.same 2, Notifications\count!

    assert.same 3, NotificationObjects\count!

