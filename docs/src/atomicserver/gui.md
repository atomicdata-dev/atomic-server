# Using the AtomicServer GUI

## Creating the first Agent on AtomicData.dev

Before you can create new things on AtomicData.dev, you'll need an _Agent_.
This is your virtual User, which can create, sign and own things.

Simply open the [demo invite](https://atomicdata.dev/invites/1) and press accept.

Copy the `secret` from the user settings page and save it somewhere safe, like in a password manager.

## Using your local AtomicServer

After [running the server](installation.md), open it in your browser.
By default, that's at [`http://localhost:9883`](http://localhost:9883).
<!-- (Fun fact: `&#9883;` is HTML entity code for the Atom icon: ⚛.) -->

The first screen should show you your main [_Drive_](https://atomicdata.dev/classes/Drive).
You can think of this as your root folder.
It is the resource hosted at the root URL, effectively being the home page of your server.

There's an instruction on the screen about the `/setup` page.
Click this, and you'll get a screen showing an [_Invite_](https://atomicdata.dev/classes/Invite).
Normally, you could `Accept as new user`, but **since you're running on `localhost`, you won't be able to use the newly created Agent on non-local Atomic-Servers**.

Therefore, it may be best to create an Agent on some _other_ running server, such as the [demo Invite on AtomicData.dev](https://atomicdata.dev/invites/1).
And after that, copy the Secret from the `User settings` panel from AtomicData.dev, go back to your `localhost` version, and press `sign in`.
Paste the Secret, and voila! You're signed in.

Now, again go to `/setup`. This time, you can `Accept as {user}`.
After clicking, your Agent has gotten `write` rights for the Drive!
You can verify this by hovering over the description field, clicking the edit icon, and making a few changes.
You can also press the menu button (three dots, top left) and press `Data view` to see your agent after the `write` field.
Note that you can now edit every field.
You can also fetch your data now as various formats.

Try checking out the other features in the menu bar, and check out the `collections`.

Again, check out the [README](https://github.com/atomicdata-dev/atomic-server) for more information and guides!

Now, let's create some data.

## Creating your first Atomic Data

Now let's create a [_Table_](https://atomicdata.dev/classes/Table).
A Class represents an abstract concept, such as a `BlogPost` (which we'll do here).
We can do this in a couple of ways:

- Press the `+ icon` button on the left menu (only visible when logged in), and selecting Class
- Opening [Class](https://atomicdata.dev/classes/Class) and pressing `new class`
- Going to the [Classes Collection](https://atomicdata.dev/classes/) and pressing the plus icon

The result is the same: we end up with a form in which we can fill in some details.

Let's add a shortname (singular), and then a description.
After that, we'll add the `required` properties.
This form you're looking at is constructed by using the `required` and `recommended` Properties defined in `Class`.
We can use these same fields to generate our BlogPost resource!
Which fields would be required in a `BlogPost`?
A `name`, and a `description`, probably.

So click on the `+ icon` under `requires` and search for these Properties to add them.

Now, we can skip the `recommended` properties, and get right to saving our newly created `BlogPost` class.
So, press save, and now look at what you created.

Notice a couple of things:

- Your Class has its own URL.
- It has a `parent`, shown in the top of the screen. This has impact on the visibility and rights of your Resource. We'll get to that [later in the documentation](../hierarchy.md).

Now, go to the navigation bar, which is by default at the bottom of the window. Use its context menu to open the `Data View`.
This view gives you some more insight into your newly created data, and various ways in which you can serialize it.
