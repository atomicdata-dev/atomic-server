# AtomicServer FAQ & Troubleshooting

## I can't find my question, I need support

- Create an [issue on github](https://github.com/atomicdata-dev/atomic-server/issues) or [join the discord](https://discord.gg/a72Rv2P)!

## Do I need NGINX or something?

No, AtomicServer has its own HTTPS support. Just pass a `--https` flag!

## Can I create backups?

There are two ways you can create backups:

1. **Export the JSON-AD**. Run `atomic-server export` to create a JSON-AD backup in your `~/.config/atomic/backups` folder.
Import them using `atomic-server import -p ~/.config/atomic/backups/${date}.json`.'
You could also copy all folders `atomic-server` uses. To see what these are, see `atomic-server show-config`.
1.  **Backup the database file**. use `atomic-server show-config` to find the `store_path` and copy the path to some place where you store the backup.

## I lost the key / secret to my Root Agent, and the `/setup` invite is no longer usable! What now?

You can run `atomic-server --initialize` to recreate the `/setup` invite. It will be reset to `1` usage.

## How do I migrate my data to a new domain?

There are no helper functions for this, but you could `atomic-server export` your JSON-AD, and find + replace your old domain with the new one.
This could especially be helpful if you're running at `localhost:9883` and want to move to a live server.

## How do I reset my database?

`atomic-server reset`. This deletes all of your data. Be careful!

## How do I make my data private, yet available online?

You can press the menu icon (the three dots in the navigation bar), go to sharing, and uncheck the public `read` right.
See the [Hierarchy chapter](https://docs.atomicdata.dev/hierarchy.html) in the docs on more info of the authorization model.

## Items are missing in my Collections / Search results

You might have a problem with your indexes.
Try rebuilding the indexes using `atomic-server --rebuild-index`.
Also, if you can, recreate and describe the indexing issue in the issue tracker, so we can fix it.

## I get a `failed to retrieve` error when opening

Try re-initializing atomic server `atomic-server --initialize`.

## Can I embed AtomicServer in another application?

Yes. This is what I'm doing with the Tauri desktop distribution of AtomicServer.
Check out the [`desktop`](https://github.com/atomicdata-dev/atomic-server/tree/master/desktop) code for an example!

## I want to use my own authorization. How do I do that?

You can disable all authorization using `--public-mode`.
Make sure AtomicServer is not publicly accessible, because this will allow anyone to read any data.

## Where is my data stored on my machine?

It depends on your operating system, because some data is _temporary_, others are _configuration files_, and so forth. Run `atomic-server show-config` to see the used paths. You can overwrite these if you want, see `--help`.

https://user-images.githubusercontent.com/2183313/139728539-d69b899f-6f9b-44cb-a1b7-bbab68beac0c.mp4
