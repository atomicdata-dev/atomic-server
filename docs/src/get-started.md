{{#title Get started with Atomic Data}}
# Get started with Atomic Data

There's a couple of levels at which you can start working with Atomic Data (from easy to hard):

- **Play with the demo**: Create an Agent, edit a document.
- **Host your own Atomic-Server**.
- **Create a react app with the template**
- **Set up the full dev environment**.
- **Create a library for Atomic Data**.

## Play with the demo

- Open [the Invite](https://atomicdata.dev/invites/1) on `atomicdata.dev`
- Press `Accept`. Now, the front-end app will generate a Private-Public Key pair. The public key will be sent to the server, which creates an Agent for you.
- You're now signed in! You can edit the document in your screen.
- Edit your Agent by going to [user settings](https://atomicdata.dev/app/agent)
- Copy your `secret`, and save it somewhere safe. You can use this to sign in on a different machine.
- Press `edit user` to add your name and perhaps a bio.
- When you're done, visit user settings again and press `sign out` to erase your credentials and end the session.

## Host your own Atomic-Sesrver (locally)

- If you have docker running, you can use this one-liner: `docker run -p 80:80 -v atomic-storage:/atomic-storage joepmeneer/atomic-server` (or use `cargo install atomic-server`, or the [binaries](https://github.com/atomicdata-dev/atomic-server/releases/))
- Now, visit `localhost` in your browser to access your server.
- It's now only available locally. If you want to get it on the _internet_, you need to set up a domain name, and make sure its traffic is routed to your computer (search `port forwarding`).

## Host your own Atomic-Server (on a VPS)

- **Set up a domain name** by using one of the many services that do this for you.
- **Get a virtual private server (VPS)** on which you can run `atomic-server`. We are running atomicdata.dev on the cheapest VPS we could find: $3.50 / month at [Vultr.com (use this link to give us $10 bucks of hosting credit)](https://www.vultr.com/?ref=8970814-8H).



- Browser app [atomic-data-browser](https://github.com/atomicdata-dev/atomic-data-browser) ([demo on atomicdata.dev](https://atomicdata.dev))
- Build a react app using [typescript & react libraries](https://github.com/atomicdata-dev/atomic-data-browser). Start with the [react template on codesandbox](https://codesandbox.io/s/atomic-data-react-template-4y9qu?file=/src/MyResource.tsx)
- Host your own [atomic-server](https://github.com/atomicdata-dev/atomic-data-browser) (powers [atomicdata.dev](https://atomicdata.dev), run with `docker run -p 80:80 -v atomic-storage:/atomic-storage joepmeneer/atomic-server`)
- Discover the command line tool: [atomic-cli](https://github.com/atomicdata-dev/atomic-server) (`cargo install atomic-cli`)
- Use the Rust library: [atomic-lib](https://github.com/atomicdata-dev/atomic-server)

Make sure to [join our Discord](https://discord.gg/a72Rv2P) if you'd like to discuss Atomic Data with others.
