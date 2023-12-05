{{#title @tomic/react: Using Atomic Data in a JS / TS React project}}
# @tomic/react: Using Atomic Data in a JS / TS React project

Atomic Data has been designed with front-end development in mind.
The open source [Atomic-Data-Browser](https://github.com/atomicdata-dev/atomic-data-browser), which is feature-packed with chatrooms, a real-time collaborative rich text editor, tables and more, is powered by two libraries:

- `@tomic/lib` ([docs](https://atomicdata-dev.github.io/atomic-data-browser/docs/modules/_tomic_lib.html)) is the core library, containing logic for fetching and storing data, keeping things in sync using websockets, and signing [commits](../commits/intro.md).
- `@tomic/react` ([docs](https://atomicdata-dev.github.io/atomic-data-browser/docs/modules/_tomic_react.html)) is the react library, featuring various useful hooks that mimic `useState`, giving you real-time updates through your app.

Check out the [template on CodeSandbox](https://codesandbox.io/s/atomic-data-react-template-4y9qu?file=/src/MyResource.tsx:0-1223):

<iframe src="https://codesandbox.io/embed/atomic-data-react-template-4y9qu?fontsize=14&hidenavigation=1&theme=dark"
  style="width:100%; height:500px; border:0; border-radius: 4px; overflow:hidden;"
  title="Atomic Data - React Template"
  allow="accelerometer; ambient-light-sensor; camera; encrypted-media; geolocation; gyroscope; hid; microphone; midi; payment; usb; vr; xr-spatial-tracking"
  sandbox="allow-forms allow-modals allow-popups allow-presentation allow-same-origin allow-scripts"
></iframe>

Feeling stuck? [Post an issue](https://github.com/atomicdata-dev/atomic-data-browser/issues/new) or [join the discord](https://discord.gg/a72Rv2P).
