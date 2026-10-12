# @tomic/template

```sh
npm create @tomic/template my-project -- --template <TEMPLATE> --server-url <SERVER_URL> --drive <DRIVE_SUBJECT>
pnpm create @tomic/template my-project --template <TEMPLATE> --server-url <SERVER_URL> --drive <DRIVE_SUBJECT>
bun create @tomic/template my-project --template <TEMPLATE> --server-url <SERVER_URL> --drive <DRIVE_SUBJECT>
yarn create @tomic/template my-project --template <TEMPLATE> --server-url <SERVER_URL> --drive <DRIVE_SUBJECT>
```

`@tomic/template` is a tool that helps you kickstart a new project using AtomicServer using a variaty of pre build templates that you can further customize to your needs.

`SERVER_URL` is the HTTP(S) API origin. `DRIVE_SUBJECT` is the `atomic:`
identity of the drive where the template data was installed.

In order to use these templates you need the coresponding template data on your AtomicServer.
To get this data go to the new resource page and click on the template you want.
A dialog will open with a description of the template and a button to add the data to your server.

The following templates are available:

| Name             | Description                                                          | AtomicServer Template |
| ---------------- | -------------------------------------------------------------------- | --------------------- |
| `sveltekit-site` | A sveltekit website with dynamically rendered content and blog posts | Website               |
| `nextjs-site`    | A nextjs website with dynamically rendered content and blog posts    | Website               |
