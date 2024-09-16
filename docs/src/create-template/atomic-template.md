# @tomic/template

```sh
npm create @tomic/template my-project -- --template <TEMPLATE> --server-url <SERVER_URL>
pnpm create @tomic/template my-project --template <TEMPLATE> --server-url <SERVER_URL>
bun create @tomic/template my-project --template <TEMPLATE> --server-url <SERVER_URL>
yarn create @tomic/template my-project --template <TEMPLATE> --server-url <SERVER_URL>
```

`@tomic/template` is a tool that helps you kickstart a new project using AtomicServer using a variaty of pre build templates that you can further customize to your needs.

In order to use these templates you need the coresponding template data on your AtomicServer.
To get this data go to the new resource page and click on the template you want.
A dialog will open with a description of the template and a button to add the data to your server.

The following templates are available:

Name | Description | AtomicServer Template
--- | --- | ---
`sveltekit-site` | A sveltekit website with dynamically rendered content and blog posts | Website
