_Check out [the docs here](https://docs.atomicdata.dev/js-cli)._

`@tomic/cli` is an NPM tool that helps the developer with creating a front-end for their atomic data project by providing typesafety on resources.
In atomic data you can create [ontologies](https://atomicdata.dev/class/ontology) that describe your business model.
You can use `@tomic/cli` to generate Typscript types for these ontologies in your front-end.

```typescript
import { Post } from './ontolgies/blog'; // <--- generated

const myBlogpost = await store.getResourceAsync<Post>(
  'https://myblog.com/atomic-is-awesome',
);

const comments = myBlogpost.props.comments; // string[] automatically inferred!
```
