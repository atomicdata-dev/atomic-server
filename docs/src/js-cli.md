{{#title @tomic/cli: Generate Typescript types from an Ontology}}

# @tomic/cli: Generate Typescript types from an Ontology

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

## Getting started

### Installation

You can install the package globally or as a dev dependency of your project.

**Globally**:

```
npm install -g @tomic/cli
```

You should now be able to run:

```
ad-generate
```

**Dev Dependency:**

```
npm install -D @tomic/cli
```

To run:

```
npx ad-generate
```

### Generating the files

To start generating your ontologies you first need to configure the cli. Start by creating the config file by running:

```
ad-generate init
```

There should now be a file called `atomic.config.json` in the folder where you ran this command. The contents will look like this:

```json
{
  "outputFolder": "./src/ontologies",
  "moduleAlias": "@tomic/lib",
  "ontologies": []
}
```

> If you want to change the location where the files are generated you can change the `outputFolder` field.

Next add the subjects of your atomic ontologies to the `ontologies` array in the config.

Now we will generate the ontology files. We do this by running the `ad-generate ontologies` command. If your ontologies don't have public read rights you will have to add an agent secret to the command that has access to these resources.

```
ad-generate ontologies --agent <AGENT_SECRET>
```

> Agent secret can also be preconfigured in the config **but be careful** when using version control as you can easily leak your secret this way.

After running the command the files will have been generated in the specified output folder along with an `index.ts` file. The only thing left to do is to register our ontologies with @tomic/lib. This should be done as soon in your apps runtime lifecycle as possible, for example in your App.tsx when using React or root index.ts in most cases.

```typescript
import { initOntologies } from './ontologies';

initOntologies();
```

### Using the types

If everything went well the generated files should now be in the output folder.
In order to gain the benefit of the typings we will need to annotate our resource with its respective class as follows:

```typescript
import { Book, creativeWorks } from './ontologies/creativeWorks.js';

const book = await store.getResourceAsync<Book>(
  'https://mybookstore.com/books/1',
);
```

Now we know what properties are required and recommended on this resource so we can safely infer the types

Because we know `written-by` is a required property in `book` we can safely infer type string;

```typescript
const authorSubject = book.get(creativeWorks.properties.writtenBy); // string
```

`description` has datatype Markdown and is inferred as string but it is a recommended property and might therefore be undefined

```typescript
const description = book.get(core.properties.description); // string | undefined
```

If the property is not in any ontology we can not infer the type so it will be of type `JSONValue`
(this type includes `undefined`)

```typescript
const unknownProp = book.get('https://unknownprop.site/prop/42'); // JSONValue
```

### Props shorthand

Because you've generated your ontologies, lib is aware of what properties exist and what their name and types are.
It is therefore possible to use the `.props` field on a resource and get full intellisense and typing!

```typescript
const book = await store.getResourceAsync<Book>(
  'https://mybookstore.com/books/1',
);

const name = book.props.name; // string
const description = book.props.description; // string | undefined
```

> The props field is a computed property and is readonly.
>
> If you have to read **very** large number of properties at a time it is more efficient to use the `resource.get()` method instead of the props field because the props field iterates over the resources propval map.

## Configuration

`@tomic/cli` loads the config file from the root of your project. This file should be called `atomic.config.json` and needs to conform to the following interface.

```typescript
interface AtomicConfig {
  /**
   * Path relative to this file where the generated files should be written to.
   */
  outputFolder: string;

  /**
   * [OPTIONAL] The @tomic/lib module identifier.
   * The default should be sufficient in most but if you have given the module an alias you should change this value
   */
  moduleAlias?: string;

  /**
   * [OPTIONAL] The secret of the agent that is used to access your atomic data server. This can also be provided as a command line argument if you don't want to store it in the config file.
   * If left empty the public agent is used.
   */
  agentSecret?: string;

  /** The list of subjects of your ontologies */
  ontologies: string[];
}
```

Running `ad-generate init` will create this file for you that you can then tweak to your own preferences.
