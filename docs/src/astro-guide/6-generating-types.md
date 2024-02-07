# Generating Types

It's time to generate some Typescript types and display our data in the Astro frontend.

First things first, installing the `@tomic/lib` and `@tomic/cli` packages.

```
npm install @tomic/lib
npm install -D @tomic/cli
```

To generate types based on the ontology we just created the cli needs to know where to get that data from. We can configure this using the `atomic.config.json` file.

Run the following command to generate one at the current working directory (Make sure this is the root of the Astro project)

```
npx ad-generate init
```

A config file called `atomic.config.json` has been generated, it should look something like this:

```json
{
  "outputFolder": "./src/ontologies",
  "moduleAlias": "@tomic/lib",
  "ontologies": []
}
```

Now lets add the subject of our ontology to the `ontologies` list. To get the subject go to your ontology in the browser and copy the url from the address bar or from the navigation/search bar at the bottom. Paste the url as string in the ontologies array like so:

```json
"ontologies": [
	"<insert my-ontology url>"
]
```

We're ready to generate the types, Run the following command:

```
npx ad-generate ontologies
```

> **NOTE:** </br>
> If your data does not have public read rights you will have to specify the agent to use to fetch the ontology:
> `npx ad-generate ontologies -a <YOUR_AGENT_SECRET>`.
> However you should consider keeping at least your ontologies publicly readable if you want to make it more easy for other apps to integrate with your stuff

If everything went as planned we should now have an `ontologies` folder inside `src` with two files: our portfolio ontology and an index.ts

Each time you rerun the ad-generate command it fetches the latest version of the ontologies specified in the config file and overwrites what's in `src/ontologies`. You'll have to rerun this command to update the types when you make changes in one of these ontologies.
