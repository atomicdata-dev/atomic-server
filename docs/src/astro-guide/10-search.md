# Making a search bar for blogposts

## Using the search API

AtomicServer comes with a fast full-text search API out of the box.
@tomic/lib provides some convenient helper functions on Store to make using this API very easy.

To use search all you need to do is:

```typescript
const results = await store.search('how to make icecream');
```

The method returns an array of subjects of resources that match the given query.

To further refine the query, we can pass a filter object to the method like so:

```typescript
const results = await store.search('how to make icecream', {
  filters: {
    [core.properties.isA]: myPortfolio.classes.blogpost,
  },
});
```

This way the result will only include resources that have an `is-a` of `blogpost`.

## Running code on the client

To make a working search bar, we will have to run code on the client.
Astro code only runs on the server but there are a few ways to have code run on the client.
The most commonly used option would be to use a frontend framework like React or Svelte but Astro also allows script tags to be added to components that will be included in the `<head />` of the page.

To keep this guide framework-agnostic we will use a script tag and a web component but feel free to use any framework you're more comfortable with, the code should be simple enough to adapt to different frameworks.

First, we need to make a change to our environment variables because right now they are not available to the client and therefore `getStore` will not be able to access `ATOMIC_SERVER_URL`.
To make an environment variable accessible to the client it needs to be prefixed with `PUBLIC_`.

In `.env` change `ATOMIC_SERVER_URL` to `PUBLIC_ATOMIC_SERVER_URL`.

```env
// .env
PUBLIC_ATOMIC_SERVER_URL=<REPLACE WITH URL TO YOUR ATOMIC SERVER>
ATOMIC_HOMEPAGE_SUBJECT=<REPLACE WITH SUBJECT OF THE HOMEPAGE RESOURCE>
```

Now update `src/helpers/getStore.ts` to reflect the name change.

```typescript
// src/helpers/getStore.ts
import { Store } from '@tomic/lib';
import { initOntologies } from '../ontologies';

let store: Store;

export function getStore(): Store {
  if (!store) {
    store = new Store({
      serverUrl: import.meta.env.PUBLIC_ATOMIC_SERVER_URL,
    });

    initOntologies();
  }

  return store;
}
```

## Creating the search bar

In `src/components` create a file called `Search.astro`.

```html
<blog-search></blog-search>

<script>
  import { getStore } from '../../helpers/getStore';
  import { core } from '@tomic/lib';
  import { myPortfolio, type Blogpost } from '../../ontologies/myPortfolio';

  class BlogSearch extends HTMLElement {
    // Get access to the store. (Since this runs on the client a new instance will be created)
    private store = getStore();
    // Create an element to store the results in
    private resultsElement = document.createElement('div');

    // Runs when the element is mounted.
    constructor() {
      super();

      // We create an input element and add a listener to it that will trigger a search.
      const input = document.createElement('input');
      input.placeholder = 'Search...';
      input.type = 'search';

      input.addEventListener('input', (e) => {
        this.searchAndDisplay(input.value);
      });

      // Add the input and result list elements to the root of our webcomponent.
      this.append(input, this.resultsElement);
    }

    /**
     * Search for blog posts using the given query and display the results.
     */
    private async searchAndDisplay(query: string) {
      if (!query) {
        // Clear the results of the previous search.
        this.resultsElement.innerHTML = '';
        return;
      }

      const results = await this.store.search(query, {
        filters: {
          [core.properties.isA]: myPortfolio.classes.blogpost,
        },
      });

      // Map the result subjects to elements.
      const elements = await Promise.all(
        results.map(s => this.createResultItem(s)),
      );

      // Clear the results of the previous search.
      this.resultsElement.innerHTML = '';

      // Append the new results to the result list.
      this.resultsElement.append(...elements);
    }

    /**
     * Create a result link for the given blog post.
     */
    private async createResultItem(subject: string): Promise<HTMLAnchorElement> {
      const post = await this.store.getResourceAsync<Blogpost>(subject);

      const resultLine = document.createElement('a');
      resultLine.innerText = post.title;
      resultLine.style.display = 'block';
      resultLine.href = `/blog/${post.props.titleSlug}`;

      return resultLine;
    }
  }

  // Register the custom element.
  customElements.define('blog-search', BlogSearch);
</script>
```

If you've never seen web components before, `<blog-search>` is our custom element that starts as just an empty shell.
We then add a `<script>` that Astro will add to the head of our HTML.
In this script, we define the class that handles how to render the `<blog-search>` element.
At the end of the script, we register the custom element class.

> NOTE: </br>
> Eventhough the server will most likely keep up with this many requests, lower end devices might not so it's still a good idea to add some kind of debounce to your searchbar.

Now all that's left to do is use the component to the blog page.

```diff
// src/pages/blog/index.astro

...
<Layout resource={homepage}>
  <h2>Blog 😁</h2>
+ <Search />
  <ul>
    {
      posts.map(post => (
        <li>
          <BlogCard subject={post} />
        </li>
      ))
    }
  </ul>
</Layout>
```

And there it is! A working real-time search bar 🎉

<video loop autoplay muted>
<source src="videos/10-1.mp4">
</video>

## The end, what's next?

That's all for this guide.
Some things you could consider adding next if you liked working with AtomicServer and want to continue building this portfolio:

- Add some more styling
- Add some interactive client components using one of many [Astro integrations](https://docs.astro.build/en/guides/integrations-guide/) (Consider checking [@tomic/react](https://www.npmjs.com/package/@tomic/react) or [@tomic/svelte](https://www.npmjs.com/package/@tomic/svelte))
- Do some SEO optimisation by adding meta tags to your `Layout.astro`.
