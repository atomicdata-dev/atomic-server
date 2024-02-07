# Setting up the frontend

Lets start with setting up Astro.

> **NOTE:** </br>
> I will use **npm** since that is the standard but you can of course use other package managers like pnpm (which I would normally choose)

To create an Astro project open your terminal in the folder you'd like to house the projects folder and run the following command:

```
npm create astro@latest
```

You will be presented by a wizard, here you can choose the folder you want to create and setup stuff like typescript.

We will choose the following options:

1. "Where should we create your new project?": `./astro-guide` (feel free to change this to anything you like)
2. "How would you like to start your new project?": choose `Empty`
3. "Install dependencies?": `Yes`
4. "Do you plan to write TypeScript?": `Yes` > `Strict`
5. "Initialize a new git repository?" Choose whatever you want here

Open the newly created folder in your favourite editor and navigate to the folder in your terminal

Check to see if everything went smoothly by testing out if it works. Run `npm run dev` and navigate to the address shown in the output (http://localhost:4321/)
You should see a boring page that looks like this:
![astro](/assets/astro-guide/3-1.webp)

### About Astro

If you've never used astro before here is a short primer:

Pages in astro are placed in the pages folder and use the `.astro` format. Files that end with `.astro` are Astro components and are always rendered on the server or at build time (But never on the client)

Routing is achieved via the filesystem so for example the file `pages/blog/how-to-sharpen-a-pencil.astro` is accessibly via `https://mysite.com/blog/how-to-sharpen-a-pencil`.

To share layout like headers and footers between pages we use Layout components, these are placed in the `layouts` folder. Lets create a layout right now.

### Layout

In `src` create a folder called `layouts` and in there a file called `Layout.astro`.

```html
<!-- src/layouts/Layout.astro -->

<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="description" content="Astro description" />
    <meta name="viewport" content="width=device-width" />
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
    <meta name="generator" content="{Astro.generator}" />
    <title>Some title</title>
  </head>
  <body>
    <header>
      <nav>
        <ul>
          <li>
            <a href="/">Home</a>
          </li>
          <li>
            <a href="/blog">Blog</a>
          </li>
        </ul>
      </nav>
      <h1>Some heading</h1>
      <p>Some header text</p>
    </header>
    <slot />
  </body>
</html>

<style is:global>
  body {
    font-family: system-ui;
  }
</style>
```

This bit of html will be wrapped around the page which will be rendered in the slot element.

Next update the `src/pages/index.astro` file to this

```jsx
---
// src/pages/index.astro
import Layout from '../layouts/Layout.astro';
---

<Layout>
	<p>Hello world!</p>
</Layout>
```

Our page should now look like this:

![Browser with a basic webpage](/assets/astro-guide/3-2.webp)

Time to take a brake from Astro and create our data model in the Atomic Data Browser.
