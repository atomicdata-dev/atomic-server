# The Image component

AtomicServer can generate optimized versions of images in modern image formats **(WebP, AVIF)** on demand by adding query parameters to the download URL of an image.
More info [here](../files.md).

Serving the correct size and format of an image can greatly improve the performance of your website. This is especially important on mobile devices, where bandwidth is limited.
But it's not always the easiest thing to do. You need to generate multiple versions of the same image and serve the correct one based on the device's capabilities.

We added a component to `@tomic/svelte` that makes this easy: the `Image` component.

In its most basic form, it looks like this:

```html
<script lang="ts">
  import { Image } from "@tomic/svelte";
</script>

<Image
  subject="https://atomicdata.dev/files/1668879942069-funny-meme.jpg"
  alt="A funny looking cat"
/>
```

You give it the subject of a file resource that has an image MIME type and it will render a [picture](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/picture) element with sources for avif, webp and the original format.
It also creates a couple of sizes the browser can choose from, based on the device's screen size.

## Making sure the browser chooses the right image

By default, the browser looks at the entire viewport width and chooses the smallest version that still covers this width.
This is often too big so we should help by giving it an approximation of the size of the image relative to the viewport.
This is done via the `sizeIndication` prop.

When the unit given is a number it is interpreted as a percentage of the viewport width. If your image is displayed in a static size you can also pass a string like '4rem'.
Note that percentages don't work as the browser doesn't know the size of the parent element yet.

```html
 <Image
  subject='http://myatomicserver.com/files/1664878581079-hiker.jpg'
  alt='a person standing in front of a mountain'
  sizeIndication={50} // the image is about 50% of the viewport width
 />
 ```

```html
 <Image
  subject='http://myatomicserver.com/files/1664878581079-hiker.jpg'
  alt='a person standing in front of a mountain'
  sizeIndication='4rem'
 />
 ```

When the image's size changes based on media queries we can give the browser a more detailed indication.

```html
<Image
  className='inline-image'
  subject='http://myatomicserver.com/files/1664878581079-hiker.jpg'
  alt='a person standing in front of a mountain'
  sizeIndication={{
    '500px': 100, // On screens smaller than 500px the image is displayed at full width.
    default: 50, // the image is about 50% of the viewport when no media query matches
  }}
/>
```

## Specifying the encoding quality

You can specify the quality of the image by passing a number between 0 and 100 to the `quality` prop.
This is only used for the webp and avif formats.

```html
<Image
  subject='http://myatomicserver.com/files/1664878581079-hiker.jpg'
  alt='a person standing in front of a mountain'
  quality={40}
/>
```

## Styling the image

By default the Image component has a max-width of `100%` and a height of `auto`.
If you don't want this, pass the `noBaseStyles` prop.
To style the image you can target it you can wrap it in a parent element and then target the image from there.

```html
<script lang="ts">
  import { Image } from "@tomic/svelte";
</script>

<div class="image-wrapper">
  <Image
    subject="https://atomicdata.dev/files/1668879942069-funny-meme.jpg"
    alt="A funny looking cat"
  />
</div>

<style>
  .image-wrapper {
    display: contents;

    & img {
      // Your styles go here
    }
  }
</style>
```

You can also pass a `class` prop and then use `:global()` selector to target that class.


## HTML Attributes
All standard HTML img attributes are passed to the underlying img element.
This makes it possible to for example add an `id` or set `loading="lazy"`

## Accessibility

The `alt` prop is required on the image component.
Screen readers use these to describe the image to visually impaired users.
If you don't have a good description of the image, you can use an empty string.
Using an empty string is still better than no alt text at all.
