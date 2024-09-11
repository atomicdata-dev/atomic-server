import { core } from '@tomic/react';
import type { Template } from '../template';

const Image: React.FC = () => {
  return (
    <svg
      width='1803'
      height='1200'
      viewBox='0 0 1803 1200'
      fill='none'
      xmlns='http://www.w3.org/2000/svg'
    >
      <g clipPath='url(#clip0_930_4)'>
        <rect width='1803' height='1200' fill='var(--template-color-bg' />
        <rect width='1920' height='130' fill='var(--template-color-bg1)' />
        <rect
          x='116'
          y='37'
          width='258'
          height='55'
          rx='15'
          fill='var(--template-color-bg'
        />
        <rect
          x='1548'
          y='49'
          width='139'
          height='32'
          rx='15'
          fill='var(--template-color-bg'
        />
        <rect
          x='1363'
          y='49'
          width='139'
          height='32'
          rx='15'
          fill='var(--template-color-bg'
        />
        <rect
          x='1178'
          y='49'
          width='139'
          height='32'
          rx='15'
          fill='var(--template-color-bg'
        />
        <rect
          x='117'
          y='201'
          width='944'
          height='87'
          rx='15'
          fill='var(--template-color-bg2)'
        />
        <rect
          x='117'
          y='357'
          width='718'
          height='29'
          rx='15'
          fill='var(--template-color-bg1)'
        />
        <rect
          x='117'
          y='417'
          width='846'
          height='29'
          rx='15'
          fill='var(--template-color-bg1)'
        />
        <rect
          x='117'
          y='477'
          width='798'
          height='29'
          rx='15'
          fill='var(--template-color-bg1)'
        />
        <rect
          x='117'
          y='537'
          width='694'
          height='29'
          rx='15'
          fill='var(--template-color-bg1)'
        />
        <rect
          x='117'
          y='597'
          width='857'
          height='29'
          rx='15'
          fill='var(--template-color-bg1)'
        />
        <rect
          x='117'
          y='657'
          width='760'
          height='29'
          rx='15'
          fill='var(--template-color-bg1)'
        />
        <rect
          x='116'
          y='755'
          width='430'
          height='369'
          rx='15'
          fill='var(--template-color-bg1)'
        />
        <rect
          x='687'
          y='755'
          width='430'
          height='369'
          rx='15'
          fill='var(--template-color-bg1)'
        />
        <rect
          x='1258'
          y='755'
          width='430'
          height='369'
          rx='15'
          fill='var(--template-color-bg1)'
        />
      </g>
    </svg>
  );
};

export const website: Template = {
  title: 'website',
  id: 'website',
  description:
    context => `This template adds a website ontology to your AtomicServer along with some sample website data.
The website features blog posts, nested menu items and content blocks to create expressive pages from data.\n
An \`@tomic/template\` template is also available to setup a fully working website in a variety of front-end frameworks that you can then customize to your preferences.
\`\`\`
npm create @tomic/template my-project -- --template sveltekit-site --server-url ${context.serverUrl}
pnpm create @tomic/template my-project --template sveltekit-site --server-url ${context.serverUrl}
yarn create @tomic/template my-project --template sveltekit-site --server-url ${context.serverUrl}
\`\`\`
Currently available @tomic/templates for the website template are:
- sveltekit-site`,
  Image,
  rootResourceLocalIDs: ['01j6zqa7qgamwh5960dzy99j70'],
  resources: [
    {
      [core.properties.localId]: '01j6zqa7qgamwh5960dzy99j70',
      [core.properties.classes]: [
        '01j6zqa7qgamwh5960dzy99j70/class/blog-index-page',
        '01j6zqa7qgamwh5960dzy99j70/class/blogpost',
        '01j6zqa7qgamwh5960dzy99j70/class/image-gallery-block',
        '01j6zqa7qgamwh5960dzy99j70/class/menu-item',
        '01j6zqa7qgamwh5960dzy99j70/class/page',
        '01j6zqa7qgamwh5960dzy99j70/class/text-block',
        '01j6zqa7qgamwh5960dzy99j70/class/website',
      ],
      [core.properties.description]: 'Ontology for the template website.',
      [core.properties.instances]: [],
      [core.properties.isA]: [core.classes.ontology],
      [core.properties.properties]: [
        '01j6zqa7qgamwh5960dzy99j70/property/blocks',
        '01j6zqa7qgamwh5960dzy99j70/property/cover-image',
        '01j6zqa7qgamwh5960dzy99j70/property/homepage',
        '01j6zqa7qgamwh5960dzy99j70/property/path',
        '01j6zqa7qgamwh5960dzy99j70/property/images',
        '01j6zqa7qgamwh5960dzy99j70/property/links-to',
        '01j6zqa7qgamwh5960dzy99j70/property/menu-items',
        '01j6zqa7qgamwh5960dzy99j70/property/published-at',
        '01j6zqa7qgamwh5960dzy99j70/property/sub-items',
      ],
      [core.properties.shortname]: 'website',
    },
    {
      [core.properties.localId]:
        '01j6zqa7qgamwh5960dzy99j70/class/blog-index-page',
      [core.properties.description]: 'Page with a list of blogposts.',
      [core.properties.isA]: [core.classes.class],

      [core.properties.parent]: '01j6zqa7qgamwh5960dzy99j70',
      [core.properties.requires]: [
        core.properties.name,
        core.properties.description,
        '01j6zqa7qgamwh5960dzy99j70/property/path',
      ],
      [core.properties.shortname]: 'blog-index-page',
    },
    {
      [core.properties.localId]: '01j6zqa7qgamwh5960dzy99j70/class/blogpost',
      [core.properties.description]: 'A blogpost on a website',
      [core.properties.isA]: [core.classes.class],

      [core.properties.parent]: '01j6zqa7qgamwh5960dzy99j70',
      [core.properties.requires]: [
        core.properties.name,
        core.properties.description,
        '01j6zqa7qgamwh5960dzy99j70/property/path',
        '01j6zqa7qgamwh5960dzy99j70/property/cover-image',
        '01j6zqa7qgamwh5960dzy99j70/property/published-at',
      ],
      [core.properties.shortname]: 'blogpost',
    },
    {
      [core.properties.localId]:
        '01j6zqa7qgamwh5960dzy99j70/class/image-gallery-block',
      [core.properties.description]: 'A list of images',
      [core.properties.isA]: [core.classes.class],

      [core.properties.parent]: '01j6zqa7qgamwh5960dzy99j70',
      [core.properties.recommends]: [core.properties.name],
      [core.properties.requires]: [
        '01j6zqa7qgamwh5960dzy99j70/property/images',
      ],
      [core.properties.shortname]: 'image-gallery-block',
    },
    {
      [core.properties.localId]: '01j6zqa7qgamwh5960dzy99j70/class/menu-item',
      [core.properties.description]:
        'A link or dropdown menu in the navbar of the website.',
      [core.properties.isA]: [core.classes.class],

      [core.properties.parent]: '01j6zqa7qgamwh5960dzy99j70',
      [core.properties.recommends]: [
        '01j6zqa7qgamwh5960dzy99j70/property/sub-items',
        '01j6zqa7qgamwh5960dzy99j70/property/links-to',
      ],
      [core.properties.requires]: [core.properties.name],
      [core.properties.shortname]: 'menu-item',
    },
    {
      [core.properties.localId]: '01j6zqa7qgamwh5960dzy99j70/class/page',
      [core.properties.description]:
        'A page of a website.\\\n\\\nName and description are used for title and meta-tags.',
      [core.properties.isA]: [core.classes.class],

      [core.properties.parent]: '01j6zqa7qgamwh5960dzy99j70',
      [core.properties.recommends]: [
        '01j6zqa7qgamwh5960dzy99j70/property/blocks',
      ],
      [core.properties.requires]: [
        core.properties.name,
        core.properties.description,
        '01j6zqa7qgamwh5960dzy99j70/property/path',
      ],
      [core.properties.shortname]: 'page',
    },
    {
      [core.properties.localId]: '01j6zqa7qgamwh5960dzy99j70/class/text-block',
      [core.properties.description]: 'A block of text',
      [core.properties.isA]: [core.classes.class],

      [core.properties.parent]: '01j6zqa7qgamwh5960dzy99j70',
      [core.properties.requires]: [core.properties.description],
      [core.properties.shortname]: 'text-block',
    },
    {
      [core.properties.localId]: '01j6zqa7qgamwh5960dzy99j70/class/website',
      [core.properties.description]: 'Root data of the website.',
      [core.properties.isA]: [core.classes.class],

      [core.properties.parent]: '01j6zqa7qgamwh5960dzy99j70',
      [core.properties.recommends]: [
        '01j6zqa7qgamwh5960dzy99j70/property/menu-items',
      ],
      [core.properties.requires]: [
        '01j6zqa7qgamwh5960dzy99j70/property/homepage',
        core.properties.name,
      ],
      [core.properties.shortname]: 'website',
    },
    {
      [core.properties.localId]: '01j6zqa7qgamwh5960dzy99j70/property/blocks',
      [core.properties.datatype]:
        'https://atomicdata.dev/datatypes/resourceArray',
      [core.properties.description]: 'A list of blocks to display on the page',
      [core.properties.isA]: [core.classes.property],

      [core.properties.parent]: '01j6zqa7qgamwh5960dzy99j70',
      [core.properties.shortname]: 'blocks',
    },
    {
      [core.properties.localId]:
        '01j6zqa7qgamwh5960dzy99j70/property/cover-image',
      [core.properties.classtype]: 'https://atomicdata.dev/classes/File',
      [core.properties.datatype]: 'https://atomicdata.dev/datatypes/atomicURL',
      [core.properties.description]:
        'Image that is displayed at the top of the blogpost.',
      [core.properties.isA]: [core.classes.property],

      [core.properties.parent]: '01j6zqa7qgamwh5960dzy99j70',
      [core.properties.shortname]: 'cover-image',
    },
    {
      [core.properties.localId]: '01j6zqa7qgamwh5960dzy99j70/property/homepage',
      [core.properties.classtype]: '01j6zqa7qgamwh5960dzy99j70/class/page',
      [core.properties.datatype]: 'https://atomicdata.dev/datatypes/atomicURL',
      [core.properties.description]: 'Homepage of the website',
      [core.properties.isA]: [core.classes.property],

      [core.properties.parent]: '01j6zqa7qgamwh5960dzy99j70',
      [core.properties.shortname]: 'homepage',
    },
    {
      [core.properties.localId]: '01j6zqa7qgamwh5960dzy99j70/property/path',
      [core.properties.datatype]: 'https://atomicdata.dev/datatypes/string',
      [core.properties.description]:
        'The path a page should live on. Should be relative to the root of the website.',
      [core.properties.isA]: [core.classes.property],

      [core.properties.parent]: '01j6zqa7qgamwh5960dzy99j70',
      [core.properties.shortname]: 'href',
    },
    {
      [core.properties.localId]: '01j6zqa7qgamwh5960dzy99j70/property/images',
      [core.properties.classtype]: 'https://atomicdata.dev/classes/File',
      [core.properties.datatype]:
        'https://atomicdata.dev/datatypes/resourceArray',
      [core.properties.description]: 'A list of images to display',
      [core.properties.isA]: [core.classes.property],

      [core.properties.parent]: '01j6zqa7qgamwh5960dzy99j70',
      [core.properties.shortname]: 'images',
    },
    {
      [core.properties.localId]: '01j6zqa7qgamwh5960dzy99j70/property/links-to',
      [core.properties.datatype]: 'https://atomicdata.dev/datatypes/atomicURL',
      [core.properties.description]:
        'Determines to what resource the menu item links.',
      [core.properties.isA]: [core.classes.property],

      [core.properties.parent]: '01j6zqa7qgamwh5960dzy99j70',
      [core.properties.shortname]: 'links-to',
    },
    {
      [core.properties.localId]:
        '01j6zqa7qgamwh5960dzy99j70/property/menu-items',
      [core.properties.classtype]: '01j6zqa7qgamwh5960dzy99j70/class/menu-item',
      [core.properties.datatype]:
        'https://atomicdata.dev/datatypes/resourceArray',
      [core.properties.description]: 'A lists of menu items',
      [core.properties.isA]: [core.classes.property],

      [core.properties.parent]: '01j6zqa7qgamwh5960dzy99j70',
      [core.properties.shortname]: 'menu-items',
    },
    {
      [core.properties.localId]:
        '01j6zqa7qgamwh5960dzy99j70/property/published-at',
      [core.properties.datatype]: 'https://atomicdata.dev/datatypes/timestamp',
      [core.properties.description]:
        'The date and time something was published',
      [core.properties.isA]: [core.classes.property],

      [core.properties.parent]: '01j6zqa7qgamwh5960dzy99j70',
      [core.properties.shortname]: 'published-at',
    },
    {
      [core.properties.localId]:
        '01j6zqa7qgamwh5960dzy99j70/property/sub-items',
      [core.properties.classtype]: '01j6zqa7qgamwh5960dzy99j70/class/menu-item',
      [core.properties.datatype]:
        'https://atomicdata.dev/datatypes/resourceArray',
      [core.properties.description]:
        'A list of menu items that are nested under this menu item.',
      [core.properties.isA]: [core.classes.property],

      [core.properties.parent]: '01j6zqa7qgamwh5960dzy99j70',
      [core.properties.shortname]: 'sub-items',
    },
  ],
};
