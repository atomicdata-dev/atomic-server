import { core, dataBrowser } from '@tomic/react';
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
  rootResourceLocalIDs: ['website', '01j5zr8e919ph7g5xgyehv0g17'],
  resources: [
    // =============== TEMPLATE ONTOLOGY ===============
    {
      [core.properties.localId]: 'website',
      [core.properties.classes]: [
        'website/class/blog-index-page',
        'website/class/blogpost',
        'website/class/image-gallery-block',
        'website/class/menu-item',
        'website/class/page',
        'website/class/text-block',
        'website/class/website',
      ],
      [core.properties.description]: 'Ontology for the template website.',
      [core.properties.instances]: [],
      [core.properties.isA]: [core.classes.ontology],
      [core.properties.properties]: [
        'website/property/blocks',
        'website/property/cover-image',
        'website/property/external-link',
        'website/property/homepage',
        'website/property/path',
        'website/property/images',
        'website/property/links-to',
        'website/property/menu-items',
        'website/property/published-at',
        'website/property/sub-items',
      ],
      [core.properties.shortname]: 'website',
    },
    {
      [core.properties.localId]: 'website/class/blog-index-page',
      [core.properties.description]: 'Page with a list of blogposts.',
      [core.properties.isA]: [core.classes.class],

      [core.properties.parent]: 'website',
      [core.properties.requires]: [
        core.properties.name,
        core.properties.description,
        'website/property/path',
      ],
      [core.properties.shortname]: 'blog-index-page',
    },
    {
      [core.properties.localId]: 'website/class/blogpost',
      [core.properties.description]: 'A blogpost on a website',
      [core.properties.isA]: [core.classes.class],

      [core.properties.parent]: 'website',
      [core.properties.requires]: [
        core.properties.name,
        core.properties.description,
        'website/property/path',
        'website/property/cover-image',
        'website/property/published-at',
      ],
      [core.properties.shortname]: 'blogpost',
    },
    {
      [core.properties.localId]: 'website/class/image-gallery-block',
      [core.properties.description]: 'A list of images',
      [core.properties.isA]: [core.classes.class],

      [core.properties.parent]: 'website',
      [core.properties.recommends]: [core.properties.name],
      [core.properties.requires]: ['website/property/images'],
      [core.properties.shortname]: 'image-gallery-block',
    },
    {
      [core.properties.localId]: 'website/class/menu-item',
      [core.properties.description]:
        'A link or dropdown menu in the navbar of the website.',
      [core.properties.isA]: [core.classes.class],

      [core.properties.parent]: 'website',
      [core.properties.recommends]: [
        'website/property/sub-items',
        'website/property/links-to',
        'website/property/external-link',
      ],
      [core.properties.requires]: [core.properties.name],
      [core.properties.shortname]: 'menu-item',
    },
    {
      [core.properties.localId]: 'website/class/page',
      [core.properties.description]:
        'A page of a website.\\\n\\\nName and description are used for title and meta-tags.',
      [core.properties.isA]: [core.classes.class],

      [core.properties.parent]: 'website',
      [core.properties.recommends]: ['website/property/blocks'],
      [core.properties.requires]: [
        core.properties.name,
        core.properties.description,
        'website/property/path',
      ],
      [core.properties.shortname]: 'page',
    },
    {
      [core.properties.localId]: 'website/class/text-block',
      [core.properties.description]: 'A block of text',
      [core.properties.isA]: [core.classes.class],

      [core.properties.parent]: 'website',
      [core.properties.requires]: [core.properties.description],
      [core.properties.shortname]: 'text-block',
    },
    {
      [core.properties.localId]: 'website/class/website',
      [core.properties.description]: 'Root data of the website.',
      [core.properties.isA]: [core.classes.class],

      [core.properties.parent]: 'website',
      [core.properties.recommends]: ['website/property/menu-items'],
      [core.properties.requires]: [
        'website/property/homepage',
        core.properties.name,
      ],
      [core.properties.shortname]: 'website',
    },
    {
      [core.properties.localId]: 'website/property/blocks',
      [core.properties.datatype]:
        'https://atomicdata.dev/datatypes/resourceArray',
      [core.properties.description]: 'A list of blocks to display on the page',
      [core.properties.isA]: [core.classes.property],

      [core.properties.parent]: 'website',
      [core.properties.shortname]: 'blocks',
    },
    {
      [core.properties.localId]: 'website/property/cover-image',
      [core.properties.classtype]: 'https://atomicdata.dev/classes/File',
      [core.properties.datatype]: 'https://atomicdata.dev/datatypes/atomicURL',
      [core.properties.description]:
        'Image that is displayed at the top of the blogpost.',
      [core.properties.isA]: [core.classes.property],

      [core.properties.parent]: 'website',
      [core.properties.shortname]: 'cover-image',
    },
    {
      [core.properties.localId]: 'website/property/external-link',
      [core.properties.datatype]: 'https://atomicdata.dev/datatypes/string',
      [core.properties.description]: 'Link to an external website',
      [core.properties.isA]: [core.classes.property],

      [core.properties.parent]: 'website',
      [core.properties.shortname]: 'external-link',
    },
    {
      [core.properties.localId]: 'website/property/homepage',
      [core.properties.classtype]: 'website/class/page',
      [core.properties.datatype]: 'https://atomicdata.dev/datatypes/atomicURL',
      [core.properties.description]: 'Homepage of the website',
      [core.properties.isA]: [core.classes.property],

      [core.properties.parent]: 'website',
      [core.properties.shortname]: 'homepage',
    },
    {
      [core.properties.localId]: 'website/property/path',
      [core.properties.datatype]: 'https://atomicdata.dev/datatypes/string',
      [core.properties.description]:
        'The path a page should live on. Should be relative to the root of the website.',
      [core.properties.isA]: [core.classes.property],

      [core.properties.parent]: 'website',
      [core.properties.shortname]: 'href',
    },
    {
      [core.properties.localId]: 'website/property/images',
      [core.properties.classtype]: 'https://atomicdata.dev/classes/File',
      [core.properties.datatype]:
        'https://atomicdata.dev/datatypes/resourceArray',
      [core.properties.description]: 'A list of images to display',
      [core.properties.isA]: [core.classes.property],

      [core.properties.parent]: 'website',
      [core.properties.shortname]: 'images',
    },
    {
      [core.properties.localId]: 'website/property/links-to',
      [core.properties.datatype]: 'https://atomicdata.dev/datatypes/atomicURL',
      [core.properties.description]:
        'Determines to what resource the menu item links.',
      [core.properties.isA]: [core.classes.property],

      [core.properties.parent]: 'website',
      [core.properties.shortname]: 'links-to',
    },
    {
      [core.properties.localId]: 'website/property/menu-items',
      [core.properties.classtype]: 'website/class/menu-item',
      [core.properties.datatype]:
        'https://atomicdata.dev/datatypes/resourceArray',
      [core.properties.description]: 'A lists of menu items',
      [core.properties.isA]: [core.classes.property],

      [core.properties.parent]: 'website',
      [core.properties.shortname]: 'menu-items',
    },
    {
      [core.properties.localId]: 'website/property/published-at',
      [core.properties.datatype]: 'https://atomicdata.dev/datatypes/timestamp',
      [core.properties.description]:
        'The date and time something was published',
      [core.properties.isA]: [core.classes.property],

      [core.properties.parent]: 'website',
      [core.properties.shortname]: 'published-at',
    },
    {
      [core.properties.localId]: 'website/property/sub-items',
      [core.properties.classtype]: 'website/class/menu-item',
      [core.properties.datatype]:
        'https://atomicdata.dev/datatypes/resourceArray',
      [core.properties.description]:
        'A list of menu items that are nested under this menu item.',
      [core.properties.isA]: [core.classes.property],

      [core.properties.parent]: 'website',
      [core.properties.shortname]: 'sub-items',
    },
    // =============== TEMPLATE SITE ===============
    {
      [core.properties.localId]: '01j5zr8e919ph7g5xgyehv0g17',
      [core.properties.isA]: [dataBrowser.classes.folder],
      [core.properties.name]: 'Site Data',
      [dataBrowser.properties.subResources]: [
        '01j5zrd23mxam4mdg2ak97gqcm',
        '01j5zrevq917dp0wm4p2vnd7nr',
        '01j67112t57y1nefp8gerjz4ba',
        '01j67hpt3x1jpwq3pnhh57kcph',
        '01j67hnx3j12j9skvhhjw44v7v',
        '01j6cbg9djf269zdwwv5114jsd',
        '01j6cjpvhc8sgmqeg6v84fgxtv',
      ],
      [dataBrowser.properties.displayStyle]:
        'https://atomicdata.dev/display-style/list',
    },
    {
      [core.properties.localId]: '01j5zrevq917dp0wm4p2vnd7nr',
      'website/property/homepage': '01j5zrd23mxam4mdg2ak97gqcm',
      'website/property/menu-items': [
        '01j670xy9me8yk6fte8wrqwxfd',
        '01j5zrecgbejcbpvtkj1g8f2cn',
        '01j6cbh8bgpvvn0e8hk87bvgnr',
        '01j67bedjzrpp6mva2a6576fh6',
      ],
      [core.properties.isA]: ['website/class/website'],
      [core.properties.name]: 'Atomic Website Template',
      [core.properties.parent]: '01j5zr8e919ph7g5xgyehv0g17',
      [dataBrowser.properties.subResources]: [
        '01j670xy9me8yk6fte8wrqwxfd',
        '01j5zrecgbejcbpvtkj1g8f2cn',
        '01j6cbh8bgpvvn0e8hk87bvgnr',
        '01j67bedjzrpp6mva2a6576fh6',
      ],
    },
    {
      [core.properties.localId]: '01j670xy9me8yk6fte8wrqwxfd',
      'website/property/links-to': '01j5zrd23mxam4mdg2ak97gqcm',
      [core.properties.isA]: ['website/class/menu-item'],
      [core.properties.name]: 'Home',
      [core.properties.parent]: '01j5zrevq917dp0wm4p2vnd7nr',
    },
    {
      [core.properties.localId]: '01j5zrecgbejcbpvtkj1g8f2cn',
      'website/property/links-to': '01j67112t57y1nefp8gerjz4ba',
      [core.properties.isA]: ['website/class/menu-item'],
      [core.properties.name]: 'About',
      [core.properties.parent]: '01j5zrevq917dp0wm4p2vnd7nr',
    },
    {
      [core.properties.localId]: '01j6cbh8bgpvvn0e8hk87bvgnr',
      'website/property/links-to': '01j6cjpvhc8sgmqeg6v84fgxtv',
      [core.properties.isA]: ['website/class/menu-item'],
      [core.properties.name]: 'Blog',
      [core.properties.parent]: '01j5zrevq917dp0wm4p2vnd7nr',
    },
    {
      [core.properties.localId]: '01j67bedjzrpp6mva2a6576fh6',
      'website/property/sub-items': [
        '01j67bmrfhxf1m9wqy2eajzcps',
        '01j67bnfz2wwt67gr7jxep4rn8',
      ],
      [core.properties.isA]: ['website/class/menu-item'],
      [core.properties.name]: 'Projects',
      [core.properties.parent]: '01j5zrevq917dp0wm4p2vnd7nr',
      [dataBrowser.properties.subResources]: [
        '01j67bmrfhxf1m9wqy2eajzcps',
        '01j67bnfz2wwt67gr7jxep4rn8',
      ],
    },
    {
      [core.properties.localId]: '01j67bmrfhxf1m9wqy2eajzcps',
      'website/property/links-to': '01j67hnx3j12j9skvhhjw44v7v',
      [core.properties.isA]: ['website/class/menu-item'],
      [core.properties.name]: 'This website',
      [core.properties.parent]: '01j67bedjzrpp6mva2a6576fh6',
    },
    {
      [core.properties.localId]: '01j67bnfz2wwt67gr7jxep4rn8',
      'website/property/links-to': '01j67hpt3x1jpwq3pnhh57kcph',
      [core.properties.isA]: ['website/class/menu-item'],
      [core.properties.name]: 'Making Cheese',
      [core.properties.parent]: '01j67bedjzrpp6mva2a6576fh6',
    },
    {
      [core.properties.localId]: '01j5zrd23mxam4mdg2ak97gqcm',
      'website/property/blocks': [
        '01j69w16079grvs7x9x0bk5kjb',
        '01j69weee5kvxedekcsm9z8hgd',
      ],
      'website/property/path': '/',
      [core.properties.description]: 'A Sveltekit site made with Atomic Data',
      [core.properties.isA]: ['website/class/page'],
      [core.properties.name]: 'Atomic Website Template',
      [core.properties.parent]: '01j5zr8e919ph7g5xgyehv0g17',
      [dataBrowser.properties.subResources]: [
        '01j69w16079grvs7x9x0bk5kjb',
        '01j69weee5kvxedekcsm9z8hgd',
      ],
    },
    {
      [core.properties.localId]: '01j69w16079grvs7x9x0bk5kjb',
      [core.properties.description]:
        'This is a template site generated with @tomic/template.\n\nThis content can be changed in the AtomicServer UI.\n\nLorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum',
      [core.properties.isA]: ['website/class/text-block'],
      [core.properties.parent]: '01j5zrd23mxam4mdg2ak97gqcm',
    },
    {
      [core.properties.localId]: '01j69weee5kvxedekcsm9z8hgd',
      'website/property/images': [
        'https://atomicdata.dev/files/1726131947878-matt-flores-auOYGNcPSw8-unsplash.jpg',
        'https://atomicdata.dev/files/1726131961564-carson-arias-7Z03R1wOdmI-unsplash.jpg',
        'https://atomicdata.dev/files/1726131980022-nick-baker-VuPIUePS_vU-unsplash.jpg',
        'https://atomicdata.dev/files/1726131992774-crawford-jolly--gFxMygtgsg-unsplash.jpg',
        'https://atomicdata.dev/files/1726131984886-philipp-hofmann-q8FpoS21UQE-unsplash.jpg',
        'https://atomicdata.dev/files/1726131998153-mike-dorner-sf_1ZDA1YFw-unsplash.jpg',
      ],
      [core.properties.isA]: ['website/class/image-gallery-block'],
      [core.properties.name]: 'Some pictures',
      [core.properties.parent]: '01j5zrd23mxam4mdg2ak97gqcm',
    },
    {
      [core.properties.localId]: '01j67112t57y1nefp8gerjz4ba',
      'website/property/blocks': ['01j6c7hs5z48pgdxrms4a3n91h'],
      'website/property/path': '/about',
      [core.properties.description]: 'About this template site',
      [core.properties.isA]: ['website/class/page'],
      [core.properties.name]: 'About',
      [core.properties.parent]: '01j5zr8e919ph7g5xgyehv0g17',
      [dataBrowser.properties.subResources]: ['01j6c7hs5z48pgdxrms4a3n91h'],
    },
    {
      [core.properties.localId]: '01j6c7hs5z48pgdxrms4a3n91h',
      [core.properties.description]:
        'Hi I’m —— and I love ——!\n\nLorem ipsum dolor sit amet, consectetur adipiscing elit. Pellentesque ut pellentesque tortor. Sed a lobortis tellus. Phasellus at consequat metus, nec luctus eros. Aliquam erat volutpat. Pellentesque malesuada felis ut augue pulvinar venenatis. Vestibulum condimentum ut leo et pellentesque. Nam lobortis bibendum malesuada. Nam eu augue neque. Nam est quam, ultricies ac accumsan quis, gravida at quam. Aliquam mollis fermentum odio quis ultrices. Vestibulum sagittis, metus vel fringilla ultrices, nibh tellus pellentesque sapien, mollis hendrerit nunc orci id felis. Nullam accumsan eros a ante ultrices fringilla. Mauris ut faucibus felis.\n\nProin at condimentum velit, id sollicitudin nibh. Sed dapibus vehicula congue. Vestibulum risus velit, rutrum non mattis in, placerat auctor libero. Fusce nec augue condimentum, posuere justo eget, ornare ex. Fusce euismod ultrices rhoncus. Aenean congue est et dui vestibulum, sed gravida dui iaculis. Aenean imperdiet molestie arcu vel fringilla. Quisque sit amet elementum lorem. Vestibulum id fringilla mauris. Ut congue et nunc a rhoncus. Nullam a auctor erat. Cras id nibh pharetra, suscipit arcu sagittis, rutrum urna. Maecenas sed arcu justo. Vivamus eu lorem ac enim tincidunt volutpat quis eget nisl. Vivamus posuere est ac elit efficitur, ut viverra leo pretium. Suspendisse eleifend tortor sit amet turpis laoreet vulputate.\n\nQuisque lobortis dolor quis vulputate tristique. Nullam dignissim nec nulla non mattis. Pellentesque bibendum, ipsum vel volutpat faucibus, nisi enim condimentum magna, vitae lobortis libero diam ac turpis. Nam luctus a erat non blandit. Quisque ultrices dictum tortor, sed ultrices turpis gravida id. Mauris sed lacus ultricies tellus pulvinar convallis. Vivamus purus felis, sagittis nec pharetra in, pharetra a metus. Suspendisse congue lacus massa, auctor hendrerit augue dictum vel. Cras varius sollicitudin rhoncus. Integer convallis dui nec elit pellentesque, in commodo quam rutrum. Proin vitae mauris tortor.',
      [core.properties.isA]: ['website/class/text-block'],
      [core.properties.parent]: '01j67112t57y1nefp8gerjz4ba',
    },
    {
      [core.properties.localId]: '01j67hpt3x1jpwq3pnhh57kcph',
      'website/property/blocks': ['01j7jyh9e626k4gb1w0c7mkjp1'],
      'website/property/path': '/making-cheese',
      [core.properties.description]: 'I made my own cheese!',
      [core.properties.isA]: ['website/class/page'],
      [core.properties.name]: 'Making Cheese',
      [core.properties.parent]: '01j5zr8e919ph7g5xgyehv0g17',
      [dataBrowser.properties.subResources]: ['01j7jyh9e626k4gb1w0c7mkjp1'],
    },
    {
      [core.properties.localId]: '01j7jyh9e626k4gb1w0c7mkjp1',
      [core.properties.description]:
        'Recently I started making my own cheese! It’s really cool.\n\nLorem ipsum dolor sit amet, consectetur adipiscing elit. Pellentesque ut pellentesque tortor. Sed a lobortis tellus. Phasellus at consequat metus, nec luctus eros. Aliquam erat volutpat. Pellentesque malesuada felis ut augue pulvinar venenatis. Vestibulum condimentum ut leo et pellentesque. Nam lobortis bibendum malesuada. Nam eu augue neque. Nam est quam, ultricies ac accumsan quis, gravida at quam. Aliquam mollis fermentum odio quis ultrices. Vestibulum sagittis, metus vel fringilla ultrices, nibh tellus pellentesque sapien, mollis hendrerit nunc orci id felis. Nullam accumsan eros a ante ultrices fringilla. Mauris ut faucibus felis.\n\n![](https://atomicdata.dev/download/files/1726139217600-katrin-leinfellner-v9deD75EaRw-unsplash.jpg)Proin at condimentum velit, id sollicitudin nibh. Sed dapibus vehicula congue. Vestibulum risus velit, rutrum non mattis in, placerat auctor libero. Fusce nec augue condimentum, posuere justo eget, ornare ex. Fusce euismod ultrices rhoncus. Aenean congue est et dui vestibulum, sed gravida dui iaculis. Aenean imperdiet molestie arcu vel fringilla. Quisque sit amet elementum lorem. Vestibulum id fringilla mauris. Ut congue et nunc a rhoncus. Nullam a auctor erat. Cras id nibh pharetra, suscipit arcu sagittis, rutrum urna. Maecenas sed arcu justo. Vivamus eu lorem ac enim tincidunt volutpat quis eget nisl. Vivamus posuere est ac elit efficitur, ut viverra leo pretium. Suspendisse eleifend tortor sit amet turpis laoreet vulputate.\n\nQuisque lobortis dolor quis vulputate tristique. Nullam dignissim nec nulla non mattis. Pellentesque bibendum, ipsum vel volutpat faucibus, nisi enim condimentum magna, vitae lobortis libero diam ac turpis. Nam luctus a erat non blandit. Quisque ultrices dictum tortor, sed ultrices turpis gravida id. Mauris sed lacus ultricies tellus pulvinar convallis. Vivamus purus felis, sagittis nec pharetra in, pharetra a metus. Suspendisse congue lacus massa, auctor hendrerit augue dictum vel. Cras varius sollicitudin rhoncus. Integer convallis dui nec elit pellentesque, in commodo quam rutrum. Proin vitae mauris tortor.',
      [core.properties.isA]: ['website/class/text-block'],
      [core.properties.parent]: '01j67hpt3x1jpwq3pnhh57kcph',
    },
    {
      [core.properties.localId]: '01j67hnx3j12j9skvhhjw44v7v',
      'website/property/blocks': ['01j7jzsj3ec6twny6wp1g3gcx3'],
      'website/property/path': '/this-website',
      [core.properties.description]:
        'I created this website to try out AtomicServer',
      [core.properties.isA]: ['website/class/page'],
      [core.properties.name]: 'This website',
      [core.properties.parent]: '01j5zr8e919ph7g5xgyehv0g17',
      [dataBrowser.properties.subResources]: ['01j7jzsj3ec6twny6wp1g3gcx3'],
    },
    {
      [core.properties.localId]: '01j7jzsj3ec6twny6wp1g3gcx3',
      [core.properties.description]:
        'A project I’ve been working recently is creating this website.\n\nIt was very easy! The only thing I had to do was apply the Website template to my AtomicServer drive, run an npm command to generate some code and then edit the site to make it my own.',
      [core.properties.isA]: ['website/class/text-block'],
      [core.properties.parent]: '01j67hnx3j12j9skvhhjw44v7v',
    },
    {
      [core.properties.localId]: '01j6cbg9djf269zdwwv5114jsd',
      [core.properties.isA]: [dataBrowser.classes.folder],
      [core.properties.name]: 'Blog posts',
      [core.properties.parent]: '01j5zr8e919ph7g5xgyehv0g17',
      [dataBrowser.properties.subResources]: [
        '01j6cbmtr2nq8fhhjkq764rcf3',
        '01j6cc8pn7rpg4pymv6v0bvx2c',
        '01j6ccm53p4bv9f92m4tpehcba',
        '01j6ewtynjsyq7b3sc1pgqppde',
      ],
      'https://atomicdata.dev/property/display-style':
        'https://atomicdata.dev/display-style/list',
    },
    {
      [core.properties.localId]: '01j6cbmtr2nq8fhhjkq764rcf3',
      'website/property/cover-image':
        'https://atomicdata.dev/files/1726129537342-pexels-photo-4498553.webp',
      'website/property/path':
        '/blog/how-to-tie-your-shoe-laces-correctly-everytime',
      'website/property/published-at': 1724248980000,
      [core.properties.description]:
        'Tying your shoes might seem simple, but many people struggle with laces that come undone throughout the day. Whether you’re a runner or just want to keep your sneakers snug, here’s a foolproof way to tie your shoe laces correctly every time!\n\n#### 1. **Start with a Solid Foundation**\n\nBegin by crossing one lace over the other and pulling it tight, forming a secure "X." This is the base of your knot and helps keep your shoes firmly on your feet.\n\n#### 2. **Create the Bunny Ears**\n\nNow, make a loop (or "bunny ear") with each lace. Pinch the loops between your thumb and index finger. The loops should look like bunny ears!\n\n#### 3. **Cross and Tuck**\n\nTake one loop and cross it over the other. Then, tuck it underneath, just like you did with the initial "X." Pull both loops tight. This is your basic knot, but with loops that will hold their shape.\n\n#### 4. **The Secret to Staying Power**\n\nHere’s the trick most people miss: **double knot it.** To do this, simply tie the loops together one more time. This adds extra friction and ensures the knot stays intact all day.\n\n#### 5. **Adjust for Comfort**\n\nFinally, pull the loops until the laces feel snug but not too tight. Make sure the knot sits flat and comfortably against your foot to avoid discomfort.\n\nWith this method, you\'ll tie your shoes right every time, keeping them secure for longer, whether you\'re walking, running, or just going about your day. Happy tying!',
      [core.properties.isA]: ['website/class/blogpost'],
      [core.properties.name]:
        'How to tie your shoe laces correctly every time!',
      [core.properties.parent]: '01j6cbg9djf269zdwwv5114jsd',
    },
    {
      [core.properties.localId]: '01j6cc8pn7rpg4pymv6v0bvx2c',
      'website/property/cover-image':
        'https://atomicdata.dev/files/1726129561923-pexels-olly-3760809.jpg',
      'website/property/path': '/blog/10-weird-but-genious-lifehacks',
      'website/property/published-at': 1722787560000,
      [core.properties.description]:
        "You know those life hacks that sound so clever, you’re convinced they’ll change your life forever—but then you realize you’ll probably never use them? Well, here’s a list of some truly weird but *genius* life hacks that are so brilliant, you’ll still find reasons to never actually try them.\n\n#### 1. **Turn Your Hoodie Backwards for a Built-In Snack Pouch**\n\nWhy balance that bowl of popcorn on your lap when you can wear your hoodie backwards, and voilà—a snack pouch! The hoodie’s hood can hold popcorn, chips, or candy while you binge Netflix. Is it genius? Absolutely. Will you ever do it? Probably only if you're *really* committed to laziness.\n\n#### 2. **Use a Fork to Hold Your Taco Together**\n\nTacos falling apart faster than your New Year's resolutions? Stick a fork through the open end to keep all the delicious ingredients intact. The fork tines also act as handy little prongs to hold the taco in place while you eat. Practical? Yes. But let’s be real, you’re just going to grab a pile of napkins and hope for the best.\n\n#### 3. **Bread Clips as Flip-Flop Fixers**\n\nYou know those annoying little plastic clips that keep bread bags closed? Next time the strap pops out of your flip-flop, pop one of these bad boys on the bottom to hold it in place. Your flip-flop is fixed! This hack is genius, but the likelihood of having a bread clip when your flip-flop breaks is about the same as winning the lottery.\n\n#### 4. **Aluminum Foil to Sharpen Scissors**\n\nBlunt scissors? No problem! Fold some aluminum foil a few times and cut through it with your scissors. It's like a mini workout for the blades. A few snips and your scissors will be sharper than your wit. But let’s face it, the only time you’ll remember this is when you’re halfway through wrapping a gift with a pair of very sad, very dull scissors.\n\n#### 5. **Rubber Bands Around a Paint Can to Wipe Excess Paint Off**\n\nWhy get paint all over the rim of the can? Stretch a rubber band across the opening of the can, and wipe your brush on it to remove excess paint. It keeps things clean and prevents that dreaded crusty paint layer from forming. Yet, somehow, we all just end up with crusty paint cans.\n\n#### 6. **Store Your Headphones in an Old Mint Container**\n\nThat tangled mess of headphones at the bottom of your bag? Avoid it entirely by using an old mint tin as a little headphone holder. It keeps them untangled and fresh-smelling! But honestly, wireless earbuds are calling your name, and this will remain an unused, albeit genius, hack.\n\n#### 7. **Use an Empty Toilet Paper Roll to Amplify Your Phone's Sound**\n\nNo Bluetooth speaker? No problem! Take an empty toilet paper roll, cut a slot big enough for your phone, and pop it in. The sound will echo through the roll and give you an instant volume boost. Will you try it? Maybe, but likely only once just to see if it works. Then you’ll put it aside and forget about it forever.\n\n#### 8. **Freeze Grapes to Chill Wine Without Watering It Down**\n\nYou’re having a nice glass of white wine and it’s just not cold enough. Instead of adding ice cubes (ugh, watered-down wine!), freeze grapes and toss them in. They’ll chill your drink without diluting it. Genius? Absolutely. Will you remember to pre-freeze the grapes? Probably not—good luck with that warm Chardonnay.\n\n#### 9. **Use a Dustpan to Fill a Bucket That Doesn’t Fit in the Sink**\n\nGot a bucket that’s too big to fit under the faucet? Grab a dustpan, hold it under the stream, and let the water slide down the handle and into the bucket. Instant problem-solver! The only catch? You’ll definitely forget this trick the next time you’re awkwardly splashing water everywhere.\n\n#### 10. **Use a Staple Remover to Save Your Fingernails When Adding Keys to a Keyring**\n\nAdding a new key to your keyring is a nail-destroying nightmare. Enter: the humble staple remover. Just use it to pry the ring open and slide the key right on, no broken nails required. Will you remember this hack when you need it? Unlikely—you’ll probably still be wrestling with that keyring like it’s your nemesis.\n\n---\n\n### Conclusion: Hacks You Won't Try (But Really Should)\n\nThere you have it: 10 life hacks that are weirdly genius but, let’s be honest, probably won’t make it into your daily routine. The ideas are brilliant, but the execution? Well, that’s another story. However, if you do attempt any of these, you’ll feel like a life-hack legend. And hey, that counts for something!\n\nSo, next time you’re snacking out of a backward hoodie or fixing flip-flops with a bread clip, just remember: you’re living your best (weird) life.",
      [core.properties.isA]: ['website/class/blogpost'],
      [core.properties.name]:
        '10 Weird But Genius Life Hacks You Probably Won’t Use',
      [core.properties.parent]: '01j6cbg9djf269zdwwv5114jsd',
    },
    {
      [core.properties.localId]: '01j6ccm53p4bv9f92m4tpehcba',
      'website/property/cover-image':
        'https://atomicdata.dev/files/1726129572468-pexels-adam-lukac-254247-773958.jpg',
      'website/property/path': '/blog/can-you-really-survive-on-coffee-alone',
      'website/property/published-at': 1724853840000,
      [core.properties.description]:
        'Let’s face it: coffee is more than just a beverage—it’s a lifestyle. It fuels our mornings, powers our afternoons, and sometimes becomes a late-night lifeline. But what if coffee was the *only* thing keeping you going? Could you survive an entire week on nothing but liquid caffeine? Well, I decided to find out, so here’s my highly caffeinated journey through a week where coffee was my only sustenance. Spoiler: things got weird.\n\n#### Day 1: Optimistic Beginnings\n\n**8:00 AM**: I’m feeling great. My morning coffee tastes like motivation in a cup, and I’m fully convinced I’ll breeze through this week. Coffee is practically a food group, right? It’s made from beans, which technically makes it a salad. I’m starting my day with a large mug of French press, imagining myself as some sort of coffee-fueled superhero.\n\n**12:00 PM**: Time for lunch… of coffee. I opt for a cold brew to mix things up, and surprisingly, I feel fine. My productivity levels are soaring, and I’m firing off emails at the speed of light. Who needs food when you have caffeine?\n\n**6:00 PM**: Dinner rolls around, and I’m starting to get hungry. I decide to jazz things up with a fancy cappuccino. Frothy milk counts as food, right? So far, so good. I head to bed with a slight headache but still confident.\n\n#### Day 2: Caffeine Highs and Lows\n\n**8:00 AM**: Woke up with a slight jitter. I blame it on excitement for another day of coffee-only living (and not the three cups I had before bed). I pour myself a large Americano and push through. My body may be craving nutrients, but my mind? Still riding that caffeine wave.\n\n**1:00 PM**: I’m starting to lose focus. My cold brew lunch is just not hitting the spot today. Is it possible to feel both wired and exhausted at the same time? The answer is yes. \n\n**4:00 PM**: I decide to take a nap, but my heart is racing too fast to sleep. Is this what being a hummingbird feels like? I can’t remember what food tastes like, but I think I’m fine.\n\n#### Day 3: Questioning My Life Choices\n\n**9:00 AM**: I missed my morning alarm because I stayed up until 3 AM Googling "how much coffee is too much coffee." Turns out, no one really knows. I pour a double espresso to catch up on lost energy. It’s not working.\n\n**12:00 PM**: My co-workers keep asking why I’m shaking, and I tell them I’m fine. I am not fine. \n\n**5:00 PM**: I swear I just saw my chair move on its own. I decide to switch to decaf for dinner. Decaf is basically salad dressing on my coffee-salad, right? Definitely still counts.\n\n#### Day 4: Caffeine Delirium\n\n**8:00 AM**: At this point, I’m pretty sure my body has transcended hunger. Who needs solid food when you can run on pure espresso? I’ve stopped feeling full (or hungry), and I’ve reached a zen state of caffeinated consciousness. I like to call it "Java Nirvana."\n\n**11:00 AM**: My hands won’t stop trembling, so I just hold my coffee mug constantly now. People assume I’m drinking and not vibrating into a higher dimension. \n\n**3:00 PM**: I attempt to meditate but can’t sit still for more than 10 seconds. It feels like ants are dancing inside my skin. Note to self: drinking coffee during a yoga session was a *bad* idea.\n\n#### Day 5: Coffee-fueled Creativity (or Insanity?)\n\n**7:00 AM**: My morning coffee is starting to taste… boring. In a desperate attempt to switch things up, I add some cocoa powder to my cold brew and call it a mocha smoothie. I’m basically a barista now. I feel slightly less shaky, though I may be hallucinating from the sheer amount of caffeine in my bloodstream.\n\n**1:00 PM**: I think I’ve become one with my coffee mug. It’s not just a vessel for my drink anymore—it’s an extension of my being. I try to write a blog post, but my fingers are typing faster than my brain can keep up. I end up with a garbled mess of letters and decide it’s a poetic expression of my current mental state.\n\n**7:00 PM**: I forgot to have dinner. But then again, I haven’t really “had” any meals all week, so why start now?\n\n#### Day 6: Coffee, My Constant Companion\n\n**9:00 AM**: Coffee is life. Coffee is love. I’m convinced my cells are now made of pure caffeine. I brew a pot of drip coffee just for the aroma and bask in the smell like it’s the nectar of the gods. I may be a little delirious, but I feel strangely enlightened.\n\n**3:00 PM**: I have developed the ability to hear colors. Or maybe I’ve lost it. Either way, I can smell time and it smells like espresso.\n\n**9:00 PM**: I try to watch a movie, but I can’t sit still for more than 20 minutes. I pace around the room like a caffeinated cheetah, plotting my next coffee creation. Maybe a double macchiato with whipped cream and regret.\n\n#### Day 7: The Final Frontier\n\n**8:00 AM**: I’ve done it. I’ve survived nearly a week on coffee alone. My head hurts, my hands are shaking, and I haven’t slept a full night in days—but I’m still here. I pour myself a final celebratory cup and try to savor it, but honestly, I don’t think I can handle another drop of coffee. \n\n**12:00 PM**: I cave. My stomach can’t take it anymore. I eat an actual meal—a sandwich—and it feels like heaven. I wash it down with water. Plain, boring, wonderful water.\n\n#### Conclusion: Can You Really Survive on Coffee Alone?\n\nTechnically, yes. Should you? Absolutely not. While coffee is a wonderful, magical elixir that fuels the modern world, it turns out the human body still needs things like food and water to survive. After a week of jittery limbs, sleepless nights, and coffee-induced paranoia, I’m happy to report that I’ve returned to solid foods. My love for coffee? Still strong, but we’ve learned that maybe moderation isn’t such a bad idea after all.\n\nSo, can you survive on coffee alone? You sure can! But you might not want to… unless you enjoy vibrating through the space-time continuum.\n\n--- \n\nThis approach gives a humorous and exaggerated look at the experience while still highlighting the fact that coffee alone is *definitely* not enough to survive on!',
      [core.properties.isA]: ['website/class/blogpost'],
      [core.properties.name]: 'Can You Really Survive on Coffee Alone?',
      [core.properties.parent]: '01j6cbg9djf269zdwwv5114jsd',
    },
    {
      [core.properties.localId]: '01j6ewtynjsyq7b3sc1pgqppde',
      'website/property/cover-image':
        'https://atomicdata.dev/files/1726129576337-pexels-karolina-grabowska-7273405.jpg',
      'website/property/path': '/blog/the-biology-of-balloon-animals',
      'website/property/published-at': 1724929560000,
      [core.properties.description]:
        'Balloon animals, those delightful creatures found at birthday parties, fairs, and street performances, are often overlooked in the annals of biology. Yet, these fascinating beings have an intricate life cycle, unique dietary needs, and habitats that are, tragically, under threat from climate change. Let\'s explore the mysterious biology of balloon animals and uncover the truth about these inflatable creatures.\n\n#### Habitat: Where Do Balloon Animals Live?\n\nThe natural habitat of the balloon animal is a curious one. While you may have spotted them in urban environments, twisting and squeaking in the hands of street performers or children, balloon animals originate from the rare and mystical land known as **Balloonia**.\n\n**Balloonia** is an elusive place, often forming in the back rooms of party supply stores, deep within the hands of skilled balloon artists. It’s a warm, dry region, ideal for balloon creatures who thrive in low-humidity environments (their number-one predator is moisture). In Balloonia, these animals are free to roam under ceilings and occasionally drift near HVAC systems for an exhilarating ride on air currents.\n\nHowever, the changing climate is taking its toll on this once-thriving habitat. Rising temperatures and unpredictable weather patterns are wreaking havoc on the delicate balloons, causing rapid deflation and increased rates of premature "popping," a tragic end for any balloon creature.\n\n#### Diet: What Do Balloon Animals Eat?\n\nContrary to popular belief, balloon animals have a very specific diet. Though they may appear weightless and hollow, they subsist on a steady intake of **party vibes** and **laughter energy**. These animals feed off the joyful atmosphere at birthday parties, weddings, and carnivals, thriving best when surrounded by giggling children and adults exclaiming, "How do they do that?"\n\nWhile balloon animals can absorb happiness through osmosis, they have a special fondness for being gently bopped on the head or having their squeaky surfaces rubbed by curious hands. This helps stimulate their "fun receptors," boosting their buoyancy and prolonging their lifespan. \n\nHowever, with the decline in in-person celebrations due to various global challenges (we’re looking at you, pandemic), balloon animals are facing a food crisis. Zoom parties, though cheerful, do not emit the same level of concentrated joy energy, leaving many balloon creatures feeling deflated—literally and figuratively.\n\n#### Balloon Animal Taxonomy: From Dogs to Dinosaurs\n\nBalloon animals come in a wide variety of shapes and species, much like any other animal kingdom. The **Canis Latex**, commonly known as the Balloon Dog, is one of the most ubiquitous species, often found bouncing around children’s parties. These creatures are characterized by their perky tails, elongated snouts, and irresistible urge to be bopped around.\n\nOther notable species include:\n- **Equus Inflateus (The Balloon Horse)**: Known for its long, wobbly legs and majestic mane, the balloon horse can be seen galloping across festive fields.\n- **Sauris Popperus (The Balloon Dinosaur)**: Once thought extinct, this species can still be found at prehistoric-themed parties, usually crafted into a fierce-looking T-Rex or a friendly brontosaurus.\n- **Serpentis Twisticus (The Balloon Snake)**: A simple, yet elegant species, the balloon snake is often the first balloon animal to emerge from the hands of novice balloon artists. It’s long, sleek, and sometimes given an adorable face with a permanent marker.\n\nBalloon animals, while plentiful in variety, all share the same genetic makeup: a latex exterior and a hollow, air-filled core. The complex twists and knots of their bodies are akin to their evolutionary armor, protecting them from predators (except for sharp objects, of course—more on those enemies later).\n\n#### Natural Predators and Threats\n\nBalloon animals, despite their festive appearance, face numerous threats in the wild. Their greatest nemesis? **Sharp objects**. This includes everything from wayward tree branches to the terrifying claws of household cats. The sight of a balloon dog trembling as it senses a nearby cactus is enough to tug at anyone’s heartstrings.\n\nOther natural enemies include:\n- **Direct sunlight**: Prolonged exposure to UV rays causes balloon animals to lose their elasticity, resulting in drooping and eventual death by slow deflation.\n- **Over-excited children**: Though balloon animals thrive in environments filled with joy, an overly enthusiastic child’s rough handling can lead to an untimely pop.\n- **Humidity**: A balloon animal’s worst nightmare. Moisture weakens their latex skin, causing it to break down more easily. Balloonia’s dry climate is the perfect breeding ground, but humid places like basements or rainy outdoor parties? Pure balloon carnage.\n\n#### Climate Change: The Balloon Animal Crisis\n\nIn recent years, climate change has posed a significant threat to balloon animals and their habitats. The rise in global temperatures has resulted in the **Balloonia Heatwave Phenomenon**, where balloon animals are now subjected to extreme heat, causing rapid expansion and the dreaded "pop" syndrome. As the air inside them heats up, it expands, stretching their latex bodies to the breaking point.\n\nAdditionally, the increase in natural disasters, like thunderstorms, has made balloon parties more unpredictable. Lightning strikes and sudden gusts of wind pose serious dangers to balloon animals, often flinging them into hazardous environments filled with sharp debris.\n\n**Deflation rates have skyrocketed**, with some species, like the intricate balloon giraffe, now considered endangered due to their fragile long necks, which are more prone to bursting under pressure.\n\nIn an effort to combat this crisis, balloon conservationists have suggested several mitigation strategies:\n- **Indoor-only parties**: By holding celebrations indoors, balloon animals are kept safe from harmful UV rays and weather-related threats.\n- **Humidity control measures**: Balloon sanctuaries now include humidifiers and coolers to preserve their latex structures.\n- **Adopting biodegradable balloons**: These are not only eco-friendly but less prone to the environmental damage caused by traditional balloon material, giving balloon animals a fighting chance in a warming world.\n\n#### The Future of Balloon Animals\n\nWith climate change on the rise and unpredictable party attendance rates, the future of balloon animals is uncertain. Conservation efforts are underway, and balloon scientists are exploring the possibility of more resilient latex species that can survive in a variety of conditions.\n\nIn the meantime, you can do your part by adopting sustainable party practices, holding celebrations in climate-controlled environments, and treating balloon animals with the gentle care they deserve. Every bounce, every squeak prolongs their precious, inflatable lives.\n\nRemember: a world without balloon animals is a world without joy. Let’s keep these delightful creatures thriving for future generations!',
      [core.properties.isA]: ['website/class/blogpost'],
      [core.properties.name]:
        'The Biology of Balloon Animals: A Deep Dive into Their Wild World',
      [core.properties.parent]: '01j6cbg9djf269zdwwv5114jsd',
    },
    {
      [core.properties.localId]: '01j6cjpvhc8sgmqeg6v84fgxtv',
      'website/property/path': '/blog',
      [core.properties.description]: 'List of blog posts',
      [core.properties.isA]: ['website/class/blog-index-page'],
      [core.properties.name]: 'Blog',
      [core.properties.parent]: '01j5zr8e919ph7g5xgyehv0g17',
    },
  ],
};
