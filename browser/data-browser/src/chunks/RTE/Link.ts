import { Link as TiptapLink } from '@tiptap/extension-link';
import { registerCustomProtocol, reset } from 'linkifyjs';

// Linkify's parser is shared by every editor. Configure it once when this
// module loads, before parsing links, rather than registering on each editor
// mount and resetting it when any one editor closes. Reset also makes HMR safe.
reset();
registerCustomProtocol('tel', true);

export const Link = TiptapLink.extend({
  onCreate() {},
  onDestroy() {},
}).configure({
  protocols: [{ scheme: 'tel', optionalSlashes: true }],
});
