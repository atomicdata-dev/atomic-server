import { Core, Resource } from '@tomic/react';

export interface PropertyCategoryFormProps {
  resource: Resource<Core.Property>;
  /**
   * True when the form edits a saved column. Otherwise `resource` is a draft
   * of a column that does not exist yet. `resource.new` cannot tell: a draft's
   * genesis is signed on creation, which clears it.
   */
  existingProperty?: boolean;
}
