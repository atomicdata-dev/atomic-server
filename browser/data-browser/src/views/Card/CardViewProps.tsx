import { Resource } from '@tomic/react';

export interface CardViewPropsBase {
  /** Maximum height, only basic details are shown */
  small?: boolean;
  /** Show a highlight border */
  highlight?: boolean;
  /** An HTML reference */
  ref?: React.RefObject<HTMLDivElement>;
  /**
   * If you expect to render this card in the initial view (e.g. it's in the top
   * of some list)
   */
  initialInView?: boolean;
}

/** The properties passed to every CardView */
export interface CardViewProps extends CardViewPropsBase {
  /** The full Resource to be displayed */
  resource: Resource;
}
