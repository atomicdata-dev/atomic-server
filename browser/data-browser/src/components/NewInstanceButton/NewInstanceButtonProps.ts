import { IconType } from 'react-icons';

interface Props {
  /** URL of the Class to be instantiated */
  klass: string;
  subtle?: boolean;
  icon?: boolean;
  IconComponent?: IconType;
  /** subject of the parent Resource, which will be passed to the form */
  parent?: string;
  /** Give explicit label. If missing, uses the Shortname of the Class */
  label?: string;
  className?: string;
}

export type NewInstanceButtonProps = React.PropsWithChildren<Props>;
