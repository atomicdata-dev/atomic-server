import React, { ReactNode } from 'react';
import clsx from 'clsx';
import styles from './HStack.module.css';

interface HStackProps {
  gap?: React.CSSProperties['gap'];
  align?: React.CSSProperties['alignItems'];
  justify?: React.CSSProperties['justifyContent'];
  fullWidth?: boolean;
  wrap?: boolean;
  children: ReactNode;
}

const HStack: React.FC<HStackProps> = ({
  gap = '1rem',
  align = 'start',
  justify = 'start',
  fullWidth = false,
  wrap = false,
  children,
}) => {
  const inlineStyles: {
    [key: string]: string | number;
  } = {
    '--hstack-gap': gap,
    '--hstack-align': align,
    '--hstack-justify': justify,
  };

  return (
    <div
      style={inlineStyles}
      className={clsx(styles.hstack, {
        [styles.fullWidth]: fullWidth,
        [styles.wrap]: wrap,
      })}
    >
      {children}
    </div>
  );
};

export default HStack;
