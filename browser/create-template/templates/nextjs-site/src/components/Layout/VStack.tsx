import React, { ReactNode } from "react";
import styles from "./VStack.module.css";

interface VStackProps {
  gap?: React.CSSProperties["gap"];
  align?: React.CSSProperties["alignItems"];
  justify?: React.CSSProperties["justifyContent"];
  height?: React.CSSProperties["height"];
  children: ReactNode;
}

const VStack: React.FC<VStackProps> = ({
  gap = "1rem",
  align = "start",
  justify = "start",
  height = "auto",
  children,
}) => {
  const inlineStyles: {
    [key: string]: React.CSSProperties[keyof React.CSSProperties];
  } = {
    "--vstack-gap": gap,
    "--vstack-align": align,
    "--vstack-justify": justify,
    "--vstack-height": height,
  };

  return (
    <div style={inlineStyles} className={styles.vstack}>
      {children}
    </div>
  );
};

export default VStack;
