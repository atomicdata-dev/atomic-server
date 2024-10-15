import { DefaultTheme } from 'styled-components';

const randomId = () => Math.random().toString(36).substring(2, 15);

/**
 * Creates an object that can be used to define and reference a css variable.
 * Using css vars like this makes it easier to track their usage and manage css.
 */
export class CSSVar {
  /**
   * The raw css variable name.
   */
  public readonly raw: string;

  /**
   * Creates an css variable object that can be used to define and reference a css variable.
   * @param name - The name of the css variable, must be a valid css variable name without the leading `--`.
   */
  public constructor(name: string) {
    this.raw = `--${name}-${randomId()}`;
  }

  /**
   * Defines the css variable.
   * @param value - The value of the css variable, can also be a function that gets the same props as the Styled Component.
   */
  public define<T extends { theme: DefaultTheme }>(
    value: ((p: T) => unknown) | string | number,
  ): (p: T) => string {
    return props =>
      `${this.raw}: ${typeof value === 'function' ? value(props) : value};`;
  }

  /**
   * Returns a reference to the css variable to use as a value.
   * @param fallback - Optional fallback value to use if the css variable is not defined.
   */
  public var(fallback?: unknown) {
    return fallback === undefined
      ? `var(${this.raw})`
      : `var(${this.raw}, ${fallback})`;
  }
}
