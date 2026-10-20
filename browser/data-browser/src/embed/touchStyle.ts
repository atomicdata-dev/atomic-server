/**
 * Touch feedback in the app's web view. Android draws a flat blue rectangle
 * (`-webkit-tap-highlight-color`) on whatever is tapped, and the browser's
 * focus ring after a tap. Both go; a press shows a faint wash of the text
 * colour instead (works on light and dark, over any background), as the app's
 * native lists do.
 */
export const embedTouchCss = `
  html, * {
    -webkit-tap-highlight-color: transparent;
  }
  a, img, button, [role='button'] {
    -webkit-touch-callout: none;
  }
  :focus:not(:focus-visible) {
    outline: none;
  }
  a, button, [role='button'], [role='link'], [role='option'], [role='menuitem'], [role='tab'], [tabindex]:not([tabindex='-1']):not(input):not(textarea) {
    transition: background-color 80ms;
  }
  a:active, button:active, [role='button']:active, [role='link']:active, [role='option']:active, [role='menuitem']:active, [role='tab']:active, [tabindex]:not([tabindex='-1']):not(input):not(textarea):active {
    background-image: linear-gradient(rgba(128, 128, 128, 0.16), rgba(128, 128, 128, 0.16));
  }
`;
