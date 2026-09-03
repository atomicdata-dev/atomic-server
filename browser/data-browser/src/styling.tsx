import {
  createGlobalStyle,
  DefaultTheme,
  ThemeProvider,
} from 'styled-components';
import {
  complement,
  darken,
  lighten,
  setLightness,
  setSaturation,
} from 'polished';
import './reset.css';
import { useContext, type JSX } from 'react';
import { SettingsContext } from './helpers/AppSettings';
import { CurrentBackgroundColor } from './globalCssVars';
import { BREADCRUMB_BAR_TRANSITION_TAG } from './helpers/transitionName';

interface ThemeWrapperProps {
  children: React.ReactNode;
}

/**
 * Provides the theme for all components below. Make sure to wrap this inside
 * SettingsContext
 */
export const ThemeWrapper = ({ children }: ThemeWrapperProps): JSX.Element => {
  const { mainColor, darkMode, colorfulMode } = useContext(SettingsContext);

  return (
    <>
      <ThemeProvider theme={buildTheme(darkMode, mainColor, colorfulMode)}>
        {children}
      </ThemeProvider>
    </>
  );
};

/**
 * The app's muted color palette: the main-color presets in the appearance
 * settings, and the default colors for new tags.
 */
export const presetColors = [
  '#4C6FA5', // dusty blue
  '#6E9B7B', // sage green
  '#CC7B54', // terracotta
  '#B5657A', // dusty rose
  '#CC9A44', // mustard
  '#7C7BB8', // periwinkle
  '#4E9B96', // muted teal
  '#A9825E', // warm taupe
];

/**
 * Wraps the app chrome (sidebar, navbar). In colorful mode it swaps the
 * neutral ramp for tones of the main color, so no grey ever sits on a colored
 * surface. Outside colorful mode it changes nothing.
 */
export const ChromeTheme = ({ children }: ThemeWrapperProps): JSX.Element => (
  <ThemeProvider theme={chromeTheme}>{children}</ThemeProvider>
);

const chromeTheme = (outer: DefaultTheme | undefined): DefaultTheme => {
  // ChromeTheme is always nested inside ThemeWrapper, so outer is never
  // actually undefined.
  if (!outer || !outer.colorful) {
    return outer!;
  }

  const tone = (lightness: number, saturation: number) =>
    setLightness(lightness, setSaturation(saturation, outer.colors.main));

  const colors = outer.darkMode
    ? {
        bg: tone(0.12, 0.35),
        bg1: tone(0.18, 0.35),
        bg2: tone(0.28, 0.3),
        text: tone(0.92, 0.3),
        text1: tone(0.85, 0.3),
        textLight: tone(0.72, 0.25),
        textLight2: tone(0.5, 0.25),
      }
    : {
        bg: tone(0.93, 0.55),
        bg1: tone(0.88, 0.5),
        bg2: tone(0.8, 0.4),
        text: tone(0.13, 0.4),
        text1: tone(0.18, 0.4),
        textLight: tone(0.35, 0.3),
        textLight2: tone(0.55, 0.25),
      };

  return { ...outer, colors: { ...outer.colors, ...colors } };
};

/**
 * Adjust the z-index order here. Watch out: do not use in styled-components,
 * prefer to use `theme.zIndex`
 */
export const zIndex = {
  sidebar: 10,
  searchOverlay: 9,
  dialog: 100,
  dropdown: 200,
  networkIndicator: 300,
  toast: 400,
};

/** Default animation duration in ms */
export const animationDuration = 100;

const breadCrumbBarHeight = '2.2rem';
const floatingSearchBarPadding = '4.2rem';

function size(index = 3): string {
  const sizes = [
    size.raw(0.25),
    size.raw(0.5),
    size.raw(1),
    size.raw(1.25),
    size.raw(1.5),
    size.raw(1.75),
    size.raw(2),
    size.raw(3),
    size.raw(4),
    size.raw(5),
    size.raw(7.5),
    size.raw(10),
    size.raw(15),
    size.raw(20),
    size.raw(30),
  ];

  const sizeStr = sizes[index - 1];

  if (sizeStr === undefined) {
    throw new Error(`Size index ${index} out of bounds`);
  }

  return sizeStr;
}

size.raw = (multiplier: number) => `${multiplier}rem`;

/** Construct a StyledComponents theme object */
export const buildTheme = (
  darkMode: boolean,
  mainIn: string,
  colorful = false,
): DefaultTheme => {
  // Guard against undefined during HMR re-initialization (e.g. useLocalStorage cold start)
  const safeMain = mainIn || '#1b50d8';
  const main = darkMode ? lighten(0.2, safeMain) : safeMain;
  const complementaryIn = complement(safeMain);
  const complementary = darkMode
    ? lighten(0.2, complementaryIn)
    : complementaryIn;
  const bg = darkMode ? '#000000' : '#ffffff';
  const text = darkMode ? '#fff' : '#000';
  // Colorful mode: content and text stay neutral for readability; the main
  // color shows in the app chrome (sidebar, navbar) via ChromeTheme, with a
  // barely-there tint on the body behind it. Tinting the full neutral ramp
  // reads as a monochrome wash, not as color.
  const bgBodyColorful = darkMode
    ? setLightness(0.045, setSaturation(0.25, safeMain))
    : setLightness(0.975, setSaturation(0.35, safeMain));
  const shadowColor = darkMode ? 'rgba(255,255,255,.15)' : 'rgba(0,0,0,0.07)';
  const shadowColorIntense = darkMode
    ? 'rgba(255,255,255,.3)'
    : 'rgba(0,0,0,0.2)';

  return {
    darkMode,
    colorful,
    fontFamilyHeader:
      "'Montserrat', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
    fontFamily:
      "'Open Sans', 'Helvetica Neue', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
    boxShadow: `0 0 10px 0px ${shadowColor}`,
    boxShadowIntense: `0 0 22px 0px ${shadowColorIntense}`,
    boxShadowSoft: `0px 1.5px 2.2px rgba(0, 0, 0, 0.02),
    0px 3.5px 5.3px rgba(0, 0, 0, 0.028), 0px 6.6px 10px rgba(0, 0, 0, 0.035),
    0px 11.8px 17.9px rgba(0, 0, 0, 0.042),
    0px 22.1px 33.4px rgba(0, 0, 0, 0.05), 0px 53px 80px rgba(0, 0, 0, 0.07);`,
    containerWidth: 40,
    containerWidthWide: '900px',
    fontSizeBody: 1,
    fontSizeH1: 1.5,
    sideBarWidth: 15,
    margin: 1,
    radius: '9px',
    heights: {
      breadCrumbBar: breadCrumbBarHeight,
      floatingSearchBarPadding: floatingSearchBarPadding,
      fullPage: `100%`,
    },
    size,
    colors: {
      main,
      mainLight: darkMode ? lighten(0.08)(main) : lighten(0.08)(main),
      mainDark: darkMode ? darken(0.08)(main) : darken(0.08)(main),
      complementary,
      bg: bg,
      // Use pitch black for dark mode
      bgBody: colorful ? bgBodyColorful : darkMode ? bg : darken(0.02)(bg),
      mainSelectedBg: setLightness(darkMode ? 0.05 : 0.97, main),
      mainSelectedFg: setLightness(darkMode ? 0.7 : 0.25, main),
      bg1: darkMode ? lighten(0.1)(bg) : darken(0.05)(bg),
      bg2: darkMode ? lighten(0.3)(bg) : darken(0.2)(bg),
      text,
      text1: darkMode ? darken(0.1)(text) : lighten(0.1)(text),
      textLight: darkMode ? darken(0.4)(text) : lighten(0.4)(text),
      textLight2: darkMode ? darken(0.8)(text) : lighten(0.8)(text),
      alert: '#cf5b5b',
      alertLight: '#e66f6f',
      warning: '#f5a623',
      diff: {
        addedBg: '#e4ffe4',
        addedFg: '#003500',
        removedBg: '#ffcdcd',
        removedFg: '#2d0000',
      },
    },
    animation: {
      duration: `${animationDuration}ms`,
    },
    zIndex,
  };
};

// Styled-components requires overwriting the default theme
declare module 'styled-components' {
  export interface DefaultTheme {
    /** If true, make things dark */
    darkMode: boolean;
    /** If true, the app chrome (via ChromeTheme) is tinted with the main color */
    colorful: boolean;
    fontFamilyHeader: string;
    fontFamily: string;
    /** Body font size in rem */
    fontSizeBody: number;
    /** Header font size in rem */
    fontSizeH1: number;
    boxShadow: string;
    boxShadowIntense: string;
    boxShadowSoft: string;
    /**
     * @deprecated
     * use size() instead
     */
    margin: number;
    /** Width of the container, in rem */
    containerWidth: number;
    /** Width of the container */
    containerWidthWide: string;
    /** Width of the sidebar, in rem */
    sideBarWidth: number;
    /** Roundness of some elements / Border radius */
    radius: string;
    /** All theme colors */
    heights: {
      breadCrumbBar: string;
      fullPage: string;
      floatingSearchBarPadding: string;
    };

    /**
     * Function that returns a size in rem for the given index.
     * Based on the following ratio:
     * 1) size.raw(0.25),
     * 2) size.raw(0.5),
     * 3) size.raw(1),
     * 4) size.raw(1.25),
     * 5) size.raw(1.5),
     * 6) size.raw(1.75),
     * 7) size.raw(2),
     * 8) size.raw(3),
     * 9) size.raw(4),
     * 10) size.raw(5),
     * 11) size.raw(7.5),
     * 12) size.raw(10),
     * 13) size.raw(15),
     * 14) size.raw(20),
     * 15) size.raw(30),
     *
     * When given no index it returns the default size (3)
     */
    size: typeof size;
    colors: {
      /** Main accent color, used for links */
      main: string;
      /** Slightly lighter version of Main accent color */
      mainLight: string;
      /** Slightly darker version of Main accent color */
      mainDark: string;
      /** Background color of selected items */
      mainSelectedBg: string;
      /** Foreground color of selected items */
      mainSelectedFg: string;
      /** Complementary color of main */
      complementary: string;
      /** The background color of the body, which is subtly different from bg */
      bgBody: string;
      /** Most common background color */
      bg: string;
      /** Subtle background color */
      bg1: string;
      /** Subtle background color */
      bg2: string;
      /** Main (body) text color */
      text: string;
      /** Sublty different hue of the main text color */
      text1: string;
      /** Lighter shade of text */
      textLight: string;
      /** Lighter shade of text, not accessible for some */
      textLight2: string;
      /** Error / warning color */
      alert: string;
      alertLight: string;
      warning: string;
      diff: {
        addedBg: string;
        addedFg: string;
        removedBg: string;
        removedFg: string;
      };
    };
    animation: {
      duration: string;
    };
    zIndex: typeof zIndex;
  }
}

/** Adds basic styles for the entire app */
export const GlobalStyle = createGlobalStyle`

  :root {
    --view-transition-duration: 150ms;
  }

  * {
    box-sizing: border-box;
    scrollbar-color: ${p => p.theme.colors.bg2} transparent;
    @media print {
      scrollbar-color: transparent transparent;
    }
    &::-webkit-scrollbar {
      width: 10px;
      height: 10px;
      padding: 3px;
      background-color: transparent;/* color of the tracking area */

    }
    &::-webkit-scrollbar-thumb {
      width: 8px;
      margin: auto;
      background-color: ${p =>
        p.theme.colors.bg2}; /* color of the tracking area */
      border-radius: ${p => p.theme.radius};

      &:hover {
        background-color: ${p => darken(0.1)(p.theme.colors.bg2)};
      }
    }
  }

  body {
    ${CurrentBackgroundColor.define(p => p.theme.colors.bgBody)}
    background-color: ${CurrentBackgroundColor.var()};
    color: ${props => props.theme.colors.text};
    font-family: ${props => props.theme.fontFamily};
    line-height: 1.5em;
    word-wrap: break-word;
    overflow-wrap: anywhere;
    // Prevents weird scrollbars appearing for a split second when opening a dialog
    overflow: hidden;

    margin: 0;
    /** Pretty dark mode transition */
    transition: background-color .2s ease, border-color .2s ease, color .2s ease;
    font-size: 1rem;
  }

  input, button, body {
    /* Don't overflow input elements */
    overflow-wrap: normal;
  }

  a {
    color: ${props => props.theme.colors.main};
  }

  h1 {
    font-size: ${p => p.theme.fontSizeH1}rem;
  }

  h2 {
    font-size: 1.7rem;
  }

  h1,h2,h3,h4,h5,h6 {
    margin-bottom: ${props => props.theme.size()};
    font-weight: bold;
    font-family: ${p => p.theme.fontFamilyHeader};
    line-height: 1em;
    margin-top: 0;
    word-break: break-word;
  }

  i {
    font-style: italic;
  }

  p {
    margin-top: 0;
    margin-bottom: ${props => props.theme.size()};
  }

  ul {
    margin-top: 0;
    margin-bottom: ${props => props.theme.size()};
    padding: 0;

    li {
      list-style-type: disc;
      margin-left: ${props => props.theme.size(7)};
      margin-bottom: ${props => props.theme.size(2)};
    }
  }

  b {
    font-weight: bold;
  }

  /* —— View transitions ——
     Matched pairs (same view-transition-name on both pages, e.g. a grid
     item's title morphing into the page H1) get the UA's plus-lighter
     cross-fade, which is seamless where pixels are identical. */
  ::view-transition-old(*),
  ::view-transition-new(*) {
    animation-duration: var(--view-transition-duration);
    /* Scale snapshots by height, preserving aspect ratio. The UA default
       (inline-size: 100%, block-size: auto) smears text horizontally when a
       narrow snapshot morphs into a wide group (grid title → page H1) —
       most visible in Firefox, which doesn't interpolate changing aspect
       ratios as smoothly as Chromium. */
    block-size: 100%;
    inline-size: auto;
  }

  /* Keep geometry (group) animations on the same clock as the fades. The UA
     default is 250ms, which held the snapshot overlay up ~100ms after the
     150ms fades had already finished. */
  ::view-transition-group(*) {
    animation-duration: var(--view-transition-duration);
  }

  /* A snapshot with no counterpart on the other page (old- or new-only —
     every group during a sidebar navigation) must swap instantly. Letting
     it alpha-fade dims unchanged-looking content ~25% mid-fade, which reads
     as a full-page flash. Morphing pairs are unaffected (their image-pair
     has two children). The download-button rules below intentionally
     override this to keep their slide in/out. */
  ::view-transition-old(*):only-child,
  ::view-transition-new(*):only-child {
    animation-duration: 0ms;
  }

  ::view-transition-old(root),
  ::view-transition-new(root) {
    animation-duration: 0ms;
  }

  @keyframes slide-in-from-right {
    from {
      transform: translateX(5rem);
      opacity: 0;
    }

    to {
      transform: translateX(0);
      opacity: 1;
    }
  }

  ::view-transition-image-pair(download-button) {
    mix-blend-mode: normal;
  }

  ::view-transition-old(download-button):only-child,
  ::view-transition-new(download-button):only-child {
    animation: slide-in-from-right var(--view-transition-duration) ease-in-out;
    animation-fill-mode: both;
  }

  ::view-transition-old(download-button):only-child {
    animation-direction: reverse;
  }

  /* Keep the navigation bar above the morphing page groups. */
  ::view-transition-group(${BREADCRUMB_BAR_TRANSITION_TAG}) {
    z-index: 10;
  }

  @media (prefers-reduced-motion) {
  ::view-transition-group(*),
  ::view-transition-old(*),
  ::view-transition-new(*) {
    animation: none !important;
  }
}

  @keyframes toast-enter {
    0%   {left:110%;}
    100% {left:0;}
  }

  @keyframes toast-exit {
    0%   {left:0;}
    100% {left:110%;}
  }
`;
