import {
  createGlobalStyle,
  DefaultTheme,
  ThemeProvider,
} from 'styled-components';
import { darken, lighten } from 'polished';
import './reset.css';
import React, { useContext } from 'react';
import { SettingsContext } from './helpers/AppSettings';

interface ThemeWrapperProps {
  children: React.ReactNode;
}

/**
 * Provides the theme for all components below. Make sure to wrap this inside
 * SettingsContext
 */
export const ThemeWrapper = ({ children }: ThemeWrapperProps): JSX.Element => {
  const { mainColor, darkMode } = useContext(SettingsContext);

  return (
    <>
      {/* @ts-ignore TODO: Check if types are fixed or upgrade styled-components to 6.0.0 */}
      <ThemeProvider key={mainColor} theme={buildTheme(darkMode, mainColor)}>
        {children}
      </ThemeProvider>
    </>
  );
};

/**
 * Adjust the z-index order here. Watch out: do not use in styled-components,
 * prefer to use `theme.zIndex`
 */
export const zIndex = {
  sidebar: 10,
  dialog: 100,
  dropdown: 200,
  networkIndicator: 300,
  toast: 400,
};

/** Default animation duration in ms */
export const animationDuration = 100;

const breadCrumbBarHeight = '2.2rem';
const floatingSearchBarPadding = '4.2rem';

/** Construct a StyledComponents theme object */
export const buildTheme = (darkMode: boolean, mainIn: string): DefaultTheme => {
  const main = darkMode ? lighten(0.2, mainIn) : mainIn;
  const bg = darkMode ? '#000000' : '#ffffff';
  const text = darkMode ? '#fff' : '#000';
  const shadowColor = darkMode ? 'rgba(255,255,255,.15)' : 'rgba(0,0,0,0.07)';
  const shadowColorIntense = darkMode
    ? 'rgba(255,255,255,.3)'
    : 'rgba(0,0,0,0.2)';

  return {
    darkMode,
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
    fontSizeH1: 2,
    sideBarWidth: 15,
    margin: 1,
    radius: '9px',
    heights: {
      breadCrumbBar: breadCrumbBarHeight,
      floatingSearchBarPadding: floatingSearchBarPadding,
      fullPage: `calc(100% - ${breadCrumbBarHeight})`,
    },
    colors: {
      main,
      mainLight: darkMode ? lighten(0.08)(main) : lighten(0.08)(main),
      mainDark: darkMode ? darken(0.08)(main) : darken(0.08)(main),
      bg: bg,
      // Use pitch black for dark mode
      bgBody: darkMode ? bg : darken(0.02)(bg),
      bg1: darkMode ? lighten(0.1)(bg) : darken(0.05)(bg),
      bg2: darkMode ? lighten(0.3)(bg) : darken(0.2)(bg),
      text,
      text1: darkMode ? darken(0.1)(text) : lighten(0.1)(text),
      textLight: darkMode ? darken(0.4)(text) : lighten(0.4)(text),
      textLight2: darkMode ? darken(0.8)(text) : lighten(0.8)(text),
      alert: '#cf5b5b',
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
    fontFamilyHeader: string;
    fontFamily: string;
    /** Body font size in rem */
    fontSizeBody: number;
    /** Header font size in rem */
    fontSizeH1: number;
    boxShadow: string;
    boxShadowIntense: string;
    boxShadowSoft: string;
    /** Base margin */
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
    colors: {
      /** Main accent color, used for links */
      main: string;
      /** Slightly lighter version of Main accent color */
      mainLight: string;
      /** Slightly darker version of Main accent color */
      mainDark: string;
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
  }

  body {
    background-color: ${props => props.theme.colors.bgBody};
    color: ${props => props.theme.colors.text};
    font-family: ${props => props.theme.fontFamily};
    line-height: 1.5em;
    word-wrap: break-word;
    overflow-wrap: anywhere;
    margin: 0;
    /** Pretty dark mode transition */
    transition: background .2s ease, border-color .2s ease, color .2s ease;
  }

  input, button, body {
    /* transition: background .2s ease, border-color .2s ease, color .2s ease; */
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
    margin-bottom: ${props => props.theme.margin}rem;
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
    margin-bottom: ${props => props.theme.margin}rem;
  }

  ul {
    margin-top: 0;
    margin-bottom: ${props => props.theme.margin}rem;
    padding: 0;

    li {
      list-style-type: disc;
      margin-left: ${props => props.theme.margin * 2}rem;
      margin-bottom: ${props => props.theme.margin / 2}rem;
    }
  }

  code {
    background-color: ${props => props.theme.colors.bg1};
    padding: 0rem 0.2rem;
    font-family: Monaco, monospace;
    font-size: .8em;
    display: inline-flex;
    white-space: nowrap;
    overflow: auto;
    max-width: 100%;
  }

  b {
    font-weight: bold;
  }

  ::view-transition-old(*),
  ::view-transition-new(*) {
    animation-duration: var(--view-transition-duration);
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

  ::view-transition-group(navbar) {
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
