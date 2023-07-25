import React, { useInsertionEffect } from 'react';
import {
  DefaultTheme,
  FlattenSimpleInterpolation,
  StyledComponent,
} from 'styled-components';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type CT = React.FunctionComponent<any>;

type SComp<
  C extends CT | keyof JSX.IntrinsicElements,
  SP extends object,
> = StyledComponent<C, DefaultTheme, SP, never>;

function getStyleElement(id: string) {
  const existingNode = document.getElementById(id);

  if (existingNode) {
    return existingNode;
  }

  const node = document.createElement('style');
  node.setAttribute('id', id);
  document.head.appendChild(node);

  return node;
}

function addQueryToDom(id: string, query: string) {
  const node = getStyleElement(id);

  node.innerHTML = query;
}

type PossibleComponent = CT | keyof JSX.IntrinsicElements;

type PropsOfComponent<C extends CT> = React.PropsWithChildren<Parameters<C>[0]>;

type Attributes<C> = C extends keyof JSX.IntrinsicElements
  ? React.PropsWithChildren<JSX.IntrinsicElements[C]>
  : never;

/**
 * Wraps a Styled component and adds Container query logic to it.
 * This is a temporary solution until Styled-components adds support for container queries.
 * If Container queries are not supported by the browser it falls back to a media query.
 */
export function wrapWithCQ<SP extends object, C extends PossibleComponent>(
  Component: SComp<C, SP>,
  match: string,
  css: string | FlattenSimpleInterpolation,
): SComp<C, SP> {
  const CQWrapper = (
    props: C extends CT ? PropsOfComponent<C> : Attributes<C>,
  ) => {
    // Create an id out of the unique styled component class.
    // this ensures we always make only one style element per component instead of one per instance.
    const id = `cq-${Component}`;

    useInsertionEffect(() => {
      const supportsContainerQueries = CSS.supports(
        'container-type',
        'inline-size',
      );

      const queryType = supportsContainerQueries ? 'container' : 'media';

      const query = `
        @${queryType} (${match}) {
          ${Component} {
            ${css}
          }
        }
      `;

      addQueryToDom(id, query);
    }, []);

    if (!props) {
      throw new Error('Props are required');
    }

    return (
      //@ts-ignore
      <Component {...props}>{props.children}</Component>
    );
  };

  // @ts-ignore
  return CQWrapper;
}
