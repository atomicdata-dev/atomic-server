import { loopingIndex } from './loopingIndex';

// CSS Query of all elements that can receive focus.
const QUERY =
  'a[href]:not([disabled]), button:not([disabled]), input:not([disabled], [type=hidden]), [tabindex]:not([disabled]):not([tabindex="-1"]), textarea:not([disabled]), select:not([disabled]), [contenteditable]:not([disabled])';

/**
 * Focus the element that is offset from the origin in the tab order.
 * Effectively simulates the behavour of the tab key but allows for specifying a different origin element from the current activeElement.
 **/
export function focusOffsetElement(offset: number, origin?: Element) {
  //add all elements we want to include in our selection
  const startElement = origin ?? document.activeElement;

  if (startElement) {
    const focussable: Element[] = [];

    document.querySelectorAll(QUERY).forEach(element => {
      //check for visibility while always include the current activeElement
      if (
        // @ts-ignore
        element.offsetWidth > 0 ||
        // @ts-ignore
        element.offsetHeight > 0 ||
        element === startElement
      ) {
        focussable.push(element);
      }
    });

    const index = focussable.indexOf(startElement);

    if (index > -1) {
      const nextElement =
        focussable[loopingIndex(index + offset, focussable.length)] ||
        focussable[0];

      // @ts-ignore
      nextElement.focus();
    }
  }
}
