/**
 * Function to map currency codes to names using this list: https://www.six-group.com/dam/download/financial-information/data-center/iso-currrency/lists/list-one.xml
 * Used to update the string in currencies.ts.
 * Only works in the browser.
 *
 * To use, move the file out of the chunks folder
 * @param xmlStr XML String with ISO 4217 data
 */
export const processCurrencyFile = (xmlStr: string): string => {
  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(xmlStr, 'text/xml');
  const currencyNodes = xmlDoc.getElementsByTagName('CcyNtry');
  const currencyMap = {};

  for (let i = 0; i < currencyNodes.length; i++) {
    const currencyNode = currencyNodes[i];
    const code = currencyNode.getElementsByTagName('Ccy')[0]?.textContent;

    if (!code) {
      continue;
    }

    const currencyName =
      currencyNode.getElementsByTagName('CcyNm')[0]?.textContent;
    currencyMap[code] = currencyName;
  }

  return JSON.stringify(currencyMap);
};
