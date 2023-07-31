import { CopyValue } from '../types';

function extractPropFromMatrix<T extends Record<string, string>>(
  matrix: T[][],
  prop: keyof T,
): string[][] {
  return matrix.map(row => row.map(cell => cell[prop]));
}

const row = (inner: string) => {
  return `<tr>${inner}</tr>`;
};

const col = (inner: string) => {
  return `<td>${inner ?? ''}</td>`;
};

export function valueMatrixToTable(valueMatrix: string[][]): string {
  const innerTable = valueMatrix.map(r => row(r.map(col).join('')));

  return `<table><tbody>${innerTable.join('')}</tbody></table>`;
}

function valueMatrixToCSV(valueMatrix: string[][]): string {
  return valueMatrix.map(r => r.join('  ')).join('\n');
}

export function copyToClipboard(values: CopyValue[][]): Promise<void> {
  const htmlValues = extractPropFromMatrix(values, 'html');
  const plainValues = extractPropFromMatrix(values, 'plain');

  const htmlText = valueMatrixToTable(htmlValues);
  const csvText = valueMatrixToCSV(plainValues);

  const htmlType = 'text/html';
  const htmlBlob = new Blob([htmlText], { type: htmlType });

  const plainType = 'text/plain';
  const plainBlob = new Blob([csvText], { type: plainType });

  const item = new ClipboardItem({
    [htmlType]: htmlBlob,
    [plainType]: plainBlob,
  });

  return navigator.clipboard.write([item]);
}

export function parseHTMLTable(data: string): string[][] {
  const template = document.createElement('template');
  template.innerHTML = data;
  const table = template.content.querySelector('table tbody');

  if (!table) {
    const text = template.content.textContent ?? '';

    return [[text]];
  }

  const result: string[][] = [];

  table.querySelectorAll('tr').forEach(tr => {
    const rowData: string[] = [];

    tr.querySelectorAll('td').forEach(td => {
      const links: string[] = [];
      td.querySelectorAll('a').forEach(a => {
        links.push(a.href);
      });

      if (links.length > 0) {
        rowData.push(links.join(','));

        return;
      }

      rowData.push(td.textContent ?? '');
    });

    result.push(rowData);
  });

  template.remove();

  return result;
}
