export type CellIndex<T> = [rowIndex: number, column: T];
export type Corner = [x: number, y: number];

export type CopyValue = {
  plain: string;
  html?: string;
};

export type CellPasteData<T> = {
  index: CellIndex<T>;
  data: string;
};

export type ColumnReorderHandler = (
  source: number,
  destination: number,
) => void;
