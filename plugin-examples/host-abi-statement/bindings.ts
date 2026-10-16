// Generated from the manifest by @tomic/plugin (generateExportBindings). Do not edit.

/** What `store.callExport` of a frame or packaged view offers. */
export interface ExportCaller {
  callExport<T = unknown>(
    iface: string,
    fn: string,
    args?: Record<string, unknown>,
  ): Promise<T>;
}

export interface StatementReadArgs {
  /** The CSV text of the statement. */
  statement: string;
}

export interface StatementReadResultTransactionsItem {
  /** The booking date, YYYY-MM-DD. */
  date: string;
  /** The description as written. */
  description: string;
  /** The amount in minor units; negative is a debit. */
  amountMinor: number;
}

export interface StatementReadResult {
  /** The number of transactions. */
  count: number;
  /** The sum of all amounts, in minor units (cents). */
  totalMinor: number;
  /** The transactions in statement order. */
  transactions: StatementReadResultTransactionsItem[];
}

/** Reads a statement (date,description,amount per line, amounts in decimal) into transactions with amounts in minor units. An optional header row is skipped. */
export function statementRead(
  store: ExportCaller,
  args: StatementReadArgs,
): Promise<StatementReadResult> {
  return store.callExport<StatementReadResult>(
    "atomic:example/statement@1",
    "read",
    { ...args },
  );
}
