// @wc-ignore-file
import { Datatype, type SchemaSpec } from '../../browser/lib/src/index.js';
export function bankingSchema(): SchemaSpec {
  const fields = [
    [
      'bank-account',
      'Account',
      'Statement account identifier (MT940 field 25); not necessarily an IBAN.',
    ],
    [
      'bank-currency',
      'Currency',
      'ISO 4217 currency code from the statement balance.',
    ],
    [
      'bank-amount',
      'Amount',
      'Exact signed decimal string in account currency. Negative is money out; positive is money in.',
    ],
    [
      'bank-value-date',
      'Value date',
      'Bank value date, without an inferred time zone.',
    ],
    [
      'bank-booking-date',
      'Booking date',
      'Booking date; value date when the statement omits it.',
    ],
    [
      'bank-description',
      'Description',
      'Original bank narrative, including structured MT940 field 86 codes.',
    ],
    [
      'bank-reference',
      'Reference',
      'Bank reference, or customer reference if absent.',
    ],
    [
      'bank-transaction-code',
      'Transaction code',
      'Original MT940 transaction type code.',
    ],
    ['bank-statement', 'Statement', 'Source statement number and sequence.'],
    [
      'bank-source-id',
      'Source identity',
      'Account-qualified importer identity for repeat detection.',
    ],
    [
      'bank-fingerprint',
      'Import fingerprint',
      'Original imported transaction content used to detect conflicting reimports.',
    ],
  ];
  return {
    properties: fields.map(([shortname, name, description]) => ({
      shortname,
      name,
      description,
      datatype: shortname.endsWith('-date') ? Datatype.DATE : Datatype.STRING,
    })),
    classes: [
      {
        shortname: 'bank-transaction',
        name: 'Bank transaction',
        description:
          'A booked bank statement entry. MT940 is the initial source format.',
        requires: [
          'bank-account',
          'bank-currency',
          'bank-amount',
          'bank-value-date',
          'bank-source-id',
        ],
        recommends: fields.slice(0, 9).map(f => f[0]),
      },
    ],
  };
}
