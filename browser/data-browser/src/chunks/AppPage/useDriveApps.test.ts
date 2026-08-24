import { describe, expect, it } from 'vitest';
import { appsForClass, type DriveApp } from './useDriveApps';

const app = (name: string, renders: string[]): DriveApp => ({
  subject: `did:ad:${name}`,
  name,
  renders,
});

describe('which apps a table offers', () => {
  const invoices = 'did:ad:class-invoice';
  const events = 'did:ad:class-event';

  it('offers an app that says it can show these rows', () => {
    const apps = [app('Ledger', [invoices]), app('Calendar', [events])];

    expect(appsForClass(apps, invoices).map(a => a.name)).toEqual(['Ledger']);
  });

  it('does not offer one that says nothing', () => {
    // An app written against its own schema would be offered for every table
    // on the drive and break on most of them. Declaring is the price of being
    // offered elsewhere.
    expect(appsForClass([app('Quiet', [])], invoices)).toEqual([]);
  });

  it('offers an app that handles several classes', () => {
    const apps = [app('Both', [invoices, events])];

    expect(appsForClass(apps, invoices)).toHaveLength(1);
    expect(appsForClass(apps, events)).toHaveLength(1);
  });

  it('offers nothing for a table whose rows have no class', () => {
    expect(appsForClass([app('Ledger', [invoices])], undefined)).toEqual([]);
  });
});
