/**
 * The country list shared by the `country` field, the `address` field's
 * country subfield and the builder's "default country" picker.
 *
 * Answers are stored as the ISO 3166-1 alpha-2 code (`"NL"`); the names
 * visitors see come from `Intl.DisplayNames`, so the list is localized by the
 * browser and this package ships no name table of its own. Mirrored loosely
 * by `is_valid_country` in `server/src/forms.rs`, which only checks the
 * two-uppercase-letter shape — this list stays the canonical one.
 */

/** ISO 3166-1 alpha-2, officially assigned codes only (so no `XK` for Kosovo
 * and none of the exceptionally reserved codes). Kept as one string because
 * 249 quoted array entries is a screenful of nothing; sorted by code here,
 * and by localized name for display (see `countryOptions`). */
export const COUNTRY_CODES: readonly string[] = `
  AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ
  BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS
  BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN
  CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE
  EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF
  GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM
  HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM
  JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC
  LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK
  ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA
  NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG
  PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW
  SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS
  ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO
  TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI
  VN VU WF WS YE YT ZA ZM ZW
`
  .trim()
  .split(/\s+/);

const COUNTRY_CODE_SET = new Set(COUNTRY_CODES);

export function isCountryCode(value: unknown): value is string {
  return typeof value === 'string' && COUNTRY_CODE_SET.has(value);
}

/** `Intl.DisplayNames` instances are expensive enough to be worth keeping —
 * a 249-entry list would otherwise rebuild one per render. */
const displayNamesCache = new Map<string, Intl.DisplayNames | undefined>();

function displayNames(
  locale: string | undefined,
): Intl.DisplayNames | undefined {
  const key = locale ?? '';

  if (!displayNamesCache.has(key)) {
    let instance: Intl.DisplayNames | undefined;

    try {
      instance = new Intl.DisplayNames(locale ? [locale] : undefined, {
        type: 'region',
      });
    } catch {
      // Unknown locale tag, or an environment without region display names.
      instance = undefined;
    }

    displayNamesCache.set(key, instance);
  }

  return displayNamesCache.get(key);
}

/** The country's name in `locale` (the environment's own locale by default),
 * falling back to the code itself so an unknown or legacy value still renders
 * as something. */
export function countryName(code: string, locale?: string): string {
  try {
    return displayNames(locale)?.of(code) ?? code;
  } catch {
    // `of()` throws on anything that isn't a well-formed region code.
    return code;
  }
}

export interface CountryOption {
  code: string;
  name: string;
}

const optionsCache = new Map<string, CountryOption[]>();

/** Every country, sorted by its localized name — what both the renderer's
 * `<select>` and the builder's picker iterate over. Cached per locale: a
 * form with a country field and an address field would otherwise sort 249
 * entries twice per render. */
export function countryOptions(locale?: string): CountryOption[] {
  const key = locale ?? '';
  const cached = optionsCache.get(key);

  if (cached) return cached;

  const collator = new Intl.Collator(locale);
  const options = COUNTRY_CODES.map(code => ({
    code,
    name: countryName(code, locale),
  })).sort((a, b) => collator.compare(a.name, b.name));

  optionsCache.set(key, options);

  return options;
}
