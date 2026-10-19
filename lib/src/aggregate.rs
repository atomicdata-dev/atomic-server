//! Statistics computed over every row a query matches — not just the page it
//! returns.
//!
//! Aggregation happens where the data already is. The store walks its own index
//! and hands back a handful of numbers, so a client can show "sum of Amount:
//! 12.340,50" without fetching 4000 rows to add them up itself. The same code
//! runs in the browser's local database (this crate compiles to wasm), so an
//! offline table gets the same totals from the same implementation.

use crate::{values::SubResource, Resource, Value};

/// What to compute over the matching rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AggregateFunction {
    Sum,
    Count,
    Avg,
    Min,
    Max,
}

impl AggregateFunction {
    pub fn as_str(&self) -> &'static str {
        match self {
            AggregateFunction::Sum => "sum",
            AggregateFunction::Count => "count",
            AggregateFunction::Avg => "avg",
            AggregateFunction::Min => "min",
            AggregateFunction::Max => "max",
        }
    }
}

/// One requested statistic.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Aggregate {
    /// The caller's own name for this statistic, echoed on the outcome. Two
    /// statistics can otherwise be indistinguishable — a sum of one computed
    /// column and a sum of another name no property at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// The property whose values are aggregated. `count` needs none: it counts
    /// rows, and with a property set it counts the rows that have one.
    #[serde(default)]
    pub property: Option<String>,
    /// A value computed from each row instead of read off it — a duration, an
    /// amount. Takes precedence over `property` when both are given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expression: Option<crate::expression::Expression>,
    pub function: AggregateFunction,
}

/// How a date or timestamp property is bucketed for a breakdown. Grouping a
/// timestamp by its exact value gives one group per row, which is never what
/// anyone means by "per day".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GroupGranularity {
    #[default]
    Exact,
    Day,
    Month,
}

/// Break the aggregates down per distinct value of a property.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AggregateGrouping {
    pub property: String,
    #[serde(default)]
    pub granularity: GroupGranularity,
    /// Minutes to add before bucketing into a day or month, so "today" means
    /// the caller's today rather than UTC's. A client passes its own offset.
    #[serde(default)]
    pub tz_offset_minutes: i64,
    /// Most buckets to return. A breakdown by a high-cardinality property would
    /// otherwise ship a group per row — the very thing this exists to avoid.
    #[serde(default)]
    pub limit: Option<usize>,
}

/// How many buckets a breakdown returns when the caller names no limit.
pub const DEFAULT_GROUP_LIMIT: usize = 100;

/// What a query was asked to aggregate.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Aggregation {
    pub aggregates: Vec<Aggregate>,
    #[serde(default)]
    pub group_by: Option<AggregateGrouping>,
    /// The instant a computed value that measures against "now" (a running
    /// duration, a days-since) is evaluated at. The caller's clock, since the
    /// caller is the one who will read the number next to a cell it computed
    /// itself; defaults to this machine's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub now_ms: Option<i64>,
    /// Minutes east of UTC the caller's calendar days are in, so a computed value
    /// that reads a DATE or "today" agrees with the cells; see
    /// [`crate::expression::Clock`].
    #[serde(default, skip_serializing_if = "is_zero")]
    pub tz_offset_minutes: i64,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

impl Aggregation {
    pub fn is_empty(&self) -> bool {
        self.aggregates.is_empty()
    }
}

/// One bucket of a breakdown.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AggregateGroup {
    /// The bucket: a value's string form, an ISO day (`2026-07-30`) or month
    /// (`2026-07`). Empty when the row has no value for the grouping property —
    /// which is a bucket too, and a useful one ("12 expenses with no category").
    pub key: String,
    pub value: Option<f64>,
    /// Rows in this bucket that contributed a value.
    pub count: usize,
}

/// The answer to one requested statistic.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AggregateOutcome {
    /// Echoes the request's `id`, so a caller can tell two otherwise identical
    /// statistics apart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub property: Option<String>,
    pub function: AggregateFunction,
    /// Over every matching row. `None` when no row had a usable value, which is
    /// not the same answer as `0`.
    pub value: Option<f64>,
    /// Rows that contributed a value.
    pub count: usize,
    /// Per-bucket results, when a breakdown was asked for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<AggregateGroup>,
    /// True when there were more buckets than the limit allowed. Never silently
    /// truncate: a breakdown that dropped half its groups looks complete
    /// otherwise.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub groups_truncated: bool,
}

/// Reads a value as a number. Timestamps count as numbers (millis), so min/max
/// over a date column answers "earliest"/"latest"; a numeric string is parsed so
/// a text column of amounts still sums.
pub fn value_as_number(value: &Value) -> Option<f64> {
    match value {
        Value::Integer(int) => Some(*int as f64),
        Value::Float(float) => Some(*float),
        Value::Timestamp(stamp) => Some(*stamp as f64),
        Value::Boolean(bool) => Some(if *bool { 1.0 } else { 0.0 }),
        Value::String(string) | Value::Slug(string) | Value::Markdown(string) => {
            string.trim().parse::<f64>().ok()
        }
        Value::Date(date) => days_from_iso_date(date).map(|days| (days * 86_400_000) as f64),
        _ => None,
    }
}

/// The bucket a row falls into, given the grouping. `None` means the row has no
/// value at all for the property, which the caller renders as its own group.
pub fn group_key(resource: &Resource, grouping: &AggregateGrouping) -> Option<String> {
    let value = resource.get(&grouping.property).ok()?;

    match value {
        // A select column stores tag subjects. The first one is the row's
        // group; a multi-tag row would otherwise have to count more than once,
        // and then the groups no longer add up to the total.
        Value::ResourceArray(items) => items.first().map(|item| match item {
            SubResource::Subject(subject) => subject.to_string(),
            SubResource::Nested(_) => String::new(),
        }),
        Value::Timestamp(stamp) => Some(bucket_instant(
            *stamp,
            grouping.granularity,
            grouping.tz_offset_minutes,
        )),
        Value::Date(date) => Some(match grouping.granularity {
            GroupGranularity::Month => date.get(0..7).unwrap_or(date).to_string(),
            // A DATE has no time of day, so it is already its own day and the
            // timezone offset must not shift it.
            _ => date.to_string(),
        }),
        other => Some(other.to_string()),
    }
}

/// Buckets an instant (millis since the epoch) into an ISO day or month in the
/// caller's timezone.
fn bucket_instant(millis: i64, granularity: GroupGranularity, tz_offset_minutes: i64) -> String {
    if granularity == GroupGranularity::Exact {
        return millis.to_string();
    }

    let shifted = millis + tz_offset_minutes * 60_000;
    // Floor division: instants before 1970 must round down, not toward zero.
    let days = shifted.div_euclid(86_400_000);
    let (year, month, day) = civil_from_days(days);

    match granularity {
        GroupGranularity::Month => format!("{year:04}-{month:02}"),
        _ => format!("{year:04}-{month:02}-{day:02}"),
    }
}

/// Days since the epoch → calendar date. Howard Hinnant's `civil_from_days`;
/// this crate compiles to wasm, so it carries no date dependency of its own.
pub(crate) fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;

    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `YYYY-MM-DD` → days since the epoch. Anything else is not a date.
fn days_from_iso_date(date: &str) -> Option<i64> {
    let mut parts = date.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.get(0..2).unwrap_or("").parse().ok()?;

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    Some(days_from_civil(year, month, day))
}

/// Calendar date → days since the epoch (the inverse of `civil_from_days`).
pub(crate) fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;

    era * 146_097 + doe - 719_468
}

/// Accumulates one function's running state as rows are scanned.
#[derive(Debug, Default, Clone)]
pub struct Accumulator {
    sum: f64,
    min: Option<f64>,
    max: Option<f64>,
    /// Rows that contributed a value.
    pub count: usize,
}

impl Accumulator {
    pub fn add(&mut self, number: f64) {
        self.sum += number;
        self.count += 1;
        self.min = Some(self.min.map_or(number, |min| min.min(number)));
        self.max = Some(self.max.map_or(number, |max| max.max(number)));
    }

    /// Counts a row without contributing a value — what `count` is made of.
    /// Rows with no usable number must NOT come through here for the other
    /// functions, or `count` stops meaning "rows that contributed" and a sum
    /// starts reporting a denominator it never used.
    pub fn count_row(&mut self) {
        self.count += 1;
    }

    pub fn finish(&self, function: AggregateFunction) -> Option<f64> {
        match function {
            AggregateFunction::Count => Some(self.count as f64),
            _ if self.count == 0 => None,
            AggregateFunction::Sum => Some(self.sum),
            AggregateFunction::Avg => Some(self.sum / self.count as f64),
            AggregateFunction::Min => self.min,
            AggregateFunction::Max => self.max,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn buckets_instants_in_the_callers_timezone() {
        // 2026-07-30T23:30:00Z is already the 31st in Amsterdam (+120).
        let stamp = 1_785_454_200_000;
        assert_eq!(
            bucket_instant(stamp, GroupGranularity::Day, 0),
            "2026-07-30"
        );
        assert_eq!(
            bucket_instant(stamp, GroupGranularity::Day, 120),
            "2026-07-31"
        );
        assert_eq!(
            bucket_instant(stamp, GroupGranularity::Month, 120),
            "2026-07"
        );
        // And an hour later in a western timezone it is still the 30th.
        assert_eq!(
            bucket_instant(stamp, GroupGranularity::Day, -300),
            "2026-07-30"
        );
    }

    #[test]
    fn buckets_instants_before_the_epoch() {
        // -1 ms is 1969-12-31, not 1970-01-01: the floor must round down.
        assert_eq!(bucket_instant(-1, GroupGranularity::Day, 0), "1969-12-31");
    }

    #[test]
    fn civil_days_round_trip() {
        for (year, month, day) in [
            (1970, 1, 1),
            (2000, 2, 29),
            (2026, 7, 30),
            (1969, 12, 31),
            (2100, 3, 1),
        ] {
            let days = days_from_civil(year, month, day);
            assert_eq!(civil_from_days(days), (year, month as u32, day as u32));
        }
    }

    #[test]
    fn reads_numbers_out_of_the_values_that_have_them() {
        assert_eq!(value_as_number(&Value::Integer(7)), Some(7.0));
        assert_eq!(value_as_number(&Value::Float(2.5)), Some(2.5));
        assert_eq!(value_as_number(&Value::Timestamp(1000)), Some(1000.0));
        assert_eq!(value_as_number(&Value::String(" 12.5 ".into())), Some(12.5));
        assert_eq!(value_as_number(&Value::String("n/a".into())), None);
        assert_eq!(
            value_as_number(&Value::Date("1970-01-02".into())),
            Some(86_400_000.0)
        );
    }

    #[test]
    fn an_empty_accumulator_has_no_value_but_still_counts_zero() {
        let acc = Accumulator::default();
        assert_eq!(acc.finish(AggregateFunction::Sum), None);
        assert_eq!(acc.finish(AggregateFunction::Avg), None);
        // Count is the one function that answers for an empty set.
        assert_eq!(acc.finish(AggregateFunction::Count), Some(0.0));
    }

    #[test]
    fn accumulates_each_function() {
        let mut acc = Accumulator::default();

        for number in [4.0, 8.0, 3.0] {
            acc.add(number);
        }

        assert_eq!(acc.finish(AggregateFunction::Sum), Some(15.0));
        assert_eq!(acc.finish(AggregateFunction::Avg), Some(5.0));
        assert_eq!(acc.finish(AggregateFunction::Min), Some(3.0));
        assert_eq!(acc.finish(AggregateFunction::Max), Some(8.0));
        assert_eq!(acc.finish(AggregateFunction::Count), Some(3.0));
    }

    #[test]
    fn counting_rows_needs_no_values() {
        // An accumulator serves ONE function, so `count_row` and `add` never
        // mix: counting a row is all a `count` aggregate ever does.
        let mut acc = Accumulator::default();
        acc.count_row();
        acc.count_row();

        assert_eq!(acc.finish(AggregateFunction::Count), Some(2.0));
    }
}
