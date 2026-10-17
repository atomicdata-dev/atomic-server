//! Values computed from a row rather than stored on it: a duration, an amount,
//! a days-since, a next-due date, "birthday within two weeks".
//!
//! The data-browser shows these as *computed columns*, but the store has to know
//! them too, so a total can sum one and a filter can narrow by one. An
//! [`Expression`] is a formula (parsed and evaluated by the `evalexpr` crate; we
//! have no parser of our own) plus a `vars` map binding the identifiers the
//! formula uses to property subjects:
//!
//! ```json
//! {"kind":"formula","formula":"coalesce(until, now()) - start",
//!  "vars":{"start":"https://…/start","until":"https://…/until"}}
//! ```
//!
//! Every variable is read as a number with [`value_as_number`] (a DATE is
//! midnight UTC in milliseconds). A property the row lacks is an *empty* value,
//! not an error, and any arithmetic on it makes the whole expression `None`: the
//! row contributes nothing, as a row without a stored value does. `coalesce`
//! is how a formula opts into a default. Variables are floats, but integer
//! literals stay integers, so write `1.0 / 2` rather than `1 / 2`.
//!
//! Functions on top of evalexpr's builtins: `now()`, `coalesce(a, b, ..)`,
//! `days(ms)` (whole days, floored), `addDays(ms, n)` and
//! `daysUntilAnniversary(date_ms)` (UTC; a Feb 29 date falls on Mar 1 in
//! non-leap years). The five original fixed kinds (`difference`, `elapsed`,
//! `daysSince`, `product`, `offset`) still deserialize, into the equivalent
//! formula, so stored Views keep working; see [`ExpressionSpec`].

use std::collections::BTreeMap;

use evalexpr::{
    ContextWithMutableFunctions, ContextWithMutableVariables, DefaultNumericTypes, EvalexprError,
    Function, HashMapContext, Node, Value as EvalValue,
};

use crate::{
    aggregate::{civil_from_days, days_from_civil, value_as_number},
    Resource,
};

const DAY_MS: f64 = 86_400_000.0;

type Num = DefaultNumericTypes;

/// One side of a legacy expression: a property to read off the row, or a fixed
/// number so a rate needs no column of its own.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum Operand {
    Property(String),
    Literal(f64),
}

/// The wire form of an [`Expression`]: the formula, or one of the five fixed
/// kinds it replaced, which convert to a formula.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ExpressionSpec {
    Formula {
        formula: String,
        #[serde(default)]
        vars: BTreeMap<String, String>,
    },
    /// `to - from`
    Difference { from: Operand, to: Operand },
    /// `(until ?? now) - from`
    Elapsed {
        from: Operand,
        #[serde(default)]
        until: Option<Operand>,
    },
    /// Whole days between `from` and now, floored.
    DaysSince { from: Operand },
    /// `a * b`
    Product { a: Operand, b: Operand },
    /// `from + days` days
    Offset { from: Operand, days: Operand },
}

/// A value computed from a row. Always a formula plus its variable bindings.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(from = "ExpressionSpec", into = "ExpressionSpec")]
pub struct Expression {
    pub formula: String,
    /// Identifier used in the formula → property subject.
    pub vars: BTreeMap<String, String>,
}

impl From<Expression> for ExpressionSpec {
    fn from(e: Expression) -> Self {
        ExpressionSpec::Formula {
            formula: e.formula,
            vars: e.vars,
        }
    }
}

impl From<ExpressionSpec> for Expression {
    fn from(spec: ExpressionSpec) -> Self {
        let mut vars = BTreeMap::new();
        // Operands become `v0`, `v1`…, or a literal in the formula text.
        let mut operand = |op: Operand| match op {
            Operand::Literal(number) => format!("({number:?})"),
            Operand::Property(property) => {
                let name = format!("v{}", vars.len());
                vars.insert(name.clone(), property);
                name
            }
        };
        let formula = match spec {
            ExpressionSpec::Formula { formula, vars } => return Expression { formula, vars },
            ExpressionSpec::Difference { from, to } => {
                let (from, to) = (operand(from), operand(to));
                format!("{to} - {from}")
            }
            ExpressionSpec::Elapsed { from, until } => {
                let from = operand(from);
                match until {
                    Some(until) => format!("coalesce({}, now()) - {from}", operand(until)),
                    None => format!("now() - {from}"),
                }
            }
            ExpressionSpec::DaysSince { from } => format!("days(now() - {})", operand(from)),
            ExpressionSpec::Product { a, b } => {
                let (a, b) = (operand(a), operand(b));
                format!("{a} * {b}")
            }
            ExpressionSpec::Offset { from, days } => {
                let (from, days) = (operand(from), operand(days));
                format!("{from} + {days} * {DAY_MS:?}")
            }
        };

        Expression { formula, vars }
    }
}

type Context = HashMapContext<Num>;

/// A formula parsed once, to evaluate against many rows at one instant.
pub struct Compiled {
    tree: Node<Num>,
    vars: Vec<(String, String)>,
    base: Context,
    tz_ms: f64,
}

/// A function over numbers. An empty argument makes the result empty.
fn numeric(
    arity: usize,
    f: impl Fn(&[f64]) -> f64 + Clone + Send + Sync + 'static,
) -> Function<Num> {
    Function::new(move |argument| {
        let args: Vec<&EvalValue<Num>> = match argument {
            EvalValue::Tuple(items) => items.iter().collect(),
            single => vec![single],
        };
        if args.len() != arity {
            return Err(EvalexprError::CustomMessage(format!(
                "expected {arity} arguments, got {}",
                args.len()
            )));
        }
        let mut numbers = Vec::with_capacity(arity);
        for arg in args {
            match arg {
                EvalValue::Empty => return Ok(EvalValue::Empty),
                EvalValue::Int(i) => numbers.push(*i as f64),
                EvalValue::Float(f) => numbers.push(*f),
                EvalValue::Boolean(b) => numbers.push(f64::from(*b)),
                other => return Err(EvalexprError::expected_number(other.clone())),
            }
        }
        Ok(EvalValue::Float(f(&numbers)))
    })
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Whole days from today to the next occurrence of `date_ms`'s month and day;
/// 0 when that is today. Days are the caller's: both the date and today are
/// placed in the zone `tz_ms` east of UTC, so a birthday does not move a day when
/// the clock passes UTC midnight.
fn days_until_anniversary(date_ms: f64, now_ms: f64, tz_ms: f64) -> f64 {
    let today = ((now_ms + tz_ms) / DAY_MS).floor() as i64;
    let (_, month, day) = civil_from_days(((date_ms + tz_ms) / DAY_MS).floor() as i64);
    let (year, _, _) = civil_from_days(today);
    let on = |y: i64| match (month, day) {
        (2, 29) if !is_leap(y) => days_from_civil(y, 3, 1),
        _ => days_from_civil(y, i64::from(month), i64::from(day)),
    };
    let mut next = on(year);

    if next < today {
        next = on(year + 1);
    }

    (next - today) as f64
}

/// The caller's clock: the instant "now" is, and the zone its calendar days are
/// in. A DATE has no zone; it is read as midnight in this one, so "today" and a
/// date stamped today agree on what day it is. A bare instant is UTC.
#[derive(Debug, Clone, Copy)]
pub struct Clock {
    pub now_ms: i64,
    /// Minutes east of UTC, as `-new Date().getTimezoneOffset()` gives them.
    pub tz_offset_minutes: i64,
}

impl From<i64> for Clock {
    fn from(now_ms: i64) -> Self {
        Self {
            now_ms,
            tz_offset_minutes: 0,
        }
    }
}

fn base_context(clock: Clock) -> Context {
    let now = clock.now_ms as f64;
    let tz_ms = (clock.tz_offset_minutes * 60_000) as f64;
    let mut ctx = Context::new();
    let mut set = |name: &str, function: Function<Num>| {
        ctx.set_function(name.to_string(), function)
            .expect("functions can be set on a HashMapContext")
    };

    set("now", Function::new(move |_| Ok(EvalValue::Float(now))));
    set(
        "coalesce",
        Function::new(|argument| {
            Ok(match argument {
                EvalValue::Tuple(items) => items
                    .iter()
                    .find(|item| !matches!(item, EvalValue::Empty))
                    .cloned()
                    .unwrap_or(EvalValue::Empty),
                single => single.clone(),
            })
        }),
    );
    set("days", numeric(1, |a| (a[0] / DAY_MS).floor()));
    set("addDays", numeric(2, |a| a[0] + a[1] * DAY_MS));
    set(
        "daysUntilAnniversary",
        numeric(1, move |a| days_until_anniversary(a[0], now, tz_ms)),
    );

    ctx
}

impl Compiled {
    /// A stored value as a number, with a DATE placed at midnight in the clock's
    /// zone rather than in UTC.
    pub fn instant(&self, value: &crate::Value) -> Option<f64> {
        let number = value_as_number(value)?;

        Some(match value {
            crate::Value::Date(_) => number - self.tz_ms,
            _ => number,
        })
    }

    /// This row's value; `get` reads a property subject as a number. `None` for
    /// a missing input, an evaluation error, or a non-numeric result.
    pub fn evaluate(&self, get: &dyn Fn(&str) -> Option<f64>) -> Option<f64> {
        // A fresh context per row: evalexpr refuses to change a variable's type,
        // and a variable is `Empty` on one row and a float on the next.
        let mut ctx = self.base.clone();

        for (name, property) in &self.vars {
            let value = get(property).map_or(EvalValue::Empty, EvalValue::Float);
            ctx.set_value(name.clone(), value).ok()?;
        }

        let number = match self.tree.eval_with_context(&ctx).ok()? {
            EvalValue::Int(i) => i as f64,
            EvalValue::Float(f) => f,
            EvalValue::Boolean(b) => f64::from(b),
            _ => return None,
        };

        number.is_finite().then_some(number)
    }
}

impl Expression {
    /// Parse the formula for repeated evaluation at `clock` (a bare `now_ms` is
    /// UTC).
    pub fn compile(&self, clock: impl Into<Clock>) -> Result<Compiled, String> {
        let clock = clock.into();
        let tree =
            evalexpr::build_operator_tree::<Num>(&self.formula).map_err(|e| e.to_string())?;

        Ok(Compiled {
            tree,
            vars: self
                .vars
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            base: base_context(clock),
            tz_ms: (clock.tz_offset_minutes * 60_000) as f64,
        })
    }

    /// Evaluate with `get` standing in for the row: the one path both a stored
    /// [`Resource`] and a plain map of values (the browser's cells) go through.
    pub fn evaluate_with(
        &self,
        clock: impl Into<Clock>,
        get: &dyn Fn(&str) -> Option<f64>,
    ) -> Option<f64> {
        self.compile(clock).ok()?.evaluate(get)
    }

    /// This row's value, or `None` when an input it needs is missing — the same
    /// "doesn't contribute" a row without a stored value gets.
    ///
    /// `now_ms` is passed in rather than read here so every row in one pass
    /// measures against the same instant, and so a caller (a browser, a test)
    /// can supply its own clock.
    pub fn evaluate(&self, resource: &Resource, clock: impl Into<Clock>) -> Option<f64> {
        let compiled = self.compile(clock).ok()?;

        compiled.evaluate(&|p| {
            resource
                .get(p)
                .ok()
                .and_then(|value| compiled.instant(value))
        })
    }

    /// Whether this expression can measure against the present, so its value may
    /// keep changing on its own. Such a value can never be indexed — a filter on
    /// one has to be evaluated per query.
    ///
    /// `elapsed` counts even when it names an end column: whether a *row* uses
    /// the clock depends on whether that row has an end yet, which is the whole
    /// point of it (a timer entry that is still running).
    pub fn depends_on_now(&self) -> bool {
        let compact: String = self.formula.split_whitespace().collect();
        compact.contains("now(") || compact.contains("daysUntilAnniversary(")
    }

    /// Checks that the formula parses and uses only declared variables and known
    /// functions, with a message fit to show the person who wrote it.
    pub fn validate(&self) -> Result<(), String> {
        let tree =
            evalexpr::build_operator_tree::<Num>(&self.formula).map_err(|e| e.to_string())?;
        let probe = base_context(0.into());

        for name in tree.iter_variable_identifiers() {
            if !self.vars.contains_key(name) {
                return Err(format!(
                    "Unknown name `{name}`: it is not one of the columns"
                ));
            }
        }

        for name in self.vars.keys() {
            let valid = !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                && !name.starts_with(|c: char| c.is_ascii_digit());
            if !valid {
                return Err(format!(
                    "`{name}` is not a valid column name (use a-z, 0-9, _)"
                ));
            }
        }

        // evalexpr accepts some incomplete input (`a +`) at parse time and finds
        // unknown functions only when calling them, so run it once with every
        // column at 1.
        let mut ctx = probe;
        for name in self.vars.keys() {
            ctx.set_value(name.clone(), EvalValue::Float(1.0))
                .map_err(|e| e.to_string())?;
        }
        tree.eval_with_context(&ctx).map_err(|e| e.to_string())?;

        Ok(())
    }
}

/// A constraint on a computed value: "logged more than an hour", "overdue by at
/// least a day".
///
/// The comparison is numeric, against the expression's own unit — milliseconds
/// for a duration, days for a days-since, an instant for a next-due date. A row
/// whose value can't be computed never matches: "overdue" is not a claim you can
/// make about a plant with no last-watered date.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExpressionFilter {
    pub expression: Expression,
    #[serde(default)]
    pub operator: crate::storelike::FilterOperator,
    pub value: f64,
    /// The instant to measure "now" against, for the expressions that do. Set by
    /// the caller so a filter agrees with the cells it is filtering; every filter
    /// in one query should carry the same one.
    #[serde(default)]
    pub now_ms: Option<i64>,
    /// Minutes east of UTC the caller's calendar days are in; see [`Clock`].
    #[serde(default)]
    pub tz_offset_minutes: i64,
}

impl ExpressionFilter {
    /// Whether this row satisfies the constraint.
    pub fn matches(&self, resource: &Resource) -> bool {
        use crate::storelike::FilterOperator;

        let clock = Clock {
            now_ms: self.now_ms.unwrap_or_else(crate::utils::now),
            tz_offset_minutes: self.tz_offset_minutes,
        };

        let Some(value) = self.expression.evaluate(resource, clock) else {
            return false;
        };

        match self.operator {
            FilterOperator::GreaterThan => value > self.value,
            FilterOperator::GreaterThanOrEqual => value >= self.value,
            FilterOperator::LessThan => value < self.value,
            FilterOperator::LessThanOrEqual => value <= self.value,
            // Equality on a float is a trap, and a duration in milliseconds is
            // never typed exactly: treat it as "the same to the unit given".
            FilterOperator::Equal => (value - self.value).abs() < 1.0,
            // String operators mean nothing here. Matching everything would
            // silently widen a view the user thought they had narrowed.
            FilterOperator::StartsWith | FilterOperator::Contains => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{urls, Value};

    #[test]
    fn expression_filter_accepts_browser_operator_names() {
        use crate::storelike::FilterOperator;
        for (wire, expected) in [
            ("eq", FilterOperator::Equal),
            ("gt", FilterOperator::GreaterThan),
            ("gte", FilterOperator::GreaterThanOrEqual),
            ("lt", FilterOperator::LessThan),
            ("lte", FilterOperator::LessThanOrEqual),
        ] {
            let filter: ExpressionFilter = serde_json::from_value(serde_json::json!({
                "expression": {"kind": "difference", "from": START, "to": END},
                "operator": wire,
                "value": 1000
            }))
            .unwrap();
            assert_eq!(filter.operator, expected);
        }
    }

    /// A row with the given values, keyed by throwaway property subjects.
    fn row(values: &[(&str, Value)]) -> Resource {
        let mut resource = Resource::new("https://example.com/row".into());

        for (property, value) in values {
            resource
                .set_unsafe((*property).to_string(), value.clone())
                .unwrap();
        }

        resource
    }

    const START: &str = "https://example.com/start";
    const END: &str = "https://example.com/end";
    const QTY: &str = "https://example.com/qty";
    const PRICE: &str = "https://example.com/price";

    #[test]
    fn difference_is_the_span_between_two_instants() {
        let resource = row(&[
            (START, Value::Timestamp(1_000)),
            (END, Value::Timestamp(61_000)),
        ]);
        let expression = Expression::from(ExpressionSpec::Difference {
            from: Operand::Property(START.into()),
            to: Operand::Property(END.into()),
        });

        assert_eq!(expression.evaluate(&resource, 0), Some(60_000.0));
    }

    #[test]
    fn elapsed_runs_until_an_end_is_stamped() {
        let running = row(&[(START, Value::Timestamp(1_000))]);
        let stopped = row(&[
            (START, Value::Timestamp(1_000)),
            (END, Value::Timestamp(4_000)),
        ]);
        let expression = Expression::from(ExpressionSpec::Elapsed {
            from: Operand::Property(START.into()),
            until: Some(Operand::Property(END.into())),
        });

        // Still running: measured against the caller's clock...
        assert_eq!(expression.evaluate(&running, 6_000), Some(5_000.0));
        // ...and once stopped, the clock is irrelevant.
        assert_eq!(expression.evaluate(&stopped, 999_999), Some(3_000.0));
        assert!(expression.depends_on_now());
    }

    #[test]
    fn a_row_missing_an_argument_has_no_value() {
        let resource = row(&[(END, Value::Timestamp(61_000))]);
        let expression = Expression::from(ExpressionSpec::Difference {
            from: Operand::Property(START.into()),
            to: Operand::Property(END.into()),
        });

        // Not zero: a row that can't be computed must not add 0 to a sum.
        assert_eq!(expression.evaluate(&resource, 0), None);
    }

    #[test]
    fn product_multiplies_a_column_by_a_literal() {
        let resource = row(&[(QTY, Value::Integer(3))]);
        let expression = Expression::from(ExpressionSpec::Product {
            a: Operand::Property(QTY.into()),
            b: Operand::Literal(85.0),
        });

        assert_eq!(expression.evaluate(&resource, 0), Some(255.0));
        assert!(!expression.depends_on_now());
    }

    #[test]
    fn product_multiplies_two_columns() {
        let resource = row(&[(QTY, Value::Integer(4)), (PRICE, Value::Float(0.3))]);
        let expression = Expression::from(ExpressionSpec::Product {
            a: Operand::Property(QTY.into()),
            b: Operand::Property(PRICE.into()),
        });

        let value = expression.evaluate(&resource, 0).unwrap();
        assert!((value - 1.2).abs() < 1e-9, "4 × 0.30 is 1.20, got {value}");
    }

    #[test]
    fn days_since_counts_whole_days_and_goes_negative_for_the_future() {
        let resource = row(&[(START, Value::Timestamp(0))]);
        let expression = Expression::from(ExpressionSpec::DaysSince {
            from: Operand::Property(START.into()),
        });

        assert_eq!(
            expression.evaluate(&resource, 86_400_000 * 3 + 5_000),
            Some(3.0)
        );
        // A date in the future is "-1 days since", not 0: `floor`, never trunc.
        assert_eq!(expression.evaluate(&resource, -1_000), Some(-1.0));
        assert!(expression.depends_on_now());
    }

    #[test]
    fn offset_shifts_a_date_by_days() {
        // A DATE has no time of day, so it reads as midnight UTC.
        let resource = row(&[(START, Value::Date("2026-01-15".into()))]);
        let expression = Expression::from(ExpressionSpec::Offset {
            from: Operand::Property(START.into()),
            days: Operand::Literal(7.0),
        });

        let due = expression.evaluate(&resource, 0).unwrap() as i64;
        assert_eq!(due, days_to_millis("2026-01-22"));
    }

    #[test]
    fn a_date_column_can_be_a_durations_endpoint() {
        let resource = row(&[
            (START, Value::Date("2026-01-15".into())),
            (END, Value::Date("2026-01-17".into())),
        ]);
        let expression = Expression::from(ExpressionSpec::Difference {
            from: Operand::Property(START.into()),
            to: Operand::Property(END.into()),
        });

        assert_eq!(expression.evaluate(&resource, 0), Some(2.0 * 86_400_000.0));
    }

    #[test]
    fn legacy_shapes_convert_to_formulas() {
        let json = r#"{"kind":"elapsed","from":"https://example.com/start","until":null}"#;
        let expression: Expression = serde_json::from_str(json).unwrap();
        assert_eq!(expression.formula, "now() - v0");
        assert_eq!(expression.vars["v0"], START);

        // A literal number and a property subject share one field.
        let json = r#"{"kind":"product","a":"https://example.com/qty","b":85}"#;
        let expression: Expression = serde_json::from_str(json).unwrap();
        assert_eq!(expression.formula, "v0 * (85.0)");
        assert!(expression.validate().is_ok());
    }

    #[test]
    fn the_formula_shape_roundtrips() {
        let json = serde_json::json!({
            "kind": "formula",
            "formula": "coalesce(until, now()) - start",
            "vars": {"start": START, "until": END},
        });
        let expression: Expression = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(&expression).unwrap(), json);
        assert!(expression.validate().is_ok());
        assert!(expression.depends_on_now());
    }

    fn formula(formula: &str, vars: &[(&str, &str)]) -> Expression {
        Expression {
            formula: formula.into(),
            vars: vars
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    fn day_ms(y: i64, m: i64, d: i64) -> i64 {
        crate::aggregate::days_from_civil(y, m, d) * 86_400_000
    }

    #[test]
    fn coalesce_defaults_a_missing_end_to_now() {
        let expression = formula(
            "coalesce(until, now()) - start",
            &[("start", START), ("until", END)],
        );
        let running = row(&[(START, Value::Timestamp(1_000))]);
        assert_eq!(expression.evaluate(&running, 6_000), Some(5_000.0));
        assert_eq!(expression.evaluate(&row(&[]), 6_000), None);
    }

    #[test]
    fn birthdays_within_two_weeks() {
        let expression = formula("daysUntilAnniversary(birth) <= 14", &[("birth", START)]);
        let dec28 = row(&[(START, Value::Timestamp(day_ms(1990, 12, 28)))]);
        let jan5 = row(&[(START, Value::Timestamp(day_ms(1985, 1, 5)))]);
        let dec20 = day_ms(2026, 12, 20) + 5_000;

        // Dec 28 is 8 days after Dec 20; Jan 5 is 16 days after it (year wrap).
        assert_eq!(expression.evaluate(&dec28, dec20), Some(1.0));
        assert_eq!(expression.evaluate(&jan5, dec20), Some(0.0));
        let days = formula("daysUntilAnniversary(birth)", &[("birth", START)]);
        assert_eq!(days.evaluate(&dec28, dec20), Some(8.0));
        assert_eq!(days.evaluate(&jan5, dec20), Some(16.0));
        // Today is 0; the day after it is almost a year away.
        assert_eq!(days.evaluate(&dec28, day_ms(2026, 12, 28)), Some(0.0));
        assert_eq!(days.evaluate(&dec28, day_ms(2026, 12, 29)), Some(364.0));
        assert_eq!(days.evaluate(&row(&[]), dec20), None);
    }

    #[test]
    fn days_are_the_callers_not_utcs() {
        // Dec 28 00:30 in UTC+2 is still Dec 27 22:30 in UTC.
        let east = Clock {
            now_ms: day_ms(2026, 12, 27) + 22 * 3_600_000 + 30 * 60_000,
            tz_offset_minutes: 120,
        };
        let days = formula("daysUntilAnniversary(birth)", &[("birth", START)]);
        let date = row(&[(START, Value::Date("1990-12-28".into()))]);
        let late_utc = row(&[(
            START,
            Value::Timestamp(day_ms(1990, 12, 28) + 14 * 3_600_000),
        )]);

        // Today is Dec 28 there: a DATE birthday is today (the UTC reading says 1).
        assert_eq!(days.evaluate(&date, east), Some(0.0));
        assert_eq!(days.evaluate(&date, east.now_ms), Some(1.0));
        // A timestamp at 14:00 UTC is Dec 28 16:00 there, and 14:00 UTC is still
        // Dec 28 in UTC: floor, not round, so it is the same day both ways.
        assert_eq!(days.evaluate(&late_utc, east), Some(0.0));
        assert_eq!(days.evaluate(&late_utc, day_ms(2026, 12, 20)), Some(8.0));

        // A date stamped today is not "in a day" at 00:30 local.
        let since = formula("days(now() - d)", &[("d", START)]);
        assert_eq!(since.evaluate(&date_today_east(), east), Some(0.0));
    }

    /// 2026-12-28 as a DATE, read in UTC+2.
    fn date_today_east() -> Resource {
        row(&[(START, Value::Date("2026-12-28".into()))])
    }

    #[test]
    fn a_leap_day_falls_on_march_first_in_other_years() {
        let days = formula("daysUntilAnniversary(birth)", &[("birth", START)]);
        let leap = row(&[(START, Value::Timestamp(day_ms(2000, 2, 29)))]);

        assert_eq!(days.evaluate(&leap, day_ms(2027, 2, 20)), Some(9.0));
        assert_eq!(days.evaluate(&leap, day_ms(2028, 2, 20)), Some(9.0));
        // After Mar 1, the next one is the real Feb 29 in 2028.
        assert_eq!(days.evaluate(&leap, day_ms(2027, 3, 2)), Some(364.0));
    }

    #[test]
    fn validate_names_what_is_wrong() {
        let unknown = formula("nope + 1", &[("start", START)]);
        assert!(unknown.validate().unwrap_err().contains("nope"));
        let function = formula("frobnicate(start)", &[("start", START)]);
        assert!(function.validate().unwrap_err().contains("frobnicate"));
        assert!(formula("start +", &[("start", START)]).validate().is_err());
        let r = formula("min(start, 3.0) + days(start)", &[("start", START)]).validate();
        assert!(r.is_ok(), "{r:?}");
    }

    #[test]
    fn an_unknown_kind_is_rejected_rather_than_guessed() {
        let json = r#"{"kind":"regression","from":"x"}"#;
        assert!(serde_json::from_str::<Expression>(json).is_err());
        // Sanity: the property URL constant is a real one, so this test file
        // fails loudly if `urls` ever stops exporting it.
        assert!(!urls::DESCRIPTION.is_empty());
    }

    fn days_to_millis(date: &str) -> i64 {
        let value = Value::Date(date.into());
        value_as_number(&value).unwrap() as i64
    }
}
