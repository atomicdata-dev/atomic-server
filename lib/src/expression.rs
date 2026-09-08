//! Values computed from a row rather than stored on it — a duration, an amount,
//! a days-since, a next-due date.
//!
//! The data-browser has shown these as *computed columns* since 2026-07-30, but
//! only in the cell: the store knew nothing about them, so a total could not sum
//! one and a filter could not narrow by one (a timer's day totals, "quantity ×
//! price summed", "overdue"). This is the same five generators, evaluated where
//! the rows live, so an aggregate or a filter can name an expression wherever it
//! can name a property.
//!
//! Deliberately still a fixed set rather than a formula language: these five
//! cover the mini-apps we build (see
//! `planning/table-templates-and-mini-apps.md`), and a formula language can wait
//! until one of them doesn't. Whatever replaces it, this is the seam it plugs
//! into.

use crate::{aggregate::value_as_number, Resource};

const DAY_MS: f64 = 86_400_000.0;

/// One side of an expression: a property to read off the row, or a fixed number
/// so a rate needs no column of its own.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum Operand {
    Property(String),
    Literal(f64),
}

impl Operand {
    /// The operand's number for this row. An instant reads as milliseconds since
    /// the epoch (a DATE included), which is what makes durations arithmetic.
    fn value(&self, resource: &Resource) -> Option<f64> {
        match self {
            Operand::Literal(number) => Some(*number),
            Operand::Property(property) => resource.get(property).ok().and_then(value_as_number),
        }
    }
}

/// A value computed from a row. The same five generators the column dialog
/// offers, in the same argument names, so one spec describes both.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Expression {
    /// `to − from`, in milliseconds: a finished duration, a lead time.
    Difference { from: Operand, to: Operand },
    /// `(until ?? now) − from`, in milliseconds. A row with a start and no end
    /// is still running, which is exactly what a timer entry is.
    Elapsed {
        from: Operand,
        #[serde(default)]
        until: Option<Operand>,
    },
    /// Whole days between `from` and now — days since last contact.
    DaysSince { from: Operand },
    /// `a × b` — quantity × price, hours × rate.
    Product { a: Operand, b: Operand },
    /// `from + days` as an instant — a next-due date from a last-done date.
    Offset { from: Operand, days: Operand },
}

impl Expression {
    /// This row's value, or `None` when an argument it needs is missing — the
    /// same "doesn't contribute" a row without a stored value gets.
    ///
    /// `now_ms` is passed in rather than read here so every row in one pass
    /// measures against the same instant, and so a caller (a browser, a test)
    /// can supply its own clock.
    pub fn evaluate(&self, resource: &Resource, now_ms: i64) -> Option<f64> {
        let now = now_ms as f64;

        match self {
            Expression::Difference { from, to } => {
                Some(to.value(resource)? - from.value(resource)?)
            }
            Expression::Elapsed { from, until } => {
                let start = from.value(resource)?;
                let end = until
                    .as_ref()
                    .and_then(|operand| operand.value(resource))
                    .unwrap_or(now);

                Some(end - start)
            }
            Expression::DaysSince { from } => {
                Some(((now - from.value(resource)?) / DAY_MS).floor())
            }
            Expression::Product { a, b } => Some(a.value(resource)? * b.value(resource)?),
            Expression::Offset { from, days } => {
                Some(from.value(resource)? + days.value(resource)? * DAY_MS)
            }
        }
    }

    /// Whether this expression can measure against the present, so its value may
    /// keep changing on its own. Such a value can never be indexed — a filter on
    /// one has to be evaluated per query.
    ///
    /// `elapsed` counts even when it names an end column: whether a *row* uses
    /// the clock depends on whether that row has an end yet, which is the whole
    /// point of it (a timer entry that is still running).
    pub fn depends_on_now(&self) -> bool {
        matches!(
            self,
            Expression::DaysSince { .. } | Expression::Elapsed { .. }
        )
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
}

impl ExpressionFilter {
    /// Whether this row satisfies the constraint.
    pub fn matches(&self, resource: &Resource) -> bool {
        use crate::storelike::FilterOperator;

        let now = self.now_ms.unwrap_or_else(crate::utils::now);

        let Some(value) = self.expression.evaluate(resource, now) else {
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
        let expression = Expression::Difference {
            from: Operand::Property(START.into()),
            to: Operand::Property(END.into()),
        };

        assert_eq!(expression.evaluate(&resource, 0), Some(60_000.0));
    }

    #[test]
    fn elapsed_runs_until_an_end_is_stamped() {
        let running = row(&[(START, Value::Timestamp(1_000))]);
        let stopped = row(&[
            (START, Value::Timestamp(1_000)),
            (END, Value::Timestamp(4_000)),
        ]);
        let expression = Expression::Elapsed {
            from: Operand::Property(START.into()),
            until: Some(Operand::Property(END.into())),
        };

        // Still running: measured against the caller's clock...
        assert_eq!(expression.evaluate(&running, 6_000), Some(5_000.0));
        // ...and once stopped, the clock is irrelevant.
        assert_eq!(expression.evaluate(&stopped, 999_999), Some(3_000.0));
        assert!(expression.depends_on_now());
    }

    #[test]
    fn a_row_missing_an_argument_has_no_value() {
        let resource = row(&[(END, Value::Timestamp(61_000))]);
        let expression = Expression::Difference {
            from: Operand::Property(START.into()),
            to: Operand::Property(END.into()),
        };

        // Not zero: a row that can't be computed must not add 0 to a sum.
        assert_eq!(expression.evaluate(&resource, 0), None);
    }

    #[test]
    fn product_multiplies_a_column_by_a_literal() {
        let resource = row(&[(QTY, Value::Integer(3))]);
        let expression = Expression::Product {
            a: Operand::Property(QTY.into()),
            b: Operand::Literal(85.0),
        };

        assert_eq!(expression.evaluate(&resource, 0), Some(255.0));
        assert!(!expression.depends_on_now());
    }

    #[test]
    fn product_multiplies_two_columns() {
        let resource = row(&[(QTY, Value::Integer(4)), (PRICE, Value::Float(0.3))]);
        let expression = Expression::Product {
            a: Operand::Property(QTY.into()),
            b: Operand::Property(PRICE.into()),
        };

        let value = expression.evaluate(&resource, 0).unwrap();
        assert!((value - 1.2).abs() < 1e-9, "4 × 0.30 is 1.20, got {value}");
    }

    #[test]
    fn days_since_counts_whole_days_and_goes_negative_for_the_future() {
        let resource = row(&[(START, Value::Timestamp(0))]);
        let expression = Expression::DaysSince {
            from: Operand::Property(START.into()),
        };

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
        let expression = Expression::Offset {
            from: Operand::Property(START.into()),
            days: Operand::Literal(7.0),
        };

        let due = expression.evaluate(&resource, 0).unwrap() as i64;
        assert_eq!(due, days_to_millis("2026-01-22"));
    }

    #[test]
    fn a_date_column_can_be_a_durations_endpoint() {
        let resource = row(&[
            (START, Value::Date("2026-01-15".into())),
            (END, Value::Date("2026-01-17".into())),
        ]);
        let expression = Expression::Difference {
            from: Operand::Property(START.into()),
            to: Operand::Property(END.into()),
        };

        assert_eq!(expression.evaluate(&resource, 0), Some(2.0 * 86_400_000.0));
    }

    #[test]
    fn the_json_shape_is_the_columns_own_kind_and_arguments() {
        let json = r#"{"kind":"elapsed","from":"https://example.com/start","until":null}"#;
        let expression: Expression = serde_json::from_str(json).unwrap();

        assert_eq!(
            expression,
            Expression::Elapsed {
                from: Operand::Property("https://example.com/start".into()),
                until: None,
            }
        );

        // A literal number and a property subject share one field, as they do in
        // the column dialog ("a fixed number" vs "a column").
        let json = r#"{"kind":"product","a":"https://example.com/qty","b":85}"#;
        let expression: Expression = serde_json::from_str(json).unwrap();
        assert_eq!(
            expression,
            Expression::Product {
                a: Operand::Property("https://example.com/qty".into()),
                b: Operand::Literal(85.0),
            }
        );
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
