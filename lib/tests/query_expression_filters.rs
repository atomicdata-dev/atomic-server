//! A query can narrow by a value it *computes* per row — "logged more than an
//! hour", "overdue", "worth more than 50" — not only by values stored on it.
//!
//! Such a constraint can't come from the query index (a running duration has no
//! stable value to key by), so it is evaluated over the set the index narrows to.
//! What must hold anyway: the page, the count and any totals all describe the
//! same, filtered set.
//! Run: cargo test -p atomic_lib --features db-redb --test query_expression_filters
#![cfg(feature = "db-redb")]

use atomic_lib::{
    agents::ForAgent,
    aggregate::{Aggregate, AggregateFunction, Aggregation},
    expression::{Expression, ExpressionFilter, ExpressionSpec, Operand},
    storelike::{FilterOperator, Query},
    urls, Db, Storelike, Subject, Value,
};

/// Stands in for a "start" column, and `FILESIZE` for an "end" column: any two
/// numeric properties every store already has will do.
const START: &str = urls::CREATED_AT;
const END: &str = urls::FILESIZE;

fn query_for(table: &str) -> Query {
    Query {
        property: Some(urls::PARENT.into()),
        value: Some(Value::AtomicUrl(table.to_string().into())),
        filters: Vec::new(),
        expression_filters: Vec::new(),
        limit: None,
        start_val: None,
        end_val: None,
        offset: 0,
        sort_by: Some(urls::SORT_ORDER.into()),
        sort_desc: false,
        include_external: false,
        exclude_trashed: false,
        include_nested: false,
        for_agent: ForAgent::Sudo,
        drive: Some(atomic_lib::db::drive_prefix_from_subject(&Subject::from(
            table.to_string(),
        ))),
        aggregation: None,
    }
}

/// A duration column: `end − start`.
fn duration() -> Expression {
    Expression::from(ExpressionSpec::Difference {
        from: Operand::Property(START.into()),
        to: Operand::Property(END.into()),
    })
}

const MINUTE: i64 = 60_000;

/// Four entries of 1, 30, 90 and 120 minutes, plus one that never ended.
async fn entries_table(store: &Db, drive: &str) -> String {
    let table = store
        .create_resource(urls::FOLDER, drive, "Time entries", None)
        .await
        .unwrap();

    for minutes in [1, 30, 90, 120] {
        store
            .create_resource(
                urls::FOLDER,
                &table,
                &format!("{minutes} minutes"),
                Some(vec![
                    (START, Value::Timestamp(0)),
                    (END, Value::Timestamp(minutes * MINUTE)),
                ]),
            )
            .await
            .unwrap();
    }

    store
        .create_resource(
            urls::FOLDER,
            &table,
            "Never ended",
            Some(vec![(START, Value::Timestamp(0))]),
        )
        .await
        .unwrap();

    table
}

#[tokio::test]
async fn a_constraint_on_a_computed_value_narrows_the_rows() {
    let store = Db::init_temp("expression_filter_rows").await.unwrap();
    let (_agent, drive) = store.setup("Alice").await.unwrap();
    let table = entries_table(&store, &drive).await;

    let mut query = query_for(&table);
    query.expression_filters = vec![ExpressionFilter {
        expression: duration(),
        operator: FilterOperator::GreaterThan,
        value: (60 * MINUTE) as f64,
        now_ms: None,
    }];

    let result = store.query(&query).await.unwrap();

    assert_eq!(
        result.subjects.len(),
        2,
        "only the 90- and 120-minute entries are longer than an hour"
    );
    assert_eq!(
        result.count, 2,
        "the count is what matched, not what the index hit"
    );

    // The row that never ended has no duration at all, so it satisfies nothing —
    // not "longer than an hour", and not "shorter than an hour" either.
    let mut shorter = query_for(&table);
    shorter.expression_filters = vec![ExpressionFilter {
        expression: duration(),
        operator: FilterOperator::LessThan,
        value: (60 * MINUTE) as f64,
        now_ms: None,
    }];

    let result = store.query(&shorter).await.unwrap();
    assert_eq!(
        result.subjects.len(),
        2,
        "the 1- and 30-minute entries; the unfinished one is in neither answer"
    );
}

#[tokio::test]
async fn paging_happens_after_the_constraint() {
    let store = Db::init_temp("expression_filter_paging").await.unwrap();
    let (_agent, drive) = store.setup("Alice").await.unwrap();
    let table = entries_table(&store, &drive).await;

    let mut query = query_for(&table);
    query.expression_filters = vec![ExpressionFilter {
        expression: duration(),
        operator: FilterOperator::GreaterThanOrEqual,
        value: (30 * MINUTE) as f64,
        now_ms: None,
    }];
    query.limit = Some(1);

    let result = store.query(&query).await.unwrap();

    assert_eq!(result.subjects.len(), 1, "one row was asked for");
    assert_eq!(
        result.count, 3,
        "the count still describes every matching row — 30, 90 and 120 minutes"
    );

    // The second page is the second *matching* row, not the second index hit.
    query.offset = 1;
    let second = store.query(&query).await.unwrap();
    assert_eq!(second.count, 3);
    assert_ne!(
        second.subjects[0], result.subjects[0],
        "paging moved through the filtered set"
    );
}

#[tokio::test]
async fn a_total_covers_exactly_the_rows_the_constraint_keeps() {
    let store = Db::init_temp("expression_filter_totals").await.unwrap();
    let (_agent, drive) = store.setup("Alice").await.unwrap();
    let table = entries_table(&store, &drive).await;

    let mut query = query_for(&table);
    query.expression_filters = vec![ExpressionFilter {
        expression: duration(),
        operator: FilterOperator::GreaterThan,
        value: (60 * MINUTE) as f64,
        now_ms: None,
    }];
    query.aggregation = Some(Aggregation {
        aggregates: vec![Aggregate {
            id: Some("logged".into()),
            property: None,
            expression: Some(duration()),
            function: AggregateFunction::Sum,
        }],
        group_by: None,
        now_ms: None,
    });
    // A page of one, to prove the total ignores paging but not the constraint.
    query.limit = Some(1);

    let result = store.query(&query).await.unwrap();

    assert_eq!(result.subjects.len(), 1);
    assert_eq!(
        result.aggregates[0].value,
        Some(((90 + 120) * MINUTE) as f64),
        "90 + 120 minutes: the entries the filter kept, all of them"
    );
    assert_eq!(result.aggregates[0].count, 2);
}

#[tokio::test]
async fn a_running_row_is_measured_against_the_callers_clock() {
    let store = Db::init_temp("expression_filter_now").await.unwrap();
    let (_agent, drive) = store.setup("Alice").await.unwrap();

    let table = store
        .create_resource(urls::FOLDER, &drive, "Time entries", None)
        .await
        .unwrap();
    // Started at the epoch and never stopped.
    store
        .create_resource(
            urls::FOLDER,
            &table,
            "Running",
            Some(vec![(START, Value::Timestamp(0))]),
        )
        .await
        .unwrap();

    let elapsed = Expression::from(ExpressionSpec::Elapsed {
        from: Operand::Property(START.into()),
        until: Some(Operand::Property(END.into())),
    });

    let running_for = |now_ms: i64, at_least: i64| {
        let mut query = query_for(&table);
        query.expression_filters = vec![ExpressionFilter {
            expression: elapsed.clone(),
            operator: FilterOperator::GreaterThanOrEqual,
            value: at_least as f64,
            now_ms: Some(now_ms),
        }];
        query
    };

    // Two hours in, it has been running for more than an hour...
    let result = store
        .query(&running_for(120 * MINUTE, 60 * MINUTE))
        .await
        .unwrap();
    assert_eq!(result.subjects.len(), 1);

    // ...but half an hour in, it hadn't. Same row, same filter, different clock:
    // this is why the caller passes one instead of the store reading its own.
    let result = store
        .query(&running_for(30 * MINUTE, 60 * MINUTE))
        .await
        .unwrap();
    assert_eq!(result.subjects.len(), 0);
}
