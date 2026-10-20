//! Example app on the Atomic host ABI: a bank statement parser.
//!
//! Exports `atomic:example/statement@1` `read`: a CSV statement
//! (`date,description,amount`, one transaction per line) in, a list of
//! transactions out. It never touches the store: a pure computation that a JS
//! app calls through `calls.call`, on the server or from a frame, with typed
//! arguments and results described by the manifest.

wit_bindgen::generate!({
    path: "../../atomic-host/wit",
    world: "sandboxed-app",
});

use atomic::host::{events::Event, types::Error};
use exports::atomic::host::app::Guest;
use serde_json::{json, Value};

struct Statement;

fn fail(code: &str, message: impl Into<String>) -> Error {
    Error {
        code: code.to_string(),
        message: message.into(),
    }
}

/// Splits one CSV line. Fields may be quoted, with `""` for a quote.
fn split_line(line: &str) -> Result<Vec<String>, String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                chars.next();
                field.push('"');
            }
            ('"', true) => quoted = false,
            ('"', false) if field.is_empty() => quoted = true,
            (',', false) => fields.push(std::mem::take(&mut field).trim().to_string()),
            _ => field.push(c),
        }
    }
    if quoted {
        return Err("unterminated quote".into());
    }
    fields.push(field.trim().to_string());
    Ok(fields)
}

/// `YYYY-MM-DD`, checked for shape and calendar range.
fn date(text: &str) -> Result<(), String> {
    let part = |range: std::ops::Range<usize>| {
        text.get(range)
            .filter(|p| p.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|p| p.parse::<u32>().ok())
    };
    let ok = text.len() == 10
        && text.as_bytes()[4] == b'-'
        && text.as_bytes()[7] == b'-'
        && part(0..4).is_some()
        && part(5..7).is_some_and(|m| (1..=12).contains(&m))
        && part(8..10).is_some_and(|d| (1..=31).contains(&d));
    if ok {
        Ok(())
    } else {
        Err(format!("'{text}' is not a YYYY-MM-DD date"))
    }
}

/// A decimal amount (`-12.50`, `1234`, `+0.5`) in minor units, no floats.
fn minor_units(text: &str) -> Result<i64, String> {
    let bad = || format!("'{text}' is not an amount");
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let (whole, cents) = digits.split_once('.').unwrap_or((digits, ""));
    let numeric = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if whole.is_empty() || !numeric(whole) || !numeric(cents) || cents.len() > 2 || whole.len() > 15
    {
        return Err(bad());
    }
    let minor = whole.parse::<i64>().map_err(|_| bad())? * 100
        + format!("{cents:0<2}").parse::<i64>().map_err(|_| bad())?;
    Ok(if negative { -minor } else { minor })
}

fn read(args: &str) -> Result<String, Error> {
    let args: Value =
        serde_json::from_str(args).map_err(|e| fail("invalid-argument", e.to_string()))?;
    let statement = args["statement"]
        .as_str()
        .ok_or_else(|| fail("invalid-argument", "statement is required"))?;

    let mut transactions = Vec::new();
    let mut total = 0i64;
    for (index, line) in statement.lines().enumerate() {
        let line_no = index + 1;
        if line.trim().is_empty() {
            continue;
        }
        let at = |message: String| fail("invalid-argument", format!("line {line_no}: {message}"));
        let fields = split_line(line).map_err(&at)?;
        // A header row is the one place where the date is not a date.
        if transactions.is_empty() && fields[0].eq_ignore_ascii_case("date") {
            continue;
        }
        let [day, description, amount] = fields.as_slice() else {
            return Err(at(format!(
                "expected 3 fields (date,description,amount), found {}",
                fields.len()
            )));
        };
        date(day).map_err(&at)?;
        let minor = minor_units(amount).map_err(&at)?;
        total = total
            .checked_add(minor)
            .ok_or_else(|| at("the total overflows".into()))?;
        transactions.push(json!({
            "date": day,
            "description": description,
            "amountMinor": minor,
        }));
    }

    Ok(json!({
        "count": transactions.len(),
        "totalMinor": total,
        "transactions": transactions,
    })
    .to_string())
}

impl Guest for Statement {
    fn on_event(_event: Event) -> Result<(), Error> {
        Ok(())
    }

    fn invoke(interface: String, function: String, args: String) -> Result<String, Error> {
        match (interface.as_str(), function.as_str()) {
            ("atomic:example/statement@1", "read") => read(&args),
            _ => Err(fail(
                "not-found",
                format!("no export {interface} {function}"),
            )),
        }
    }
}

export!(Statement);
