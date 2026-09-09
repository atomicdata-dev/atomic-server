//! Pure Google Calendar catalog adapter, shared by browser preview.
use serde_json::{json, Value};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
/// UTC date boundaries; the end is exclusive, matching Calendar's timeMax.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CalendarRange {
    start: String,
    end: String,
    #[serde(default)]
    series: bool,
}

pub(super) fn scope_calendar(document: &mut Value, range: &CalendarRange) -> Result<()> {
    let parse = |value: &str| {
        chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d")
            .map_err(|_| "Calendar dates must use YYYY-MM-DD")
    };
    let start = parse(&range.start)?;
    let end = parse(&range.end)?;
    if start >= end {
        return Err("Calendar end date must be after its start date".into());
    }
    let collection = document
        .pointer_mut("/components/crudResources/event/collections/events")
        .and_then(Value::as_object_mut)
        .ok_or("Calendar catalog has no events collection")?;
    if collection.get("urlTemplate").and_then(Value::as_str)
        != Some("/calendars/{calendarId}/events")
    {
        return Err("Calendar catalog events path has changed".into());
    }
    let query = collection
        .entry("x-list-query")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or("Invalid Calendar collection query")?;
    query.insert("timeMin".into(), json!(format!("{start}T00:00:00Z")));
    query.insert("timeMax".into(), json!(format!("{end}T00:00:00Z")));
    query.insert("singleEvents".into(), json!(!range.series));
    query.insert("showDeleted".into(), json!(true));
    if range.series {
        // A moved exception can lie outside either bound. Partial exception
        // sets must never be used to expand a retained master indefinitely.
        query.remove("timeMin");
        query.remove("timeMax");
        query.remove("orderBy");
    }
    // Older proxy catalogs omit these Google fields; preview() otherwise
    // discards them even though the API returns them. Add their official types.
    let properties = document
        .pointer_mut("/components/schemas/event/properties")
        .and_then(Value::as_object_mut)
        .ok_or("Calendar catalog event schema has changed")?;
    properties.insert(
        "recurrence".into(),
        json!({"type":"array","items":{"type":"string"}}),
    );
    properties.insert(
        "originalStartTime".into(),
        json!({"type":"object","properties":{
            "date":{"type":"string","format":"date"},
            "dateTime":{"type":"string","format":"date-time"},
            "timeZone":{"type":"string"}
        }}),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn catalog() -> Value {
        json!({"components":{"schemas":{"event":{"type":"object","properties":{}}},"crudResources":{"event":{"collections":{"events":{"urlTemplate":"/calendars/{calendarId}/events","x-list-query":{"timeMin":"stale","timeMax":"stale","orderBy":"startTime"}}}}}}})
    }
    #[test]
    fn retained_series_fetches_every_exception_including_cancellations() {
        let range: CalendarRange =
            serde_json::from_value(json!({"start":"2026-03-01","end":"2026-04-01","series":true}))
                .unwrap();
        let mut doc = catalog();
        scope_calendar(&mut doc, &range).unwrap();
        let query =
            &doc["components"]["crudResources"]["event"]["collections"]["events"]["x-list-query"];
        assert_eq!(query["singleEvents"], false);
        assert_eq!(query["showDeleted"], true);
        assert!(query.get("timeMin").is_none());
        assert!(query.get("timeMax").is_none());
        assert!(query.get("orderBy").is_none());
        let props = &doc["components"]["schemas"]["event"]["properties"];
        assert_eq!(props["recurrence"]["type"], "array");
        assert_eq!(props["originalStartTime"]["type"], "object");
    }
    #[test]
    fn bounded_import_still_expands_instances_and_requests_tombstones() {
        let range: CalendarRange =
            serde_json::from_value(json!({"start":"2026-03-01","end":"2026-04-01"})).unwrap();
        let mut doc = catalog();
        scope_calendar(&mut doc, &range).unwrap();
        let query =
            &doc["components"]["crudResources"]["event"]["collections"]["events"]["x-list-query"];
        assert_eq!(query["singleEvents"], true);
        assert_eq!(query["showDeleted"], true);
        assert_eq!(query["timeMin"], "2026-03-01T00:00:00Z");
        assert_eq!(query["timeMax"], "2026-04-01T00:00:00Z");
    }
}
