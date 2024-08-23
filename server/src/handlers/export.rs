use std::collections::HashMap;

use crate::{appstate::AppState, errors::AtomicServerResult, helpers::get_client_agent};
use actix_web::http::header::{ContentDisposition, DispositionParam, DispositionType};
use actix_web::{web, HttpResponse};
use atomic_lib::agents::ForAgent;
use atomic_lib::errors::AtomicResult;
use atomic_lib::values::SubResource;
use atomic_lib::Query;
use atomic_lib::{urls, Db, Resource, Storelike, Value};
use chrono::DateTime;
use serde::Deserialize;

#[serde_with::serde_as]
#[serde_with::skip_serializing_none]
#[derive(Deserialize, Debug)]
pub struct ExportParams {
    pub format: Option<String>,
    pub subject: Option<String>,
    pub display_refs_as_name: Option<bool>,
}

/// Exports a resource in the specified format.
#[tracing::instrument(skip(appstate, req))]
pub async fn handle_export(
    path: Option<web::Path<String>>,
    appstate: web::Data<AppState>,
    params: web::Query<ExportParams>,
    req: actix_web::HttpRequest,
) -> AtomicServerResult<HttpResponse> {
    let headers = req.headers();
    let store = &appstate.store;

    let Some(subject) = params.subject.clone() else {
        return Err("No subject provided".into());
    };

    let Some(format) = params.format.clone() else {
        return Err("No format provided".into());
    };

    let for_agent = get_client_agent(headers, &appstate, subject.clone())?;
    let display_refs_as_name = params.display_refs_as_name.unwrap_or(false);

    match format.as_str() {
        "csv" => {
            let exporter = CSVExporter {
                store,
                agent: &for_agent,
                display_refs_as_name,
            };

            let (name, csv) = exporter.resource_to_csv(&subject)?;
            Ok(HttpResponse::Ok()
                .content_type("text/csv")
                .insert_header((
                    actix_web::http::header::CONTENT_DISPOSITION,
                    ContentDisposition {
                        disposition: DispositionType::Attachment,
                        parameters: vec![DispositionParam::Filename(name)],
                    },
                ))
                .body(csv))
        }
        _ => Err(format!("Unsupported format: {}", format).into()),
    }
}

struct CSVExporter<'a> {
    store: &'a Db,
    agent: &'a ForAgent,
    display_refs_as_name: bool,
}

impl<'a> CSVExporter<'a> {
    pub fn resource_to_csv(&self, subject: &str) -> AtomicResult<(String, String)> {
        println!("Exporting resource to CSV: {}", subject);
        let resource = self
            .store
            .get_resource_extended(subject, false, self.agent)?;

        let binding = resource.get_classes(self.store)?;

        let classes: Vec<&str> = binding.iter().map(|c| c.subject.as_str()).collect();

        // Check the classes of the resource to determine how to export it.
        if classes.contains(&urls::TABLE) {
            let prop_order = self.get_prop_order_from_table(&resource)?;

            let data = self.build_csv_from_children(&resource, Some(prop_order))?;
            let Ok(Value::String(name)) = resource.get(urls::NAME) else {
                return Err("Resource does not have a name".into());
            };

            let filename = format!(
                "{}.csv",
                sanitize_filename::sanitize(name).replace(' ', "-")
            );
            Ok((filename, data))
        } else {
            Err("Resource does not have any supported classes".into())
        }
    }

    fn get_prop_order_from_table(&self, resource: &Resource) -> AtomicResult<Vec<String>> {
        let class_value = resource.get(urls::CLASSTYPE_PROP)?;

        let propvals = match class_value {
            Value::AtomicUrl(subject) => self
                .store
                .get_resource_extended(subject, false, self.agent)?
                .get_propvals()
                .clone(),
            Value::Resource(resource) => resource.get_propvals().clone(),
            Value::NestedResource(nested) => match nested {
                SubResource::Resource(resource) => resource.get_propvals().clone(),
                SubResource::Subject(subject) => self
                    .store
                    .get_resource_extended(subject, false, self.agent)?
                    .get_propvals()
                    .clone(),
                SubResource::Nested(props) => props.clone(),
            },
            _ => return Err("Resource does not have any supported classtype".into()),
        };

        let mut requires = Value::ResourceArray(vec![]);
        if let Some(req) = propvals.get(urls::REQUIRES) {
            requires = req.clone();
        }

        let mut recommends = Value::ResourceArray(vec![]);
        if let Some(rec) = propvals.get(urls::RECOMMENDS) {
            recommends = rec.clone();
        }

        match (requires, recommends) {
            (Value::ResourceArray(requires), Value::ResourceArray(recommends)) => {
                let mut order = vec![];
                for value in requires.iter().chain(recommends.iter()) {
                    match value {
                        SubResource::Resource(resource) => {
                            order.push(resource.get_subject().clone());
                        }
                        SubResource::Subject(subject) => {
                            order.push(subject.clone());
                        }
                        SubResource::Nested(_) => {}
                    }
                }

                Ok(order)
            }
            _ => Err("Requires and Recommends must be arrays".into()),
        }
    }

    fn build_csv_from_children(
        &self,
        resource: &Resource,
        prop_order: Option<Vec<String>>,
    ) -> AtomicResult<String> {
        let query = Query {
            property: Some(urls::PARENT.into()),
            value: Some(atomic_lib::Value::String(resource.get_subject().clone())),
            limit: None,
            start_val: None,
            end_val: None,
            offset: 0,
            sort_by: Some(urls::CREATED_AT.into()),
            sort_desc: false,
            include_external: false,
            include_nested: true,
            for_agent: self.agent.clone(),
        };

        let results = self.store.query(&query)?;
        let mut body_csv = String::new();
        let mut encountered_properties = prop_order.unwrap_or_default();

        for item in results.resources.iter() {
            let mut line_vec: Vec<String> = vec![String::new(); encountered_properties.len()];
            line_vec.insert(0, item.get_subject().to_string());

            for (prop, value) in item.get_propvals().iter() {
                if prop == urls::PARENT || prop == urls::LAST_COMMIT {
                    continue;
                }

                let fixed_value = CSVExporter::escape_csv_value(self.value_to_string(value));

                if let Some(index) = encountered_properties.iter().position(|p| p == prop) {
                    line_vec[index + 1] = fixed_value;
                } else {
                    encountered_properties.push(prop.clone());
                    line_vec.push(fixed_value);
                }
            }

            let line = line_vec.join(",");
            body_csv.push_str(&format!("\n{}", line));
        }

        let header = self.create_csv_header_from_props(&encountered_properties)?;
        let csv = format!("{}{}", header, body_csv);

        Ok(csv)
    }

    fn create_csv_header_from_props(&self, props: &[String]) -> AtomicResult<String> {
        let mut header = "subject".to_string();
        for prop in props.iter() {
            let name: String =
                if let Ok(resource) = self.store.get_resource_extended(prop, true, self.agent) {
                    resource.get(urls::SHORTNAME)?.to_string()
                } else {
                    prop.to_string()
                };
            header.push_str(&format!(",{}", name));
        }

        Ok(header)
    }

    fn value_to_string(&self, value: &Value) -> String {
        match value {
            Value::Timestamp(ts) => {
                let seconds = ts / 1000;
                let remaining_nanoseconds = (ts % 1000) * 1_000_000; // Convert remaining milliseconds to nanoseconds

                let Some(date_time) =
                    DateTime::from_timestamp(seconds, remaining_nanoseconds as u32)
                else {
                    return ts.to_string();
                };

                date_time.to_rfc3339()
            }
            Value::ResourceArray(values) => {
                let names: Vec<String> = values
                    .iter()
                    .map(|v| match v {
                        SubResource::Subject(subject) => self.get_name_from_subject(subject),
                        SubResource::Resource(resource) => self.get_name_from_propvals(
                            resource.get_propvals(),
                            resource.get_subject().clone(),
                        ),
                        SubResource::Nested(nested) => {
                            self.get_name_from_propvals(nested, "".to_string())
                        }
                    })
                    .collect();

                names.join(", ")
            }
            Value::Resource(resource) => {
                self.get_name_from_propvals(resource.get_propvals(), resource.get_subject().clone())
            }
            Value::AtomicUrl(subject) => self.get_name_from_subject(subject),
            _ => value.to_string(),
        }
    }

    fn get_name_from_subject(&self, subject: &str) -> String {
        let Ok(resource) = self.store.get_resource_extended(subject, true, self.agent) else {
            return subject.to_string();
        };

        self.get_name_from_propvals(resource.get_propvals(), resource.get_subject().clone())
    }

    fn get_name_from_propvals(&self, propvals: &HashMap<String, Value>, subject: String) -> String {
        if !self.display_refs_as_name {
            return subject;
        }

        if let Some(value) = propvals.get(urls::DOWNLOAD_URL) {
            return value.to_string();
        }
        if let Some(value) = propvals.get(urls::NAME) {
            return value.to_string();
        }
        if let Some(value) = propvals.get(urls::SHORTNAME) {
            return value.to_string();
        }
        if let Some(value) = propvals.get(urls::FILENAME) {
            return value.to_string();
        }

        subject
    }

    fn escape_csv_value(value: String) -> String {
        let no_quotes = value.replace('"', "\"\"");
        let reg = regex::Regex::new(r"\n|,").unwrap();

        if reg.is_match(&no_quotes) {
            format!("\"{}\"", no_quotes)
        } else {
            no_quotes
        }
    }
}
