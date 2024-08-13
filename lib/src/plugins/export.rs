use crate::endpoints::Endpoint;

pub fn export_endpoint() -> Endpoint {
    Endpoint {
        path: "/export".to_string(),
        params: vec!["subject".into(), "format".into(), "display_refs_as_name".into()],
        description: r#"Export table data

Use with the following parameters
- **subject**: Subject of the resource to export.
- **format**: Format of the export, currently only supports `csv`.
- **display_refs_as_name**: If true, it will display referenced resources by their name instead of subject.
"#
        .to_string(),
        shortname: "export".to_string(),
        handle: None,
        handle_post: None,
    }
}
