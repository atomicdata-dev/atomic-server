use kuchiki::{traits::TendrilSink, NodeRef};
use lol_html::{element, rewrite_str, text, ElementContentHandlers, RewriteStrSettings, Selector};
use std::{borrow::Cow, collections::HashMap, string::FromUtf8Error};
use url::Url;
use urlencoding::encode;
use uuid::Uuid;

use crate::{
    client::fetch_body, endpoints::Endpoint, errors::AtomicResult, urls, values::Value,
    AtomicError, AtomicErrorType, Resource, Storelike,
};

type Handler<'s, 'h> = Vec<(Cow<'s, Selector>, ElementContentHandlers<'h>)>;

pub fn bookmark_endpoint() -> Endpoint {
    Endpoint {
        path: "/fetchbookmark".to_string(),
        params: [urls::URL.to_string(), urls::NAME.to_string()].into(),
        description: "The website will be fetched and parsed by the server. The data will then be added as a markdown document that is fully indexed.".to_string(),
        shortname: "bookmark".to_string(),
        handle: Some(handle_bookmark_request),
    }
}

fn handle_bookmark_request(
    url: url::Url,
    store: &impl Storelike,
    _: Option<&str>,
) -> AtomicResult<Resource> {
    let params = url.query_pairs();
    let mut path = None;
    let mut name = None;

    for (k, v) in params {
        if let "url" = k.as_ref() {
            path = Some(v.to_string())
        };

        if let "name" = k.as_ref() {
            name = Some(v.to_string())
        };
    }

    if path.is_none() || name.is_none() {
        return bookmark_endpoint().to_resource(store);
    }

    let path = path.unwrap();
    let mut name = name.unwrap();

    let mut resource = Resource::new(url.to_string());
    resource.set_class(urls::BOOKMARK.into())?;
    resource.set_propval_string(urls::URL.into(), &path.clone(), store)?;

    // Fetch the data and create a parser from it.
    let content = fetch_data(&path)?;
    let mut parser = Parser::from_html(&path, &content);

    // Extract the title from the HTML
    if let Some(title) = parser.get_title() {
        name = title;
    }

    resource.set_propval_string(urls::NAME.into(), &name, store)?;

    // Clean and transform the HTML to markdown.
    if let Ok(cleaned_html) = parser.clean_document() {
        let md = html2md::parse_html(&cleaned_html);

        resource.set_propval(urls::PREVIEW.into(), Value::Markdown(md), store)?;

        Ok(resource)
    } else {
        Err(AtomicError {
            message: "Could not parse HTML".to_string(),
            error_type: AtomicErrorType::OtherError,
        })
    }
}

fn fetch_data(url: &str) -> AtomicResult<String> {
    match fetch_body(url, "text/html", None) {
        Ok(response) => Ok(response),
        Err(e) => {
            return Err(AtomicError {
                message: format!("Error fetching data: {}", e),
                error_type: crate::AtomicErrorType::OtherError,
            })
        }
    }
}

struct Parser {
    url: Url,
    internal_html: String,
    root_element: String,
    anchor_text_buffer: std::rc::Rc<std::cell::RefCell<String>>,
    svg_map: HashMap<String, String>,
}

impl Parser {
    pub fn from_html(url: &str, html: &str) -> Parser {
        Parser {
            url: Url::parse(url).unwrap(),
            internal_html: html.to_string(),
            root_element: "body".to_string(),
            anchor_text_buffer: std::rc::Rc::new(std::cell::RefCell::new(String::new())),
            svg_map: HashMap::new(),
        }
    }

    pub fn serialize(node: NodeRef) -> Result<String, FromUtf8Error> {
        let mut stream = Vec::new();
        if let Err(e) = node.serialize(&mut stream) {
            println!("{}", e);
        }

        let result = String::from_utf8(stream);

        return result;
    }

    pub fn get_title(&self) -> Option<String> {
        let document = kuchiki::parse_html().one(self.internal_html.clone());

        if let Ok(title_element) = document.select_first("title") {
            return Some(title_element.text_contents());
        } else {
            return None;
        }
    }

    pub fn clean_document(&mut self) -> Result<String, AtomicError> {
        self.select_best_node()?;
        self.index_svgs()?;
        self.process_html()?;

        return Ok(self.internal_html.clone());
    }

    fn resolve_url(&self, url: &str) -> String {
        if let Err(_) = Url::parse(&url) {
            return self.url.join(&url).unwrap().as_str().to_string();
        }

        url.to_string()
    }

    fn select_best_node(&mut self) -> Result<(), AtomicError> {
        const BEST_SCENARIO_SELECTORS: [&str; 3] = ["article", "main", r#"div[role="main"]"#];

        let document = kuchiki::parse_html().one(self.internal_html.clone());

        let mut best_node = document
            .select("body")
            .unwrap()
            .next()
            .unwrap()
            .as_node()
            .clone();

        for selector in BEST_SCENARIO_SELECTORS.iter() {
            if let Ok(mut node_match) = document.select(selector) {
                if let Some(next_node) = node_match.next() {
                    self.root_element = next_node.name.local.to_string();
                    best_node = next_node.as_node().clone();
                    break;
                }
            }
        }

        match Parser::serialize(best_node) {
            Ok(result) => {
                self.internal_html = result;
                Ok(())
            }
            Err(e) => Err(AtomicError {
                message: format!("Error serializing node: {}", e),
                error_type: AtomicErrorType::OtherError,
            }),
        }
    }

    fn index_svgs(&mut self) -> Result<(), AtomicError> {
        let document = kuchiki::parse_html().one(self.internal_html.clone());

        for node in document.select("svg").unwrap() {
            let id = Uuid::new_v4().to_string();

            let svg = Parser::serialize(node.clone().as_node().clone()).unwrap();

            // Tag the element with an ID so the rewriter can find it later.
            node.attributes
                .borrow_mut()
                .insert("id".to_string(), id.clone());

            self.svg_map.insert(id, encode(&svg).into_owned());
        }

        match Parser::serialize(document) {
            Ok(result) => {
                self.internal_html = result;
                Ok(())
            }
            Err(e) => Err(AtomicError {
                message: format!("Error serializing node: {}", e),
                error_type: AtomicErrorType::OtherError,
            }),
        }
    }

    fn process_html(&mut self) -> Result<(), AtomicError> {
        match rewrite_str(
            &self.internal_html,
            RewriteStrSettings {
                element_content_handlers: vec![
                    self.unpack_noscript_handler(),
                    self.remove_unwanted_elements_handler(),
                    self.transform_figures_handler(),
                    self.transform_figcaptions_handler(),
                    self.resolve_relative_path_handler(),
                    self.simplify_link_text_handler(),
                    self.trim_link_text_handler(),
                    self.convert_svg_to_image_handler(),
                    self.strip_image_dimensions_handler(),
                ]
                .into_iter()
                .flatten()
                .collect(),
                ..RewriteStrSettings::default()
            },
        ) {
            Ok(result) => {
                self.internal_html = result;
                Ok(())
            }
            Err(e) => Err(AtomicError {
                message: format!("Error removing unwanted elements: {}", e),
                error_type: AtomicErrorType::OtherError,
            }),
        }
    }

    fn unpack_noscript_handler<'h, 's>(&self) -> Handler<'s, 'h> {
        return vec![element!("noscript", |el| {
            el.remove_and_keep_content();
            Ok(())
        })];
    }

    fn remove_unwanted_elements_handler<'h, 's>(&self) -> Handler<'s, 'h> {
        let elements = "nav, footer, iframe, script, aside, style, button, label".to_string();
        let selector = if self.root_element == "article" {
            elements
        } else {
            elements + ", header"
        };

        return vec![element!(selector, |el| {
            el.remove();
            Ok(())
        })];
    }

    fn strip_image_dimensions_handler<'h, 's>(&self) -> Handler<'s, 'h> {
        return vec![element!("img", |el| {
            if el.has_attribute("width") {
                el.remove_attribute("width");
            }

            if el.has_attribute("height") {
                el.remove_attribute("height");
            }

            Ok(())
        })];
    }

    fn resolve_relative_path_handler<'h>(&'h self) -> Handler<'h, 'h> {
        return vec![element!("*[src], *[href]", |el| {
            if el.has_attribute("src") {
                let src = el.get_attribute("src").unwrap();
                el.set_attribute("src", &self.resolve_url(&src))?;
            }

            if el.has_attribute("href") {
                let href = el.get_attribute("href").unwrap();
                el.set_attribute("href", &self.resolve_url(&href))?;
            }

            Ok(())
        })];
    }

    fn convert_svg_to_image_handler<'h>(&'h self) -> Handler<'h, 'h> {
        return vec![element!("svg", |el| {
            let id = el.get_attribute("id").unwrap();
            let svg = self.svg_map.get(&id).unwrap();

            el.set_tag_name("img")?;
            el.remove_attribute("height");
            el.remove_attribute("width");
            el.remove_attribute("viewBox");
            el.remove_attribute("fill");
            el.remove_attribute("xmlns");
            el.set_attribute("src", &format!("data:image/svg+xml;utf8,{}", &svg))?;
            el.set_inner_content("", lol_html::html_content::ContentType::Html);
            Ok(())
        })];
    }

    fn simplify_link_text_handler<'h>(&self) -> Handler<'h, 'h> {
        return vec![element!("a *", |el| {
            let tag_name = el.tag_name().to_lowercase();
            if tag_name != "img" && tag_name != "picture" {
                el.remove_and_keep_content();
            }

            Ok(())
        })];
    }

    fn transform_figures_handler<'h>(&self) -> Handler<'h, 'h> {
        return vec![element!("figure", |el| {
            el.remove_and_keep_content();
            Ok(())
        })];
    }

    fn transform_figcaptions_handler<'h>(&self) -> Handler<'h, 'h> {
        return vec![element!("figcaption", |el| {
            el.set_tag_name("P").unwrap();
            Ok(())
        })];
    }

    fn trim_link_text_handler<'h>(&'h self) -> Handler<'h, 'h> {
        return vec![
            element!("a", |el| {
                self.anchor_text_buffer.borrow_mut().clear();
                let buffer = self.anchor_text_buffer.clone();
                let href = el.get_attribute("href").unwrap_or("link".to_string());

                el.on_end_tag(move |end| {
                    let s = buffer.borrow();
                    let mut text = s.as_str().trim();

                    if text.len() == 0 {
                        text = &href;
                    }

                    end.before(text, lol_html::html_content::ContentType::Text);

                    Ok(())
                })?;

                Ok(())
            }),
            text!("a", |chunk| {
                let text = chunk.as_str();
                let prepared_text = text.trim().to_owned() + " ";

                self.anchor_text_buffer
                    .borrow_mut()
                    .push_str(&prepared_text);
                chunk.remove();
                Ok(())
            }),
        ];
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_select_best_element() {
        let html = r#"<html><body><header><nav>navigation</nav></header><iframe></iframe><article><header>article header</header><p>lor em ip sum<p/></article></body></html>"#;
        let mut parser = super::Parser::from_html("https://bla.com", html);

        let parsed_html = parser.clean_document().unwrap();
        let md = html2md::parse_html(&parsed_html);

        assert_eq!(md, "article header\n\nlor em ip sum");
    }

    #[test]
    fn test_resolve_relative_paths() {
        let html = r#"<article><p>The <a href="/animals/chicken.html">chicken</a> is an animal</p></article>"#;
        let mut parser = super::Parser::from_html("https://bla.com", html);

        let parsed_html = parser.clean_document().unwrap();
        let md = html2md::parse_html(&parsed_html);

        assert_eq!(
            md,
            "The [chicken](https://bla.com/animals/chicken.html) is an animal"
        );
    }

    #[test]
    fn test_clean_link() {
        let html = r#"<html><body><a href="https://bla.com"><div>Het is</div><div>taco tijd</div></a></body></html>"#;
        let mut parser = super::Parser::from_html("https://bla.com", html);

        let parsed_html = parser.clean_document().unwrap();
        let md = html2md::parse_html(&parsed_html);

        assert_eq!(md, "[Het is taco tijd](https://bla.com)");
    }

    #[test]
    fn parse_images() {
        let html = r#"<html><body><img alt="Netflix" height="369" src="https://tweakers.net/i/Imo-YDw3aJMOUg7-aMw2OC0lk6Q=/656x/filters:strip\_icc():strip\_exif()/i/2004517792.jpeg?f=imagenormal" width="656"></body></html>"#;
        let mut parser = super::Parser::from_html("https://bla.com", html);

        let parsed_html = parser.clean_document().unwrap();
        let md = html2md::parse_html(&parsed_html);

        assert_eq!(
            md,
            r#"![Netflix](https://tweakers.net/i/Imo-YDw3aJMOUg7-aMw2OC0lk6Q=/656x/filters:strip\_icc():strip\_exif()/i/2004517792.jpeg?f=imagenormal)"#
        );
    }

    #[test]
    fn convert_svg() {
        let html =
            r#"<html><body><svg><path d="M 10 10 H 90 V 90 H 10 L 10 10"/></svg></body></html>"#;
        let mut parser = super::Parser::from_html("https://bla.com", html);

        let parsed_html = parser.clean_document().unwrap();
        let md = html2md::parse_html(&parsed_html);

        assert_eq!(
            md,
            r#"![](data:image/svg+xml;utf8,%3Csvg%3E%3Cpath%20d%3D%22M%2010%2010%20H%2090%20V%2090%20H%2010%20L%2010%2010%22%3E%3C%2Fpath%3E%3C%2Fsvg%3E)"#
        );
    }
}
