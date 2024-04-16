/**
Parse HTML documents and extract metadata.
Convert articles to Markdown strings.
Removes navigation elements and sidebars if possible, so we get a `reader` like view.
 */
use kuchikiki::{parse_html, traits::TendrilSink, NodeRef};
use lol_html::{element, rewrite_str, text, ElementContentHandlers, RewriteStrSettings, Selector};
use rand::Rng;
use std::{borrow::Cow, collections::HashMap, string::FromUtf8Error};
use url::Url;
use urlencoding::encode;

use crate::{
    client::fetch_body,
    endpoints::{Endpoint, HandleGetContext},
    errors::AtomicResult,
    urls,
    values::Value,
    AtomicError, Resource,
};

type Handler<'s, 'h> = Vec<(Cow<'s, Selector>, ElementContentHandlers<'h>)>;

pub fn bookmark_endpoint() -> Endpoint {
    Endpoint {
        path: urls::PATH_FETCH_BOOKMARK.into(),
        params: [urls::URL.to_string(), urls::NAME.to_string()].into(),
        description: "The website will be fetched and parsed. The main content of the page is identified, and the rest is stripped. Returns the Markdown.".to_string(),
        shortname: "bookmark".to_string(),
        handle: Some(handle_bookmark_request),
        handle_post: None,
    }
}

fn handle_bookmark_request(context: HandleGetContext) -> AtomicResult<Resource> {
    let HandleGetContext {
        subject,
        store,
        for_agent: _,
    } = context;
    let params = subject.query_pairs();
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

    let (name, path) = match (name, path) {
        (Some(name), Some(path)) => (name, path),
        _ => return bookmark_endpoint().to_resource(store),
    };

    let mut resource = Resource::new(subject.to_string());
    resource.set_class(urls::BOOKMARK);
    resource.set_string(urls::URL.into(), &path, store)?;

    // Fetch the data and create a parser from it.
    let content = fetch_data(&path)?;
    let mut parser = Parser::from_html(&path, &content)?;

    // Extract the title, description and preview image from the HTML
    let site_meta = parser.get_meta();

    if let Some(title) = site_meta.title {
        resource.set_string(urls::NAME.into(), &title, store)?;
    } else {
        resource.set_string(urls::NAME.into(), &name, store)?;
    }

    if let Some(description) = site_meta.description {
        resource.set_string(urls::DESCRIPTION.into(), &description, store)?;
    }

    if let Some(image) = site_meta.image {
        resource.set_string(urls::IMAGE_URL.into(), &image, store)?;
    }

    // Clean and transform the HTML to markdown.
    let cleaned_html = parser.clean_document()?;
    let md = html2md::parse_html(&cleaned_html);
    // Remove empty characters.
    // https://github.com/atomicdata-dev/atomic-server/issues/474
    let md = regex::Regex::new(r"\s{5,}").unwrap().replace_all(&md, "");

    resource.set(urls::PREVIEW.into(), Value::Markdown(md.into()), store)?;

    Ok(resource)
}

fn fetch_data(url: &str) -> AtomicResult<String> {
    fetch_body(url, "text/html", None).map_err(|e| format!("Fetching failed: {}", e).into())
}

struct Parser {
    url: Url,
    internal_html: String,
    /// The root element used to parse the rest of the Document from. Defaults to body, but can be more specific if possible.
    root_element: String,
    anchor_text_buffer: std::rc::Rc<std::cell::RefCell<String>>,
    svg_map: HashMap<String, String>,
}

struct SiteMeta {
    title: Option<String>,
    description: Option<String>,
    image: Option<String>,
}

impl Parser {
    pub fn from_html(url: &str, html: &str) -> AtomicResult<Parser> {
        Ok(Parser {
            url: Url::parse(url)?,
            internal_html: html.to_string(),
            root_element: "body".to_string(),
            anchor_text_buffer: std::rc::Rc::new(std::cell::RefCell::new(String::new())),
            svg_map: HashMap::new(),
        })
    }

    pub fn serialize(node: NodeRef) -> Result<String, FromUtf8Error> {
        let mut stream = Vec::new();
        if let Err(e) = node.serialize(&mut stream) {
            tracing::error!("Serialize error: {}", e);
        }

        String::from_utf8(stream)
    }

    pub fn get_meta(&self) -> SiteMeta {
        let document = parse_html().one(self.internal_html.clone());
        let mut title = None;
        let mut description = None;
        let mut image = None;

        if let Ok(title_element) = document.select_first("title") {
            title = Some(title_element.text_contents());
        }

        if let Ok(description_element) =
            document.select_first("meta[name='description'], meta[property='og:description']")
        {
            description = Some(
                description_element
                    .attributes
                    .borrow()
                    .get("content")
                    .unwrap_or("")
                    .to_string(),
            );
        }

        if let Ok(image_element) =
            document.select_first("meta[property='og:image'], meta[name='twitter:image']")
        {
            image = Some(
                image_element
                    .attributes
                    .borrow()
                    .get("content")
                    .unwrap_or("")
                    .to_string(),
            );
        }

        SiteMeta {
            title,
            description,
            image,
        }
    }

    pub fn clean_document(&mut self) -> AtomicResult<String> {
        self.select_best_node()?;
        self.index_svgs()?;
        self.process_html()?;

        Ok(self.internal_html.clone())
    }

    fn resolve_url(&self, url: &str) -> String {
        if Url::parse(url).is_err() {
            return self.url.join(url).unwrap().as_str().to_string();
        }

        url.to_string()
    }

    /// Finds the DOM node that is most likely to contain the article content.
    fn select_best_node(&mut self) -> AtomicResult<()> {
        const BEST_SCENARIO_SELECTORS: [&str; 3] = ["article", "main", r#"div[role="main"]"#];

        let document = parse_html().one(self.internal_html.clone());

        let mut best_node = document
            .select("body")
            .map_err(|_| "Can't find <body> tag")?
            .next()
            .ok_or("Can't find element next to <body> tag")?
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

        let serialized = Parser::serialize(best_node)?;
        self.internal_html = serialized;
        Ok(())
    }

    fn index_svgs(&mut self) -> Result<(), AtomicError> {
        let document = parse_html().one(self.internal_html.clone());

        for node in document
            .select("svg")
            .map_err(|_| "Can't find <svg> tags")?
        {
            let id: String = rand::thread_rng()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(30)
                .map(char::from)
                .collect();

            let svg = Parser::serialize(node.clone().as_node().clone())?;

            // Tag the element with an ID so the rewriter can find it later.
            node.attributes
                .borrow_mut()
                .insert("id".to_string(), id.clone());

            self.svg_map.insert(id, encode(&svg).into());
        }

        let serialized = Parser::serialize(document)?;
        self.internal_html = serialized;
        Ok(())
    }

    fn process_html(&mut self) -> Result<(), AtomicError> {
        let result = rewrite_str(
            &self.internal_html,
            RewriteStrSettings {
                element_content_handlers: vec![
                    self.unpack_noscript_handler(),
                    self.remove_unwanted_elements_handler(),
                    self.transform_figures_handler(),
                    self.transform_figcaptions_handler(),
                    self.unfold_sup_elements_handler(),
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
        )
        .map_err(|e| format!("Error removing unwanted elements: {}", e))?;
        self.internal_html = result;
        Ok(())
    }

    fn unpack_noscript_handler<'h, 's>(&self) -> Handler<'s, 'h> {
        vec![element!("noscript", |el| {
            el.remove_and_keep_content();
            Ok(())
        })]
    }

    fn remove_unwanted_elements_handler<'h, 's>(&self) -> Handler<'s, 'h> {
        let elements = "nav, footer, iframe, script, aside, style, button, label".to_string();
        let selector = if self.root_element == "article" {
            elements
        } else {
            elements + ", header"
        };

        vec![element!(selector, |el| {
            el.remove();
            Ok(())
        })]
    }

    fn strip_image_dimensions_handler<'h, 's>(&self) -> Handler<'s, 'h> {
        vec![element!("img", |el| {
            if el.has_attribute("width") {
                el.remove_attribute("width");
            }

            if el.has_attribute("height") {
                el.remove_attribute("height");
            }

            Ok(())
        })]
    }

    fn resolve_relative_path_handler(&self) -> Handler {
        vec![element!("*[src], *[href]", |el| {
            if let Some(src) = el.get_attribute("src") {
                el.set_attribute("src", &self.resolve_url(&src))?;
            }

            if let Some(href) = el.get_attribute("href") {
                el.set_attribute("href", &self.resolve_url(&href))?;
            }

            Ok(())
        })]
    }

    fn convert_svg_to_image_handler(&self) -> Handler {
        vec![element!("svg", |el| {
            let id = el.get_attribute("id").ok_or("no id in SVG")?;
            let svg = self.svg_map.get(&id).ok_or("no SVG found with id")?;

            el.set_tag_name("img")?;
            el.remove_attribute("height");
            el.remove_attribute("width");
            el.remove_attribute("viewBox");
            el.remove_attribute("fill");
            el.remove_attribute("xmlns");
            el.set_attribute("src", &format!("data:image/svg+xml;utf8,{}", &svg))?;
            el.set_inner_content("", lol_html::html_content::ContentType::Html);
            Ok(())
        })]
    }

    fn simplify_link_text_handler(&self) -> Handler {
        vec![element!("a *", |el| {
            let tag_name = el.tag_name().to_lowercase();
            if tag_name != "img" && tag_name != "picture" {
                el.remove_and_keep_content();
            }

            Ok(())
        })]
    }

    fn transform_figures_handler(&self) -> Handler {
        vec![element!("figure", |el| {
            el.remove_and_keep_content();
            Ok(())
        })]
    }

    fn transform_figcaptions_handler(&self) -> Handler {
        vec![element!("figcaption", |el| {
            el.set_tag_name("P")?;
            Ok(())
        })]
    }

    fn unfold_sup_elements_handler(&self) -> Handler {
        vec![element!("sup", |el| {
            el.remove_and_keep_content();
            Ok(())
        })]
    }

    fn trim_link_text_handler(&self) -> Handler {
        vec![
            element!("a", |el| {
                self.anchor_text_buffer.borrow_mut().clear();
                let buffer = self.anchor_text_buffer.clone();
                let href = el
                    .get_attribute("href")
                    .unwrap_or_else(|| "link".to_string());

                if let Some(handlers) = el.end_tag_handlers() {
                    handlers.push(Box::new(move |end| {
                        let s = buffer.borrow();
                        let mut text = s.as_str().trim();

                        if text.is_empty() {
                            text = &href;
                        }

                        end.before(text, lol_html::html_content::ContentType::Text);

                        Ok(())
                    }));
                }

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
        ]
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_select_best_element() {
        let html = r#"<html><body><header><nav>navigation</nav></header><iframe></iframe><article><header>article header</header><p>lor em ip sum<p/></article></body></html>"#;
        let mut parser = super::Parser::from_html("https://bla.com", html).unwrap();

        let parsed_html = parser.clean_document().unwrap();
        let md = html2md::parse_html(&parsed_html);

        assert_eq!(md, "article header\n\nlor em ip sum");
    }

    #[test]
    fn test_resolve_relative_paths() {
        let html = r#"<article><p>The <a href="/animals/chicken.html">chicken</a> is an animal</p></article>"#;
        let mut parser = super::Parser::from_html("https://bla.com", html).unwrap();

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
        let mut parser = super::Parser::from_html("https://bla.com", html).unwrap();

        let parsed_html = parser.clean_document().unwrap();
        let md = html2md::parse_html(&parsed_html);

        assert_eq!(md, "[Het is taco tijd](https://bla.com)");
    }

    #[test]
    fn parse_images() {
        let html = r#"<html><body><img alt="Netflix" height="369" src="https://tweakers.net/i/Imo-YDw3aJMOUg7-aMw2OC0lk6Q=/656x/filters:strip\_icc():strip\_exif()/i/2004517792.jpeg?f=imagenormal" width="656"></body></html>"#;
        let mut parser = super::Parser::from_html("https://bla.com", html).unwrap();

        let parsed_html = parser.clean_document().unwrap();
        let md = html2md::parse_html(&parsed_html);

        assert_eq!(
            md,
            r#"![Netflix](https://tweakers.net/i/Imo-YDw3aJMOUg7-aMw2OC0lk6Q=/656x/filters:strip\_icc():strip\_exif()/i/2004517792.jpeg?f=imagenormal)"#
        );
    }

    #[test]
    fn extract_meta_content() {
        let html = r#"<html><head><title>Programmer Facts</title><meta name="description" content="The F in testing stands for Fun" /><meta property="og:image" content="https://example.com" /></head><body></body></html>"#;
        let parser = super::Parser::from_html("https://bla.com", html).unwrap();

        let meta = parser.get_meta();

        assert_eq!(meta.title.unwrap(), "Programmer Facts");
        assert_eq!(meta.description.unwrap(), "The F in testing stands for Fun");
        assert_eq!(meta.image.unwrap(), "https://example.com");
    }

    #[test]
    fn convert_svg() {
        let html =
            r#"<html><body><svg><path d="M 10 10 H 90 V 90 H 10 L 10 10"/></svg></body></html>"#;
        let mut parser = super::Parser::from_html("https://bla.com", html).unwrap();

        let parsed_html = parser.clean_document().unwrap();
        let md = html2md::parse_html(&parsed_html);

        assert_eq!(
            md,
            r#"![](data:image/svg+xml;utf8,%3Csvg%3E%3Cpath%20d%3D%22M%2010%2010%20H%2090%20V%2090%20H%2010%20L%2010%2010%22%3E%3C%2Fpath%3E%3C%2Fsvg%3E)"#
        );
    }
}
