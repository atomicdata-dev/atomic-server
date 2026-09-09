//! The crate's error type.

use std::path::PathBuf;

use thiserror::Error;

/// Anything that can go wrong loading a document or talking to a server.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Reading a document from disk failed.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// A document could not be parsed as YAML or JSON.
    #[error("could not parse document: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),

    /// A document did not fit the OpenAPI type surface this crate expects.
    #[error("could not read document: {0}")]
    Json(#[from] serde_json::Error),

    /// A document or overlay file could not be read or parsed. Wraps the
    /// underlying [`Error::Io`] or [`Error::Yaml`] with the path that caused
    /// it, since a bare i/o or parse error doesn't otherwise name the file.
    #[error("could not load \"{path}\": {source}")]
    FileLoad {
        /// The file that could not be loaded.
        path: PathBuf,
        /// The underlying read or parse failure.
        #[source]
        source: Box<Error>,
    },

    /// An overlay used a JSONPath target outside the supported subset.
    #[error(
        "unsupported overlay target \"{0}\": only \"$\", simple dot-paths like \
         \"$.components...\", and quoted bracket segments like \
         \"$.paths['/pets'].get\" are supported"
    )]
    UnsupportedOverlayTarget(String),

    /// An overlay target segment resolved to something that isn't an object.
    #[error("overlay target segment \"{0}\" does not resolve to an object")]
    OverlayTargetNotAnObject(String),

    /// An overlay tried to `remove` the document root.
    #[error("overlay cannot remove the document root")]
    OverlayRemovesRoot,

    /// The client could not reach the server, or the server rejected the request.
    #[error("http error: {0}")]
    Http(String),

    /// A resource path was asked for that the document does not declare.
    #[error("unknown resource \"{0}\"")]
    UnknownResource(String),

    /// The document declares no `components.crudResources`; the
    /// CRUD-causality overlay hasn't been applied.
    #[error("document declares no crudResources; apply the CRUD-causality overlay")]
    NoCrudResources,

    /// A constant named a parameter the document does not declare (path or
    /// query, on any operation). A typo'd key here would otherwise sync
    /// nothing, or scope the sync far wider than intended.
    #[error("constant \"{0}\" does not name a parameter this document declares")]
    UnknownConstant(String),

    /// A path template variable is bound by neither a constant, a parent
    /// record's context provider, nor the resource's own identity binding.
    #[error(
        "path variable \"{0}\" is not bound by a constant, a parent record, \
         or an identity binding"
    )]
    UnboundContextParam(String),

    /// Two differently-named resources or fields normalized to the same
    /// ontology shortname — the ontology would then mint one term for two
    /// distinct things.
    #[error(
        "\"{first}\" and \"{second}\" both normalize to the ontology shortname \"{shortname}\""
    )]
    ShortnameCollision {
        /// The shortname both names normalized to.
        shortname: String,
        /// The name that claimed the shortname first.
        first: String,
        /// The name that collided with it.
        second: String,
    },
}

/// `Result` specialized to this crate's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
