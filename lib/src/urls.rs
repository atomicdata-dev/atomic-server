//! Contains some of the most important Atomic Data URLs.

// Classes
pub const CLASS: &str = "https://atomicdata.dev/classes/Class";
pub const PROPERTY: &str = "https://atomicdata.dev/classes/Property";
pub const DATATYPE_CLASS: &str = "https://atomicdata.dev/classes/Datatype";
pub const COMMIT: &str = "https://atomicdata.dev/classes/Commit";
pub const AGENT: &str = "https://atomicdata.dev/classes/Agent";
pub const COLLECTION: &str = "https://atomicdata.dev/classes/Collection";
pub const ENDPOINT: &str = "https://atomicdata.dev/classes/Endpoint";
pub const DRIVE: &str = "https://atomicdata.dev/classes/Drive";
pub const INVITE: &str = "https://atomicdata.dev/classes/Invite";
pub const REDIRECT: &str = "https://atomicdata.dev/classes/Redirect";
pub const ATOM: &str = "https://atomicdata.dev/classes/Atom";
pub const FILE: &str = "https://atomicdata.dev/classes/File";
pub const CHATROOM: &str = "https://atomicdata.dev/classes/ChatRoom";
pub const FOLDER: &str = "https://atomicdata.dev/classes/Folder";
pub const PARAGRAPH: &str = "https://atomicdata.dev/classes/elements/Paragraph";
pub const MESSAGE: &str = "https://atomicdata.dev/classes/Message";
pub const IMPORTER: &str = "https://atomicdata.dev/classes/Importer";
pub const ERROR: &str = "https://atomicdata.dev/classes/Error";
pub const BOOKMARK: &str = "https://atomicdata.dev/class/Bookmark";
pub const DOCUMENT_V2: &str = "https://atomicdata.dev/classes/DocumentV2";
pub const ONTOLOGY: &str = "https://atomicdata.dev/class/ontology";
pub const ENDPOINT_RESPONSE: &str =
    "https://atomicdata.dev/ontology/server/class/endpoint-response";
pub const TABLE: &str = "https://atomicdata.dev/classes/Table";
pub const PLUGIN: &str = "https://atomicdata.dev/classes/Plugin";
pub const TAG: &str = "https://atomicdata.dev/classes/Tag";
pub const PEER: &str = "https://atomicdata.dev/classes/Peer";
pub const PLAIN_TEXT: &str = "https://atomicdata.dev/classes/PlainText";
pub const FORK: &str = "https://atomicdata.dev/classes/Fork";
pub const FORM: &str = "https://atomicdata.dev/classes/Form";
pub const FORM_PAGE: &str = "https://atomicdata.dev/classes/FormPage";
pub const FORM_FIELD: &str = "https://atomicdata.dev/classes/FormField";
pub const FORM_HEADING: &str = "https://atomicdata.dev/classes/FormHeading";
pub const FORM_PARAGRAPH: &str = "https://atomicdata.dev/classes/FormParagraph";

// Properties
pub const ORIGINAL_SUBJECT: &str = "https://atomicdata.dev/properties/originalSubject";
pub const FORK_BASE: &str = "https://atomicdata.dev/properties/forkBase";
pub const FORK_VERSION: &str = "https://atomicdata.dev/properties/forkVersion";
// Content i18n (lib/defaults/i18n.json)
pub const LANGUAGE: &str = "https://atomicdata.dev/properties/language";
pub const TRANSLATION_OF: &str = "https://atomicdata.dev/properties/translationOf";
pub const DEFAULT_LANGUAGE: &str = "https://atomicdata.dev/properties/defaultLanguage";
pub const LANGUAGES: &str = "https://atomicdata.dev/properties/languages";
pub const SHORTNAME: &str = "https://atomicdata.dev/properties/shortname";
pub const DESCRIPTION: &str = "https://atomicdata.dev/properties/description";
/// Structured error classification on an `Error` resource, numeric — see
/// `sync::protocol::error_code` (F5, planning/unified-sync.md). Set
/// alongside `DESCRIPTION` on the HTTP `/commit` error body so the outbox
/// can switch on a code instead of pattern-matching the message string.
/// Absent (or `0`/unknown) means "no structured classification, fall back
/// to string matching" — always true for non-commit errors.
pub const ERROR_CODE: &str = "https://atomicdata.dev/properties/errorCode";
pub const INCOMPLETE: &str = "https://atomicdata.dev/properties/incomplete";
// ... for Properties
pub const IS_A: &str = "https://atomicdata.dev/properties/isA";
pub const IS_DYNAMIC: &str = "https://atomicdata.dev/properties/isDynamic";
pub const IS_LOCKED: &str = "https://atomicdata.dev/properties/isLocked";
pub const DATATYPE_PROP: &str = "https://atomicdata.dev/properties/datatype";
pub const CLASSTYPE_PROP: &str = "https://atomicdata.dev/properties/classtype";
pub const ALLOWS_ONLY: &str = "https://atomicdata.dev/properties/allowsOnly";
// ... for Classes
pub const REQUIRES: &str = "https://atomicdata.dev/properties/requires";
pub const RECOMMENDS: &str = "https://atomicdata.dev/properties/recommends";
// ... for Drives
pub const DEFAULT_ONTOLOGY: &str =
    "https://atomicdata.dev/ontology/server/property/default-ontology";
// ... for Commits
pub const SUBJECT: &str = "https://atomicdata.dev/properties/subject";
pub const SET: &str = "https://atomicdata.dev/properties/set";
pub const PUSH: &str = "https://atomicdata.dev/properties/push";
pub const REMOVE: &str = "https://atomicdata.dev/properties/remove";
pub const DESTROY: &str = "https://atomicdata.dev/properties/destroy";
pub const LORO_UPDATE: &str = "https://atomicdata.dev/properties/loroUpdate";
pub const SIGNER: &str = "https://atomicdata.dev/properties/signer";
pub const CREATED_AT: &str = "https://atomicdata.dev/properties/createdAt";
/// Fractional sort key ordering a resource among its siblings. Falls back to
/// `createdAt` when absent — both live on one numeric (timestamp) axis.
pub const SORT_ORDER: &str = "https://atomicdata.dev/properties/sortOrder";
pub const CREATED_BY: &str = "https://atomicdata.dev/properties/createdBy";
pub const SIGNATURE: &str = "https://atomicdata.dev/properties/signature";
pub const PREVIOUS_COMMIT: &str = "https://atomicdata.dev/properties/previousCommit";
pub const LAST_COMMIT: &str = "https://atomicdata.dev/properties/lastCommit";
pub const IS_GENESIS: &str = "https://atomicdata.dev/properties/isGenesis";
/// Inline, immutable self-verifying genesis certificate (binary; base64 in
/// JSON-AD). Carries signer/createdAt/nonce/parent/drive; the DID is
/// `did:ad:<sign(cert)>`. Decoded for race-free, drive-first rights checks.
/// See `lib/src/genesis.rs` + `planning/genesis-self-verifying.md`.
pub const GENESIS: &str = "https://atomicdata.dev/properties/genesis";
/// The drive a resource belongs to, stamped at genesis (from the cert's
/// `drive`). Lets `check_rights` consult the stable drive grant directly
/// instead of walking a possibly-not-yet-materialized parent chain — the fix
/// for the parent-before-child 401 race. (`DRIVE` above is the Drive *class*.)
pub const DRIVE_PROP: &str = "https://atomicdata.dev/properties/drive";
// ... for Agents
pub const PUBLIC_KEY: &str = "https://atomicdata.dev/properties/publicKey";
pub const NAME: &str = "https://atomicdata.dev/properties/name";
pub const DRIVES: &str = "https://atomicdata.dev/properties/drives";
/// The agent's single private home drive on a server (shared-with-me, personal data, etc.).
pub const PRIVATE_DRIVE: &str = "https://atomicdata.dev/properties/personalDrive";
/// Resources shared with this agent (e.g. accepted invites); clients show as "Shared with me".
pub const SHARED_WITH_ME: &str = "https://atomicdata.dev/properties/sharedWithMe";
pub const AVAILABLE_DOMAINS: &str = "https://atomicdata.dev/properties/availableDomains";
/// Identifies a version in a resource's Loro history. See [crate::history].
pub const VERSION_ID: &str = "https://atomicdata.dev/properties/versionId";

// ... for the Server (node) itself, served by the `/server` endpoint
pub const SERVER: &str = "https://atomicdata.dev/classes/Server";
pub const SERVER_NODE_ID: &str = "https://atomicdata.dev/properties/server/nodeId";
pub const SERVER_VERSION: &str = "https://atomicdata.dev/properties/server/version";
pub const SERVER_MANAGED: &str = "https://atomicdata.dev/properties/server/managed";
pub const SERVER_PORTAL_URL: &str = "https://atomicdata.dev/properties/server/portalUrl";
/// The Drive this server serves as its front page, if configured
/// (`ATOMIC_HOME_DRIVE`). Absent when `/` should fall back to the sign-in flow.
pub const SERVER_HOME_DRIVE: &str = "https://atomicdata.dev/properties/server/homeDrive";
/// The devices this node syncs with directly — nested [PEER] resources.
pub const SERVER_PEERS: &str = "https://atomicdata.dev/properties/server/peers";
/// `open` or `owner` — who may create a new Drive here. Absent on a node older
/// than host mode, which clients must read as `open`: that is what it does.
pub const SERVER_HOST_MODE: &str = "https://atomicdata.dev/properties/server/hostMode";
pub const SERVER_ACCEPTS_NEW_DRIVES: &str =
    "https://atomicdata.dev/properties/server/acceptsNewDrives";
pub const SERVER_OWNER_SET: &str = "https://atomicdata.dev/properties/server/ownerSet";

// ... for Peers
pub const PEER_NODE_ID: &str = "https://atomicdata.dev/properties/peer/nodeId";
pub const PEER_DEVICE_NAME: &str = "https://atomicdata.dev/properties/peer/deviceName";
pub const PEER_AGENT: &str = "https://atomicdata.dev/properties/peer/agent";
pub const PEER_LAST_SEEN: &str = "https://atomicdata.dev/properties/peer/lastSeen";
/// True while the peer holds an open connection to the node reporting it.
pub const PEER_LIVE: &str = "https://atomicdata.dev/properties/peer/live";
/// Resources moved by the LAST completed sync with this peer — not a lifetime
/// total. See `KnownPeer::last_sent`.
pub const PEER_LAST_SENT: &str = "https://atomicdata.dev/properties/peer/lastSent";
pub const PEER_LAST_RECEIVED: &str = "https://atomicdata.dev/properties/peer/lastReceived";
// ... for Collections
pub const COLLECTION_PROPERTY: &str = "https://atomicdata.dev/properties/collection/property";
pub const COLLECTION_VALUE: &str = "https://atomicdata.dev/properties/collection/value";
pub const COLLECTION_MEMBER_COUNT: &str =
    "https://atomicdata.dev/properties/collection/totalMembers";
pub const COLLECTION_TOTAL_PAGES: &str = "https://atomicdata.dev/properties/collection/totalPages";
pub const COLLECTION_CURRENT_PAGE: &str =
    "https://atomicdata.dev/properties/collection/currentPage";
pub const COLLECTION_MEMBERS: &str = "https://atomicdata.dev/properties/collection/members";
pub const COLLECTION_INCLUDE_NESTED: &str =
    "https://atomicdata.dev/properties/collection/includeNested";
pub const COLLECTION_INCLUDE_EXTERNAL: &str =
    "https://atomicdata.dev/properties/collection/includeExternal";
pub const COLLECTION_PAGE_SIZE: &str = "https://atomicdata.dev/properties/collection/pageSize";
pub const COLLECTION_SORT_BY: &str = "https://atomicdata.dev/properties/collection/sortBy";
pub const COLLECTION_SORT_DESC: &str = "https://atomicdata.dev/properties/collection/sortDesc";
pub const COLLECTION_AGGREGATES: &str = "https://atomicdata.dev/properties/collection/aggregates";
// ... for Endpoints
pub const ENDPOINT_PARAMETERS: &str = "https://atomicdata.dev/properties/endpoint/parameters";
pub const ENDPOINT_RESULTS: &str = "https://atomicdata.dev/properties/endpoint/results";
pub const ENDPOINT_IS_POST: &str = "https://atomicdata.dev/properties/endpoint/isPost";
pub const PATH: &str = "https://atomicdata.dev/properties/path";
pub const SEARCH_QUERY: &str = "https://atomicdata.dev/properties/search/query";
pub const SEARCH_LIMIT: &str = "https://atomicdata.dev/properties/search/limit";
pub const SEARCH_PROPERTY: &str = "https://atomicdata.dev/properties/search/property";
pub const SETUP_RESET: &str = "https://atomicdata.dev/properties/setup/reset";
pub const SEARCH_CHUNKS: &str = "https://atomicdata.dev/properties/search/chunks";
pub const URL: &str = "https://atomicdata.dev/property/url";
pub const PREVIEW: &str = "https://atomicdata.dev/property/preview";
// ... for Bookmarks
pub const IMAGE_URL: &str = "https://atomicdata.dev/properties/imageUrl";
// ... for Hierarchy / Drive
pub const PARENT: &str = "https://atomicdata.dev/properties/parent";
pub const READ: &str = "https://atomicdata.dev/properties/read";
pub const WRITE: &str = "https://atomicdata.dev/properties/write";
pub const APPEND: &str = "https://atomicdata.dev/properties/append";
pub const CHILDREN: &str = "https://atomicdata.dev/properties/children";
pub const SUBRESOURCES: &str = "https://atomicdata.dev/properties/subresources";
pub const SUBDOMAIN: &str = "https://atomicdata.dev/properties/subdomain";
pub const INITIAL_DRIVE: &str = "https://atomicdata.dev/properties/initialDrive";
// ... for Inivtations
pub const DESTINATION: &str = "https://atomicdata.dev/properties/destination";
pub const TARGET: &str = "https://atomicdata.dev/properties/invite/target";
pub const USAGES_LEFT: &str = "https://atomicdata.dev/properties/invite/usagesLeft";
pub const USED_BY: &str = "https://atomicdata.dev/properties/invite/usedBy";
pub const WRITE_BOOL: &str = "https://atomicdata.dev/properties/invite/write";
pub const INVITE_PUBKEY: &str = "https://atomicdata.dev/properties/invite/publicKey";
pub const INVITE_AGENT: &str = "https://atomicdata.dev/properties/invite/agent";
pub const REDIRECT_AGENT: &str = "https://atomicdata.dev/properties/invite/redirectAgent";
pub const EXPIRES_AT: &str = "https://atomicdata.dev/properties/invite/expiresAt";
// ... for Atoms
pub const ATOM_SUBJECT: &str = "https://atomicdata.dev/properties/atom/subject";
pub const ATOM_PROPERTY: &str = "https://atomicdata.dev/properties/atom/property";
pub const ATOM_VALUE: &str = "https://atomicdata.dev/properties/atom/value";
// ... for Files
pub const CHECKSUM: &str = "https://atomicdata.dev/properties/checksum";
pub const BLOB: &str = "https://atomicdata.dev/properties/blob";
/// Ordered list of `did:ad:blob:` chunk references; concatenated, they are the
/// file's bytes. Present on content-defined-chunked files, superseding `BLOB`.
pub const CHUNKS: &str = "https://atomicdata.dev/properties/chunks";
pub const FILENAME: &str = "https://atomicdata.dev/properties/filename";
pub const FILESIZE: &str = "https://atomicdata.dev/properties/filesize";
pub const MIMETYPE: &str = "https://atomicdata.dev/properties/mimetype";
pub const INTERNAL_ID: &str = "https://atomicdata.dev/properties/internalId";
pub const DOWNLOAD_URL: &str = "https://atomicdata.dev/properties/downloadURL";
pub const ATTACHMENTS: &str = "https://atomicdata.dev/properties/attachments";
pub const IMAGE_WIDTH: &str = "https://atomicdata.dev/properties/imageWidth";
pub const IMAGE_HEIGHT: &str = "https://atomicdata.dev/properties/imageHeight";
// ... for ChatRooms and Messages
pub const MESSAGES: &str = "https://atomicdata.dev/properties/messages";
pub const NEXT_PAGE: &str = "https://atomicdata.dev/properties/nextPage";
pub const ABOUT: &str = "https://atomicdata.dev/properties/about";
pub const COMMENTS_FOLDER: &str = "https://atomicdata.dev/properties/commentsFolder";
pub const MEETINGS_FOLDER: &str = "https://atomicdata.dev/properties/meetingsFolder";
pub const FOLLOW_SESSIONS_CHATROOM: &str =
    "https://atomicdata.dev/properties/followSessionsChatroom";
// ... for DocumentV2
pub const DOCUMENT_CONTENT: &str = "https://atomicdata.dev/properties/documentContent";
// ... for Importers
pub const IMPORTER_URL: &str = "https://atomicdata.dev/properties/importer/url";
pub const IMPORTER_JSON: &str = "https://atomicdata.dev/properties/importer/json";
pub const IMPORTER_PARENT: &str = "https://atomicdata.dev/properties/importer/parent";
pub const IMPORTER_OVERWRITE_OUTSIDE: &str =
    "https://atomicdata.dev/properties/importer/overwrite-outside";
pub const LOCAL_ID: &str = "https://atomicdata.dev/properties/localId";
pub const PROPERTIES: &str = "https://atomicdata.dev/properties/properties";
pub const CLASSES: &str = "https://atomicdata.dev/properties/classes";
pub const INSTANCES: &str = "https://atomicdata.dev/properties/instances";
// ... for Endpoint-Response
pub const STATUS: &str = "https://atomicdata.dev/ontology/server/property/status";
pub const RESPONSE_MESSAGE: &str =
    "https://atomicdata.dev/ontology/server/property/response-message";
// ... for Plugins
pub const PLUGIN_FILE: &str = "https://atomicdata.dev/properties/pluginFile";
pub const VERSION: &str = "https://atomicdata.dev/properties/version";
pub const CONFIG: &str = "https://atomicdata.dev/properties/config";
pub const NAMESPACE: &str = "https://atomicdata.dev/properties/namespace";
pub const PLUGINS: &str = "https://atomicdata.dev/properties/plugins";
pub const JSON_SCHEMA: &str = "https://atomicdata.dev/properties/jsonSchema";
pub const PLUGIN_AUTHOR: &str = "https://atomicdata.dev/properties/pluginAuthor";
pub const PLUGIN_AGENT: &str = "https://atomicdata.dev/properties/pluginAgent";
pub const PLUGIN_PERMISSIONS: &str = "https://atomicdata.dev/properties/pluginPermissions";
// ... for Forms
pub const FORM_DATA_CLASS: &str = "https://atomicdata.dev/properties/form-data-class";
pub const FORM_TARGET_TABLE: &str = "https://atomicdata.dev/properties/form-target-table";
pub const FORM_PAGES: &str = "https://atomicdata.dev/properties/form-pages";
pub const FORM_PUBLISHED_AT: &str = "https://atomicdata.dev/properties/form-published-at";
pub const FORM_SETTINGS: &str = "https://atomicdata.dev/properties/form-settings";
pub const FORM_PUBLISH_ID: &str = "https://atomicdata.dev/properties/form-publish-id";
pub const FORM_FIELDS: &str = "https://atomicdata.dev/properties/form-fields";
pub const COVER_IMAGE: &str = "https://atomicdata.dev/properties/cover-image";
pub const IMAGE_POSITION: &str = "https://atomicdata.dev/properties/image-position";
pub const FORM_MAPS_TO: &str = "https://atomicdata.dev/properties/form-maps-to";
pub const REQUIRED: &str = "https://atomicdata.dev/properties/required";
pub const FORM_FIELD_TYPE: &str = "https://atomicdata.dev/properties/form-field-type";
pub const FORM_FIELD_OPTIONS: &str = "https://atomicdata.dev/properties/form-field-options";
// AI
pub const TEXT_PART: &str = "https://atomicdata.dev/01jtjxtsa9syxmfca2zx5gcnmj/class/text-part";
pub const REASONING_PART: &str =
    "https://atomicdata.dev/01jtjxtsa9syxmfca2zx5gcnmj/class/reasoning-part";
// Datatypes
pub const STRING: &str = "https://atomicdata.dev/datatypes/string";
pub const MARKDOWN: &str = "https://atomicdata.dev/datatypes/markdown";
pub const SLUG: &str = "https://atomicdata.dev/datatypes/slug";
pub const ATOMIC_URL: &str = "https://atomicdata.dev/datatypes/atomicURL";
pub const INTEGER: &str = "https://atomicdata.dev/datatypes/integer";
pub const FLOAT: &str = "https://atomicdata.dev/datatypes/float";
pub const RESOURCE_ARRAY: &str = "https://atomicdata.dev/datatypes/resourceArray";
pub const BOOLEAN: &str = "https://atomicdata.dev/datatypes/boolean";
pub const DATE: &str = "https://atomicdata.dev/datatypes/date";
pub const TIMESTAMP: &str = "https://atomicdata.dev/datatypes/timestamp";
pub const URI: &str = "https://atomicdata.dev/datatypes/uri";
pub const JSON: &str = "https://atomicdata.dev/datatypes/json";
pub const LORO_DOC: &str = "https://atomicdata.dev/datatypes/lorodoc";
pub const LOCALIZED_TEXT: &str = "https://atomicdata.dev/datatypes/localizedText";

// Methods
pub const INSERT: &str = "https://atomicdata.dev/methods/insert";
pub const DELETE: &str = "https://atomicdata.dev/methods/delete";

// Instances
pub const PUBLIC_AGENT: &str = "https://atomicdata.dev/agents/publicAgent";
// The Sudo Agent does not use an HTTP(S) identifier, because it should never resolve.
// We don't want a user to actually control this URL.
pub const SUDO_AGENT: &str = "sudo:agent";

// Paths
pub fn construct_path_import(base: &str) -> String {
    format!("{base}{PATH_IMPORT}")
}

pub const PATH_IMPORT: &str = "/import";
pub const PATH_FETCH_BOOKMARK: &str = "/fetch-bookmark";
pub const PATH_QUERY: &str = "/query";
pub const PATH_PRUNE_TESTS: &str = "/prunetests";
pub const PATH_INVITE: &str = "/invites";
