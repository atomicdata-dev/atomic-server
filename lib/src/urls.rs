//! Contains some of the most important Atomic Data URLs.
//! See [crate::atomic_url] for the URL datatype.

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
pub const PARAGRAPH: &str = "https://atomicdata.dev/classes/elements/Paragraph";
pub const MESSAGE: &str = "https://atomicdata.dev/classes/Message";
pub const IMPORTER: &str = "https://atomicdata.dev/classes/Importer";
pub const ERROR: &str = "https://atomicdata.dev/classes/Error";
pub const BOOKMARK: &str = "https://atomicdata.dev/class/Bookmark";
pub const ONTOLOGY: &str = "https://atomicdata.dev/class/ontology";
pub const ENDPOINT_RESPONSE: &str =
    "https://atomicdata.dev/ontology/server/class/endpoint-response";
pub const TABLE: &str = "https://atomicdata.dev/classes/Table";

// Properties
pub const SHORTNAME: &str = "https://atomicdata.dev/properties/shortname";
pub const DESCRIPTION: &str = "https://atomicdata.dev/properties/description";
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
pub const SIGNER: &str = "https://atomicdata.dev/properties/signer";
pub const CREATED_AT: &str = "https://atomicdata.dev/properties/createdAt";
pub const SIGNATURE: &str = "https://atomicdata.dev/properties/signature";
pub const PREVIOUS_COMMIT: &str = "https://atomicdata.dev/properties/previousCommit";
pub const LAST_COMMIT: &str = "https://atomicdata.dev/properties/lastCommit";
// ... for Agents
pub const PUBLIC_KEY: &str = "https://atomicdata.dev/properties/publicKey";
pub const NAME: &str = "https://atomicdata.dev/properties/name";
pub const DRIVES: &str = "https://atomicdata.dev/properties/drives";
pub const EMAIL: &str = "https://atomicdata.dev/properties/email";
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
// ... for Endpoints
pub const ENDPOINT_PARAMETERS: &str = "https://atomicdata.dev/properties/endpoint/parameters";
pub const ENDPOINT_RESULTS: &str = "https://atomicdata.dev/properties/endpoint/results";
pub const PATH: &str = "https://atomicdata.dev/properties/path";
pub const SEARCH_QUERY: &str = "https://atomicdata.dev/properties/search/query";
pub const SEARCH_LIMIT: &str = "https://atomicdata.dev/properties/search/limit";
pub const SEARCH_PROPERTY: &str = "https://atomicdata.dev/properties/search/property";
pub const URL: &str = "https://atomicdata.dev/property/url";
pub const PREVIEW: &str = "https://atomicdata.dev/property/preview";
pub const TOKEN: &str = "https://atomicdata.dev/property/token";
// ... for Bookmarks
pub const IMAGE_URL: &str = "https://atomicdata.dev/properties/imageUrl";
// ... for Hierarchy / Drive
pub const PARENT: &str = "https://atomicdata.dev/properties/parent";
pub const READ: &str = "https://atomicdata.dev/properties/read";
pub const WRITE: &str = "https://atomicdata.dev/properties/write";
pub const APPEND: &str = "https://atomicdata.dev/properties/append";
pub const CHILDREN: &str = "https://atomicdata.dev/properties/children";
pub const SUBRESOURCES: &str = "https://atomicdata.dev/properties/subresources";
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

// Methods
pub const INSERT: &str = "https://atomicdata.dev/methods/insert";
pub const DELETE: &str = "https://atomicdata.dev/methods/delete";

// Instances
pub const PUBLIC_AGENT: &str = "https://atomicdata.dev/agents/publicAgent";
// The Sudo Agent does not use an HTTP(S) identifier, because it should never resolve.
// We don't want a user to actually control this URL.
pub const SUDO_AGENT: &str = "sudo:agent";

// Paths
pub const PATH_IMPORT: &str = "/import";
pub const PATH_FETCH_BOOKMARK: &str = "/fetch-bookmark";
pub const PATH_TPF: &str = "/tpf";
pub const PATH_PATH: &str = "/path";
pub const PATH_COMMITS: &str = "/commits";
pub const PATH_ENDPOINTS: &str = "/endpoints";
pub const PATH_REGISTER: &str = "/register";
pub const PATH_CONFIRM_EMAIL: &str = "/confirm-email";
pub const PATH_RESET_PUBKEY: &str = "/reset-public-key";
pub const PATH_CONFIRM_RESET: &str = "/confirm-reset-public-key";
pub const PATH_QUERY: &str = "/query";
pub const PATH_PRUNE_TESTS: &str = "/prunetests";
