/// Property URLs used by the store itself.
abstract final class Props {
  static const isA = 'https://atomicdata.dev/properties/isA';
  static const name = 'https://atomicdata.dev/properties/name';
  static const description = 'https://atomicdata.dev/properties/description';
  static const parent = 'https://atomicdata.dev/properties/parent';
  static const sortOrder = 'https://atomicdata.dev/properties/sortOrder';
  static const shortname = 'https://atomicdata.dev/properties/shortname';
  static const createdAt = 'https://atomicdata.dev/properties/createdAt';

  /// The properties above that hold links, which [Resource.set] stores as
  /// links when you pass a plain `String` ([isA] as a list of one link). A
  /// property of your own is not in this set: use `LinkValue` for it.
  static const linkProperties = {isA, parent};

  /// The rich-text body of a [Classes.documentV2]. Lives in the resource's
  /// Loro document, not as a plain value: edit it with the editor, not `set`.
  static const documentContent =
      'https://atomicdata.dev/properties/documentContent';

  /// File properties (a [Classes.file]).
  static const filename = 'https://atomicdata.dev/properties/filename';
  static const mimetype = 'https://atomicdata.dev/properties/mimetype';
  static const downloadUrl = 'https://atomicdata.dev/properties/downloadURL';
}

/// Class URLs of the resources apps create most.
abstract final class Classes {
  static const drive = 'https://atomicdata.dev/classes/Drive';
  static const folder = 'https://atomicdata.dev/classes/Folder';
  static const documentV2 = 'https://atomicdata.dev/classes/DocumentV2';
  static const file = 'https://atomicdata.dev/classes/File';
  static const chatRoom = 'https://atomicdata.dev/classes/ChatRoom';
  static const message = 'https://atomicdata.dev/classes/Message';
  static const table = 'https://atomicdata.dev/classes/Table';
  static const tag = 'https://atomicdata.dev/classes/Tag';
}
