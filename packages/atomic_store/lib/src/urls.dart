/// Property URLs used by the store itself.
abstract final class Props {
  static const isA = 'https://atomicdata.dev/properties/isA';
  static const name = 'https://atomicdata.dev/properties/name';
  static const description = 'https://atomicdata.dev/properties/description';
  static const parent = 'https://atomicdata.dev/properties/parent';
  static const sortOrder = 'https://atomicdata.dev/properties/sortOrder';
}

/// Class URLs of the resources apps create most.
abstract final class Classes {
  static const drive = 'https://atomicdata.dev/classes/Drive';
  static const folder = 'https://atomicdata.dev/classes/Folder';
  static const documentV2 = 'https://atomicdata.dev/classes/DocumentV2';
}
