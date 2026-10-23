import 'dart:convert';

import 'exceptions.dart';

/// A property value, typed like the datatype of its property. Compare with
/// `==`; the classes are immutable.
sealed class Value {
  const Value();

  /// [raw] as a [Value]: a [Value] as is, a `String` as a string, `int`,
  /// `double` and `bool` as numbers and booleans, a `DateTime` as a timestamp,
  /// a `List` as an [ArrayValue] (its strings are links, because arrays hold
  /// links and nested resources only) and a `Map<String, Object?>` as a
  /// [NestedValue]. Use [LinkValue], [MarkdownValue] and the others to say more.
  static Value of(Object raw) => switch (raw) {
        Value v => v,
        String s => StringValue(s),
        int i => IntegerValue(i),
        double d => FloatValue(d),
        bool b => BooleanValue(b),
        DateTime t => TimestampValue(t.millisecondsSinceEpoch),
        List<Object?> l => ArrayValue([
            for (final e in l)
              switch (e) {
                String s => LinkValue(s),
                Object o => Value.of(o),
                null => throw const StoreException(
                    StoreErrorKind.invalid, 'An array cannot hold null'),
              }
          ]),
        Map<String, Object?> m => NestedValue({
            for (final e in m.entries)
              if (e.value != null) e.key: Value.of(e.value!)
          }),
        _ => throw StoreException(StoreErrorKind.invalid,
            'No Atomic value for a ${raw.runtimeType}'),
      };
}

final class StringValue extends Value {
  const StringValue(this.value);
  final String value;
  @override
  bool operator ==(Object other) => other is StringValue && other.value == value;
  @override
  int get hashCode => Object.hash(StringValue, value);
  @override
  String toString() => value;
}

final class MarkdownValue extends Value {
  const MarkdownValue(this.value);
  final String value;
  @override
  bool operator ==(Object other) =>
      other is MarkdownValue && other.value == value;
  @override
  int get hashCode => Object.hash(MarkdownValue, value);
  @override
  String toString() => value;
}

final class SlugValue extends Value {
  const SlugValue(this.value);
  final String value;
  @override
  bool operator ==(Object other) => other is SlugValue && other.value == value;
  @override
  int get hashCode => Object.hash(SlugValue, value);
  @override
  String toString() => value;
}

/// An ISO 8601 date, as text.
final class DateValue extends Value {
  const DateValue(this.value);
  final String value;
  @override
  bool operator ==(Object other) => other is DateValue && other.value == value;
  @override
  int get hashCode => Object.hash(DateValue, value);
  @override
  String toString() => value;
}

final class UriValue extends Value {
  const UriValue(this.value);
  final String value;
  @override
  bool operator ==(Object other) => other is UriValue && other.value == value;
  @override
  int get hashCode => Object.hash(UriValue, value);
  @override
  String toString() => value;
}

/// A link to another resource.
final class LinkValue extends Value {
  const LinkValue(this.subject);
  final String subject;
  @override
  bool operator ==(Object other) =>
      other is LinkValue && other.subject == subject;
  @override
  int get hashCode => Object.hash(LinkValue, subject);
  @override
  String toString() => subject;
}

final class IntegerValue extends Value {
  const IntegerValue(this.value);
  final int value;
  @override
  bool operator ==(Object other) =>
      other is IntegerValue && other.value == value;
  @override
  int get hashCode => Object.hash(IntegerValue, value);
  @override
  String toString() => '$value';
}

final class FloatValue extends Value {
  const FloatValue(this.value);
  final double value;
  @override
  bool operator ==(Object other) => other is FloatValue && other.value == value;
  @override
  int get hashCode => Object.hash(FloatValue, value);
  @override
  String toString() => '$value';
}

/// Unix epoch milliseconds.
final class TimestampValue extends Value {
  const TimestampValue(this.millis);
  final int millis;
  DateTime get dateTime =>
      DateTime.fromMillisecondsSinceEpoch(millis, isUtc: true);
  @override
  bool operator ==(Object other) =>
      other is TimestampValue && other.millis == millis;
  @override
  int get hashCode => Object.hash(TimestampValue, millis);
  @override
  String toString() => '$millis';
}

final class BooleanValue extends Value {
  const BooleanValue(this.value);
  final bool value;
  @override
  bool operator ==(Object other) =>
      other is BooleanValue && other.value == value;
  @override
  int get hashCode => Object.hash(BooleanValue, value);
  @override
  String toString() => '$value';
}

/// A list of [LinkValue]s and [NestedValue]s.
final class ArrayValue extends Value {
  const ArrayValue(this.items);
  final List<Value> items;

  /// The subjects of the links in the list.
  List<String> get links =>
      [for (final i in items) if (i is LinkValue) i.subject];

  @override
  bool operator ==(Object other) =>
      other is ArrayValue && _listEquals(other.items, items);
  @override
  int get hashCode => Object.hashAll(items);
  @override
  String toString() => '[${items.join(', ')}]';
}

/// A resource without a subject of its own, inside another.
final class NestedValue extends Value {
  const NestedValue(this.props);
  final Map<String, Value> props;
  @override
  bool operator ==(Object other) =>
      other is NestedValue && _mapEquals(other.props, props);
  @override
  int get hashCode => Object.hashAllUnordered(
      props.entries.map((e) => Object.hash(e.key, e.value)));
  @override
  String toString() => '{${props.entries.map((e) => '${e.key}: ${e.value}').join(', ')}}';
}

/// JSON text. The way to store what other datatypes cannot: a list of plain
/// strings (arrays hold links only), a small map, a list of numbers.
///
/// ```dart
/// todo.set(tags, JsonValue.strings(['urgent', 'home']));   // or todo.setStrings
/// todo.getStrings(tags);                                   // ['urgent', 'home']
/// ```
final class JsonValue extends Value {
  const JsonValue(this.json);

  /// [data] (anything `jsonEncode` accepts) as JSON text.
  factory JsonValue.encode(Object? data) => JsonValue(jsonEncode(data));

  /// A JSON array of [items].
  factory JsonValue.strings(Iterable<String> items) =>
      JsonValue(jsonEncode(items.toList()));

  final String json;

  /// The decoded JSON (`List`, `Map`, `String`, `num`, `bool` or `null`).
  /// Throws [FormatException] when [json] is not JSON.
  Object? get data => jsonDecode(json);
  @override
  bool operator ==(Object other) => other is JsonValue && other.json == json;
  @override
  int get hashCode => Object.hash(JsonValue, json);
  @override
  String toString() => json;
}

/// Translated strings by BCP 47 language tag.
final class LocalizedValue extends Value {
  const LocalizedValue(this.texts);
  final Map<String, String> texts;
  @override
  bool operator ==(Object other) =>
      other is LocalizedValue && _mapEquals(other.texts, texts);
  @override
  int get hashCode => Object.hashAllUnordered(
      texts.entries.map((e) => Object.hash(e.key, e.value)));
  @override
  String toString() => texts.toString();
}

/// A value this library cannot interpret (a Loro document, an unknown
/// datatype). It can be read but not written.
final class UnsupportedValue extends Value {
  const UnsupportedValue(this.datatype, this.description);
  final String datatype;
  final String description;
  @override
  bool operator ==(Object other) =>
      other is UnsupportedValue &&
      other.datatype == datatype &&
      other.description == description;
  @override
  int get hashCode => Object.hash(UnsupportedValue, datatype, description);
  @override
  String toString() => description;
}

bool _listEquals(List<Value> a, List<Value> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

bool _mapEquals<V>(Map<String, V> a, Map<String, V> b) {
  if (a.length != b.length) return false;
  for (final e in a.entries) {
    if (!b.containsKey(e.key) || b[e.key] != e.value) return false;
  }
  return true;
}
