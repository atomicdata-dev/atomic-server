import 'dart:convert';
import 'dart:typed_data';

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart' show FakeApi, app;

/// A 1x1 png.
final Uint8List _png = base64Decode(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==');

/// An image that never loads.
class _Broken extends ImageProvider<_Broken> {
  @override
  Future<_Broken> obtainKey(ImageConfiguration c) async => this;
  @override
  ImageStreamCompleter loadImage(_Broken key, ImageDecoderCallback decode) =>
      OneFrameImageStreamCompleter(Future.error(Exception('404')));
}

ImageProvider? _unwrap(ImageProvider p) {
  var cur = p;
  while (cur is ResizeImage) {
    cur = cur.imageProvider;
  }
  return cur;
}

Widget _wrap(Widget child) => app(Scaffold(body: Center(child: child)));

Image _image(WidgetTester tester) => tester.widget<Image>(find.byType(Image));

void main() {
  testWidgets(
      'a url: the image is drawn at the size it is shown, over the initial',
      (tester) async {
    tester.view.devicePixelRatio = 3;
    addTearDown(tester.view.reset);
    String? asked;
    await tester.pumpWidget(_wrap(ProfileAvatar(
      name: 'Joep',
      radius: 12,
      imageUrl: 'https://example.test/me.png',
      imageFactory: (url) {
        asked = url;
        return MemoryImage(_png);
      },
    )));
    expect(asked, 'https://example.test/me.png');
    final image = _image(tester);
    expect(image.width, 24);
    expect(image.filterQuality, FilterQuality.medium);
    final resize = image.image as ResizeImage;
    expect(resize.width, 72);
    expect(_unwrap(image.image), isA<MemoryImage>());
    // The initial is there while it loads.
    expect(find.text('J'), findsOneWidget);
  });

  testWidgets('no picture: the initial, no image', (tester) async {
    await tester.pumpWidget(_wrap(const ProfileAvatar(name: 'joep')));
    expect(find.byType(Image), findsNothing);
    expect(find.text('J'), findsOneWidget);
    for (final url in [
      '',
      '   ',
      'not a url',
      '/relative.png',
      'file:///a.png'
    ]) {
      await tester
          .pumpWidget(_wrap(ProfileAvatar(name: 'Joep', imageUrl: url)));
      expect(find.byType(Image), findsNothing, reason: url);
      expect(find.text('J'), findsOneWidget, reason: url);
    }
  });

  testWidgets('bytes win over the url', (tester) async {
    await tester.pumpWidget(_wrap(ProfileAvatar(
      name: 'Joep',
      imageUrl: 'https://example.test/me.png',
      imageBytes: _png,
      imageFactory: (_) => fail('the url is not needed'),
    )));
    expect(_unwrap(_image(tester).image), isA<MemoryImage>());
  });

  testWidgets('a data: uri is decoded in place, not fetched', (tester) async {
    await tester.pumpWidget(_wrap(ProfileAvatar(
        name: 'Joep',
        imageUrl: 'data:image/png;base64,${base64Encode(_png)}')));
    expect(_unwrap(_image(tester).image), isA<MemoryImage>());
  });

  testWidgets('an http url is fetched through the network image',
      (tester) async {
    await tester.pumpWidget(_wrap(const ProfileAvatar(
        name: 'Joep', imageUrl: 'https://example.test/me.png')));
    expect(_unwrap(_image(tester).image), isA<NetworkImage>());
  });

  testWidgets('a picture that fails keeps the initial and logs why',
      (tester) async {
    final logs = <String?>[];
    final old = debugPrint;
    debugPrint = (m, {wrapWidth}) => logs.add(m);
    await tester.pumpWidget(_wrap(ProfileAvatar(
        name: 'Joep',
        imageUrl: 'https://example.test/me.png',
        imageFactory: (_) => _Broken())));
    await tester.pump();
    await tester.pump();
    expect(find.text('J'), findsOneWidget);
    debugPrint = old;
    expect(logs.any((l) => l?.contains('no picture') ?? false), isTrue);
  });

  testWidgets('bytes that are not an image keep the initial', (tester) async {
    await tester.pumpWidget(_wrap(ProfileAvatar(
        name: 'Joep', imageBytes: Uint8List.fromList([1, 2, 3, 4]))));
    await tester
        .runAsync(() => Future<void>.delayed(const Duration(milliseconds: 50)));
    await tester.pump();
    await tester.pump();
    expect(find.text('J'), findsOneWidget);
    // The decode error is reported by the image, not thrown at the test.
    tester.takeException();
  });

  test('a relative url is resolved against the server', () {
    expect(resolveAvatarUrl('/download/me.png', base: 'https://a.test/x/y'),
        'https://a.test/download/me.png');
    expect(resolveAvatarUrl('me.png', base: 'https://a.test/x/'),
        'https://a.test/x/me.png');
    expect(resolveAvatarUrl('https://b.test/me.png', base: 'https://a.test'),
        'https://b.test/me.png');
    expect(resolveAvatarUrl('/me.png'), '');
    expect(resolveAvatarUrl(null, base: 'https://a.test'), '');
    expect(resolveAvatarUrl('  ', base: 'https://a.test'), '');
  });

  testWidgets('a relative url is resolved before the image is asked for',
      (tester) async {
    String? asked;
    await tester.pumpWidget(_wrap(ProfileAvatar(
      name: 'Joep',
      imageUrl: '/download/me.png',
      baseUrl: 'https://a.test',
      imageFactory: (url) {
        asked = url;
        return MemoryImage(_png);
      },
    )));
    expect(asked, 'https://a.test/download/me.png');
  });

  testWidgets('the name is the semantics label', (tester) async {
    final handle = tester.ensureSemantics();
    await tester.pumpWidget(_wrap(const ProfileAvatar(name: 'Joep')));
    expect(find.bySemanticsLabel(RegExp('Joep')), findsOneWidget);
    handle.dispose();
  });

  group('in the shell', () {
    setUp(() => SharedPreferences.setMockInitialValues({}));

    Widget shell(AssistantApi api, {ShellController? out}) => app(AppShell(
          api: api,
          drive: 'did:ad:drive',
          warmPool: (_) => null,
          profile: (_) => const Scaffold(body: Text('profile page')),
          home: ChatsScreen(drive: 'did:ad:drive', api: api),
        ));

    ShellController controller(WidgetTester tester) =>
        tester.widget<ShellScope>(find.byType(ShellScope)).controller;

    testWidgets('a profile that arrives later swaps the picture in',
        (tester) async {
      tester.view.devicePixelRatio = 1;
      tester.view.physicalSize = const Size(360, 800);
      addTearDown(tester.view.reset);
      final api = _Api(const ProfileIdentity(name: 'Joep', pendingImage: true));
      await tester.pumpWidget(shell(api));
      await tester.pump();
      await tester.pump();
      expect(find.byType(Image), findsNothing);
      expect(find.text('J'), findsOneWidget);

      // The File and its bytes have synced in: the next load has the picture.
      api.who = ProfileIdentity(name: 'Joep', imageBytes: _png);
      await controller(tester).refreshIdentity();
      await tester.pump();
      expect(find.byType(Image), findsOneWidget);
    });

    testWidgets('a picture that is pending is asked for again', (tester) async {
      tester.view.devicePixelRatio = 1;
      tester.view.physicalSize = const Size(360, 800);
      addTearDown(tester.view.reset);
      final api = _Api(const ProfileIdentity(name: 'Joep', pendingImage: true));
      await tester.pumpWidget(shell(api));
      await tester.pump();
      controller(tester).identityRetries = const [
        Duration(seconds: 1),
        Duration(seconds: 1),
      ];
      await controller(tester).refreshIdentity();
      final loads = api.loads;
      api.who = ProfileIdentity(name: 'Joep', imageBytes: _png);
      await tester.pump(const Duration(seconds: 2));
      await tester.pump();
      expect(api.loads, greaterThan(loads));
      expect(find.byType(Image), findsOneWidget);
    });

    testWidgets('a failed read does not take the shown picture away',
        (tester) async {
      tester.view.devicePixelRatio = 1;
      tester.view.physicalSize = const Size(360, 800);
      addTearDown(tester.view.reset);
      final api = _Api(ProfileIdentity(name: 'Joep', imageBytes: _png));
      await tester.pumpWidget(shell(api));
      await tester.pump();
      await tester.pump();
      expect(find.byType(Image), findsOneWidget);
      controller(tester).identityRetries = const [];
      api.who = const ProfileIdentity(name: 'Joep', pendingImage: true);
      await controller(tester).refreshIdentity();
      await tester.pump();
      expect(find.byType(Image), findsOneWidget);
    });

    testWidgets('another account without a picture replaces the picture',
        (tester) async {
      tester.view.devicePixelRatio = 1;
      tester.view.physicalSize = const Size(360, 800);
      addTearDown(tester.view.reset);
      final api = _Api(ProfileIdentity(name: 'Joep', imageBytes: _png));
      await tester.pumpWidget(shell(api));
      await tester.pump();
      await tester.pump();
      api.who = const ProfileIdentity(name: 'Polle');
      await controller(tester).refreshIdentity();
      await tester.pump();
      expect(find.byType(Image), findsNothing);
      expect(find.text('P'), findsOneWidget);
    });
  });
}

class _Api extends FakeApi {
  ProfileIdentity? who;
  int loads = 0;
  _Api(this.who);

  @override
  Future<ProfileIdentity?> ownIdentity() async {
    loads++;
    return who;
  }
}
