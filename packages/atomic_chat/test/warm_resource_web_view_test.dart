import 'dart:async';
import 'dart:convert';

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'unimplemented_api.dart';

class FakeWarmPage implements WarmPage {
  FakeWarmPage(this.send);
  final void Function(String message) send;
  final scripts = <String>[];
  final _ready = Completer<void>();
  bool released = false;
  void Function(String)? handler;
  VoidCallback? loaded;

  void becomeReady() => _ready.complete();
  void fail() {
    _ready.future.ignore();
    _ready.completeError('boom');
  }

  @override
  bool get isReady => _ready.isCompleted && !released;
  @override
  Future<void> get whenReady => _ready.future;
  @override
  set onMessage(void Function(String)? h) => handler = h;
  @override
  set onLoaded(VoidCallback? h) => loaded = h;
  @override
  Future<void> runJavaScript(String script) async => scripts.add(script);
  @override
  Future<Object> runJavaScriptReturningResult(String script) async => false;
  @override
  Widget build() => const Center(child: Text('warm page'));
  @override
  void release() => released = true;
}

class _Api extends UnimplementedApi {
  const _Api();
  @override
  Future<String> embedCall(String method, String argsJson) async => '"x"';
}

class _CountingApi extends UnimplementedApi {
  final calls = <String>[];
  @override
  Future<String> embedCall(String method, String argsJson) async {
    calls.add('$method $argsJson');
    return '[${calls.length}]';
  }
}

/// Answers each read with one `{s: subject}` row per subject.
class _RowsApi extends UnimplementedApi {
  final asked = <List<Object?>>[];
  @override
  Future<String> embedCall(String method, String argsJson) async {
    final subjects = (jsonDecode(argsJson) as List).first as List<Object?>;
    asked.add(subjects);
    return jsonEncode([
      for (final s in subjects) {'s': s}
    ]);
  }
}

void main() {
  final pages = <FakeWarmPage>[];
  late WarmResourceWebView pool;

  WarmResourceWebView makePool({bool failFirst = false}) {
    var n = 0;
    return WarmResourceWebView(
      api: const _Api(),
      rewarmDelay: Duration.zero,
      backgroundGrace: const Duration(minutes: 5),
      builder: (onMessage) async {
        if (failFirst && n++ == 0) throw StateError('no server');
        final p = FakeWarmPage(onMessage);
        pages.add(p);
        return p;
      },
    );
  }

  setUp(pages.clear);
  tearDown(() => pool.dispose());

  test('warmUp makes exactly one spare', () async {
    pool = makePool();
    pool
      ..warmUp()
      ..warmUp();
    await pumpEventQueue();
    expect(pages, hasLength(1));
    expect(pool.hasSpare, isTrue);
    expect(pool.isReady, isFalse);
  });

  test('a spare that is not ready is not taken', () async {
    pool = makePool()..warmUp();
    await pumpEventQueue();
    expect(pool.take(), isNull);
    // It is still the spare, and gets taken once it is up.
    pages.single.becomeReady();
    await pumpEventQueue();
    final spare = pages.single;
    expect(pool.take(), same(spare));
  });

  test('taking a ready spare warms the next one, and only one', () async {
    pool = makePool()..warmUp();
    await pumpEventQueue();
    pages.single.becomeReady();
    await pumpEventQueue();

    final first = pool.take();
    expect(first, same(pages.first));
    await pumpEventQueue();
    expect(pages, hasLength(2));
    expect((first! as FakeWarmPage).released, isFalse,
        reason: 'the taker owns it');

    // Nothing more is started while the new spare lives.
    pool.warmUp();
    await pumpEventQueue();
    expect(pages, hasLength(2));
    expect(pool.take(), isNull);
  });

  test('a ready spare renders the likely next resource, then goes blank',
      () async {
    pool = makePool()..showAhead = () async => 'https://x/next';
    pool.warmUp();
    await pumpEventQueue();
    final page = pages.single;
    expect(page.scripts, isEmpty, reason: 'not before it is up');
    page.becomeReady();
    await pumpEventQueue();
    expect(page.scripts.single,
        allOf(contains('e.show("https://x/next")'), contains('e.show("")')),
        reason: 'shown, then blank: an attached page that already shows '
            'what it is asked for does not paint again');
    expect(WarmResourceWebView.shownAhead[page], 'https://x/next');
  });

  test('a page rendered ahead is not noted as opened', () async {
    pool = makePool()..warmUp();
    await pumpEventQueue();
    final page = pages.single;
    page.send(jsonEncode({
      'id': 4,
      'method': 'opened',
      'args': ['https://x/next']
    }));
    await pumpEventQueue();
    // Answered by the pool itself (the API would have noted it in Recents).
    expect(page.scripts.single, 'window.__atomicReply(4,true,null)');
  });

  test('a spare reporting the saved theme sets the app\'s', () async {
    SharedPreferences.setMockInitialValues({});
    addTearDown(() => AppThemeMode.mode.value = ThemeMode.system);
    pool = makePool()..warmUp();
    await pumpEventQueue();
    final page = pages.single;
    page.send(jsonEncode({
      'id': 3,
      'method': 'theme',
      'args': ['dark'],
    }));
    await pumpEventQueue();
    expect(AppThemeMode.mode.value, ThemeMode.dark);
    expect(page.scripts, contains('window.__atomicReply(3,true,"true")'));
  });

  test('a read started on pointer-down answers the page\'s first call once',
      () async {
    final api = _CountingApi();
    pool = WarmResourceWebView(
        api: api, rewarmDelay: Duration.zero, builder: (_) async => throw 'x');
    pool.prefetch('did:ad:doc');
    pool.prefetch('did:ad:doc');
    expect(api.calls, ['getResourcesWithSnapshots [["did:ad:doc"]]'],
        reason: 'a second pointer-down right after reads nothing again');

    expect(pool.takePrefetched('getResourcesWithSnapshots', '[["did:ad:x"]]'),
        isNull,
        reason: 'another resource');
    expect(pool.takePrefetched('query', '[["did:ad:doc"]]'), isNull);
    final answer =
        pool.takePrefetched('getResourcesWithSnapshots', '[["did:ad:doc"]]');
    expect(await answer, '[1]');
    expect(pool.takePrefetched('getResourcesWithSnapshots', '[["did:ad:doc"]]'),
        isNull,
        reason: 'taken once; later reads go to the store');
  });

  test('a prefetched resource read in one batch with others keeps its place',
      () async {
    final api = _RowsApi();
    pool = WarmResourceWebView(
        api: api, rewarmDelay: Duration.zero, builder: (_) async => throw 'x');
    pool.prefetch('b');
    final answer =
        pool.takePrefetched('getResourcesWithSnapshots', '[["a","b","c"]]');
    expect(jsonDecode((await answer)!), [
      {'s': 'a'},
      {'s': 'b'},
      {'s': 'c'},
    ]);
    expect(api.asked, [
      ['b'],
      ['a', 'c'],
    ]);
  });

  test('a failed start leaves no spare and take opens cold', () async {
    pool = makePool(failFirst: true)..warmUp();
    await pumpEventQueue();
    expect(pool.failures, 1);
    expect(pool.hasSpare, isFalse);
    expect(pool.take(), isNull);
    pool.warmUp();
    await pumpEventQueue();
    expect(pages, hasLength(1));
  });

  test('a spare that fails while loading is dropped and released', () async {
    pool = makePool()..warmUp();
    await pumpEventQueue();
    pages.single.fail();
    await pumpEventQueue();
    expect(pool.failures, 1);
    expect(pool.hasSpare, isFalse);
    expect(pages.single.released, isTrue);
  });

  test('dispose and release drop the spare', () async {
    pool = makePool()..warmUp();
    await pumpEventQueue();
    pool.release();
    expect(pages.single.released, isTrue);
    expect(pool.hasSpare, isFalse);
    pool.warmUp();
    await pumpEventQueue();
    expect(pages, hasLength(2));
    pool.dispose();
    expect(pages.last.released, isTrue);
    pool.warmUp();
    await pumpEventQueue();
    expect(pages, hasLength(2), reason: 'a disposed pool starts nothing');
  });

  testWidgets('a long time in the background drops the spare; return warms',
      (tester) async {
    pool = WarmResourceWebView(
      api: const _Api(),
      rewarmDelay: Duration.zero,
      backgroundGrace: const Duration(seconds: 30),
      builder: (m) async {
        final p = FakeWarmPage(m)..becomeReady();
        pages.add(p);
        return p;
      },
    )..warmUp();
    await tester.pump();
    expect(pool.isReady, isTrue);

    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
    await tester.pump(const Duration(seconds: 10));
    expect(pool.isReady, isTrue);
    await tester.pump(const Duration(seconds: 25));
    expect(pool.hasSpare, isFalse);
    expect(pages.single.released, isTrue);

    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pump();
    expect(pages, hasLength(2));
  });

  group('ResourceView with a spare', () {
    Future<void> openView(WidgetTester tester, ShellController shell) async {
      await tester.pumpWidget(MaterialApp(
        theme: ThemeData(extensions: const [AppColors.light]),
        home: ShellScope(
          controller: shell,
          child: const Scaffold(body: Text('home')),
        ),
      ));
      final navigator = tester.state<NavigatorState>(find.byType(Navigator));
      navigator.push(MaterialPageRoute<void>(
        builder: (_) => ShellScope(
          controller: shell,
          child: const ResourceView(
              api: _Api(), drive: 'd', subject: 'https://x/s'),
        ),
      ));
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 400));
    }

    Future<void> closeAll(WidgetTester tester) async {
      await tester.pumpWidget(const SizedBox());
      await tester.pump(const Duration(seconds: 1));
    }

    setUp(() {
      ResourceView.releaseDelay = Duration.zero;
      ResourceView.flushTimeout = const Duration(milliseconds: 50);
    });

    testWidgets('takes the ready spare, shows the subject, warms the next',
        (tester) async {
      pool = makePool()..warmUp();
      await tester.pump();
      pages.single.becomeReady();
      await tester.pump();
      final shell = ShellController(drive: 'd')..warm = pool;

      await openView(tester, shell);

      expect(find.text('warm page'), findsOneWidget);
      final taken = pages.first;
      expect(taken.handler, isNotNull);
      expect(
          taken.scripts
              .any((s) => s.contains('e.open') && s.contains('"https://x/s"')),
          isTrue);
      // The colour scheme reaches the taken page like any other.
      expect(taken.scripts.any((s) => s.contains('setColorScheme')), isTrue);
      expect(pages, hasLength(2), reason: 'the next spare is warming');
      expect(pages.last.released, isFalse);
      await closeAll(tester);
    });

    testWidgets('the read started on pointer-down answers the page',
        (tester) async {
      final api = _CountingApi();
      pool = WarmResourceWebView(
        api: api,
        rewarmDelay: Duration.zero,
        builder: (onMessage) async {
          final p = FakeWarmPage(onMessage);
          pages.add(p);
          return p;
        },
      )..warmUp();
      await tester.pump();
      pages.single.becomeReady();
      await tester.pump();
      final shell = ShellController(drive: 'd')..warm = pool;
      pool.prefetch('https://x/s');

      await openView(tester, shell);
      final taken = pages.first;
      taken.handler!(jsonEncode({
        'id': 7,
        'method': 'getResourcesWithSnapshots',
        'args': [
          ['https://x/s']
        ],
      }));
      await tester.pump();
      expect(api.calls, hasLength(1), reason: 'not read a second time');
      expect(taken.scripts, contains('window.__atomicReply(7,true,"[1]")'));
      await closeAll(tester);
    });

    testWidgets('a page rendered ahead reads that resource again when taken',
        (tester) async {
      pool = makePool()..warmUp();
      await tester.pump();
      pages.single.becomeReady();
      await tester.pump();
      WarmResourceWebView.shownAhead[pages.single] = 'https://x/ahead';
      final shell = ShellController(drive: 'd')..warm = pool;

      await openView(tester, shell);

      expect(
          pages.first.scripts.any((s) =>
              s.contains('e.changed(["https://x/ahead"])') &&
              s.contains('"https://x/s"')),
          isTrue,
          reason: 'it may have changed while the page was hidden');
      await closeAll(tester);
    });

    testWidgets('leaving releases the taken page, not the spare',
        (tester) async {
      pool = makePool()..warmUp();
      await tester.pump();
      pages.single.becomeReady();
      await tester.pump();
      final shell = ShellController(drive: 'd')..warm = pool;
      await openView(tester, shell);
      final taken = pages.first;

      final navigator = tester.state<NavigatorState>(find.byType(Navigator));
      unawaited(navigator.maybePop());
      await tester.pump();
      // Answer the flush the view asked for.
      final id = RegExp(r'flush:(\d+)')
          .firstMatch(taken.scripts.lastWhere((s) => s.contains('flush:')))!
          .group(1);
      taken
          .handler!(jsonEncode({'method': 'flushed', 'flush': int.parse(id!)}));
      await tester.pumpAndSettle();
      await tester.pump(const Duration(milliseconds: 10));

      expect(find.text('home'), findsOneWidget);
      expect(taken.released, isTrue);
      expect(pages.last.released, isFalse);
    });

    testWidgets('without a ready spare it opens the cold way', (tester) async {
      pool = makePool()..warmUp();
      await tester.pump();
      final shell = ShellController(drive: 'd')..warm = pool;
      final cold = <FakePage>[];
      ResourceView.pageFactory = (send) {
        final p = FakePage(send);
        cold.add(p);
        return p;
      };
      addTearDown(() => ResourceView.pageFactory = null);

      await openView(tester, shell);

      expect(cold, hasLength(1));
      expect(find.text('cold page'), findsOneWidget);
      expect(pages.single.handler, isNull, reason: 'the spare stays spare');
      await closeAll(tester);
    });
  });
}

class FakePage implements EmbedPage {
  FakePage(this.send);
  final void Function(String) send;
  @override
  Future<void> runJavaScript(String script) async {}
  @override
  Future<Object> runJavaScriptReturningResult(String script) async => false;
  @override
  Widget build() => const Center(child: Text('cold page'));
}
