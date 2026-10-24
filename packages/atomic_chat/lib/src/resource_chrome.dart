import 'dart:convert';

import 'package:atomic_flutter/atomic_flutter.dart' show AppColorsExt;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show Clipboard, ClipboardData;
import 'package:url_launcher/url_launcher.dart';

import 'app_shell.dart';
import 'assistant_api.dart';
import 'native_views.dart';
import 'resource_view.dart';
import 'slide_back_route.dart';
import 'toast.dart';

const _parentProperty = 'https://atomicdata.dev/properties/parent';
const _nameProperty = 'https://atomicdata.dev/properties/name';
const _shortnameProperty = 'https://atomicdata.dev/properties/shortname';
const _isAProperty = 'https://atomicdata.dev/properties/isA';

/// One step of a [ResourceBreadcrumbs] trail.
typedef Crumb = ({String subject, String title, String classUrl});

/// The chain drive > folder > ... above this resource, on one line scrolled to
/// its end: the web page's breadcrumbs for the screens the app draws itself
/// (its title bar already names the resource, so the chain stops above it). The
/// parents are read from the store (`getResource`, as the page does); a tap
/// on one opens it like a row would. Use as an [AppTopBar.bottom].
class ResourceBreadcrumbs extends StatefulWidget
    implements PreferredSizeWidget {
  static const height = 28.0;

  final AssistantApi api;
  final String drive;
  final String subject;

  const ResourceBreadcrumbs({
    super.key,
    required this.api,
    required this.drive,
    required this.subject,
  });

  @override
  Size get preferredSize => const Size.fromHeight(height);

  @override
  State<ResourceBreadcrumbs> createState() => _ResourceBreadcrumbsState();
}

class _ResourceBreadcrumbsState extends State<ResourceBreadcrumbs> {
  /// The ancestors, the drive first. Empty until they are read.
  List<Crumb> _parents = const [];
  final _scroll = ScrollController();

  @override
  void initState() {
    super.initState();
    _read();
  }

  @override
  void didUpdateWidget(ResourceBreadcrumbs old) {
    super.didUpdateWidget(old);
    if (old.subject != widget.subject) _read();
  }

  @override
  void dispose() {
    _scroll.dispose();
    super.dispose();
  }

  Future<Map<String, dynamic>?> _resource(String subject) async {
    var res = jsonDecode(
        await widget.api.embedCall('getResource', jsonEncode([subject])));
    if (res is String) res = jsonDecode(res);
    return res is Map<String, dynamic> ? res : null;
  }

  Future<void> _read() async {
    final subject = widget.subject;
    final chain = <Crumb>[];
    try {
      var next = (await _resource(subject))?[_parentProperty];
      // A broken parent cycle stops at the web page's depth.
      while (next is String && next.isNotEmpty && chain.length < 16) {
        final res = await _resource(next);
        if (res == null) break;
        final isA = res[_isAProperty];
        chain.insert(0, (
          subject: next,
          title: '${res[_nameProperty] ?? res[_shortnameProperty] ?? next}',
          classUrl: isA is List && isA.isNotEmpty ? '${isA.first}' : '',
        ));
        next = res[_parentProperty];
      }
    } catch (e) {
      debugPrint('[breadcrumbs] parents of $subject not read: $e');
    }
    if (!mounted || subject != widget.subject) return;
    setState(() => _parents = chain);
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scroll.hasClients) {
        _scroll.jumpTo(_scroll.position.maxScrollExtent);
      }
    });
  }

  void _open(Crumb crumb) {
    final drive = widget.drive.isEmpty
        ? ShellScope.maybeOf(context)?.drive.value ?? ''
        : widget.drive;
    widget.api.noteOpened(drive, crumb.subject);
    Navigator.of(context).push(SlideBackRoute<void>(
      builder: (_) => openResourceView(
          api: widget.api,
          drive: drive,
          subject: crumb.subject,
          title: crumb.title,
          classUrl: crumb.classUrl),
    ));
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final style = TextStyle(color: c.textSecondary, fontSize: 13);
    return SizedBox(
      height: ResourceBreadcrumbs.height,
      child: SingleChildScrollView(
        key: const Key('breadcrumbs'),
        controller: _scroll,
        scrollDirection: Axis.horizontal,
        padding: const EdgeInsets.symmetric(horizontal: 16),
        child: Row(children: [
          for (final (i, crumb) in _parents.indexed) ...[
            if (i > 0) Text('/', style: style),
            InkWell(
              onTap: () => _open(crumb),
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 4),
                child: Text(crumb.title, style: style),
              ),
            ),
          ],
        ]),
      ),
    );
  }
}

/// Gives the screen it wraps the resource's "more" menu: the bottom bar's last
/// button (on a phone) opens it, as it opens the web page's menu in a
/// [ResourceView]. It has what the app can do for a resource on its own:
/// rename (when [onRename] is given), copy the link and open it in the
/// browser. The rest of the web menu (favorite, move, trash, history) is the
/// page's and needs it.
class ResourceMenuScope extends StatefulWidget {
  final AssistantApi api;
  final String subject;
  final VoidCallback? onRename;
  final Widget child;

  const ResourceMenuScope({
    super.key,
    required this.api,
    required this.subject,
    this.onRename,
    required this.child,
  });

  @override
  State<ResourceMenuScope> createState() => _ResourceMenuScopeState();
}

class _ResourceMenuScopeState extends State<ResourceMenuScope> {
  ShellController? _shell;
  Route<dynamic>? _route;

  @override
  void initState() {
    super.initState();
    // The route is known once this is in the tree, and the shell may not be
    // told while the tree builds.
    WidgetsBinding.instance.addPostFrameCallback((_) => _register());
  }

  @override
  void didUpdateWidget(ResourceMenuScope old) {
    super.didUpdateWidget(old);
    // A new chat has no menu until its first message saves it.
    if ((old.subject.isEmpty) != widget.subject.isEmpty) _register();
  }

  void _register() {
    if (!mounted) return;
    _unregister();
    _shell = ShellScope.maybeOf(context);
    _route = ModalRoute.of(context);
    final route = _route;
    if (route != null && widget.subject.isNotEmpty) {
      _shell?.registerMenu(route, _open);
    }
  }

  void _unregister() {
    final route = _route;
    if (route != null) _shell?.unregisterMenu(route);
  }

  @override
  void dispose() {
    _unregister();
    super.dispose();
  }

  Future<void> _open(Rect anchor) async {
    final overlay = Overlay.of(context).context.findRenderObject() as RenderBox;
    String? url;
    try {
      url = widget.api.webUrl(widget.subject);
    } catch (_) {
      // No server connected: there is no link to give.
    }
    final choice = await showMenu<String>(
      context: context,
      position: RelativeRect.fromRect(anchor, Offset.zero & overlay.size),
      items: [
        if (widget.onRename != null)
          const PopupMenuItem(value: 'rename', child: Text('Rename')),
        if (url != null) ...const [
          PopupMenuItem(value: 'copy', child: Text('Copy link')),
          PopupMenuItem(value: 'browser', child: Text('Open in browser')),
        ],
      ],
    );
    if (!mounted || url == null && choice != 'rename') return;
    switch (choice) {
      case 'rename':
        widget.onRename?.call();
      case 'copy':
        await Clipboard.setData(ClipboardData(text: url!));
        if (mounted) {
          ToastScope.maybeOf(context)?.show('link-copied', 'Link copied');
        }
      case 'browser':
        await launchUrl(Uri.parse(url!), mode: LaunchMode.externalApplication);
    }
  }

  @override
  Widget build(BuildContext context) => widget.child;
}

/// The "more" button next to the list pane (the split layout), where the
/// bottom bar has none: opens the menu of the page on top, if it has one.
/// Draws nothing otherwise.
class ResourceMoreButton extends StatelessWidget {
  const ResourceMoreButton({super.key});

  @override
  Widget build(BuildContext context) {
    final shell = ShellScope.maybeOf(context);
    if (shell == null || ShellScope.layoutOf(context) != ShellLayout.split) {
      return const SizedBox.shrink();
    }
    final route = ModalRoute.of(context);
    return ListenableBuilder(
      listenable: shell,
      builder: (context, _) {
        final onMore = shell.topMenu;
        if (onMore == null || route?.isCurrent != true) {
          return const SizedBox.shrink();
        }
        return Builder(
          key: const ValueKey('more'),
          builder: (button) => IconButton(
            // As big as the web header it sits in (36 dp), not the 48 dp
            // default.
            iconSize: 20,
            padding: EdgeInsets.zero,
            visualDensity: VisualDensity.compact,
            color: context.appColors.textSecondary,
            constraints: const BoxConstraints(
                minWidth: kEmbedNavBarHeight, minHeight: kEmbedNavBarHeight),
            style: IconButton.styleFrom(
              tapTargetSize: MaterialTapTargetSize.shrinkWrap,
              fixedSize: const Size.square(kEmbedNavBarHeight),
              minimumSize: const Size.square(kEmbedNavBarHeight),
            ),
            tooltip: 'More',
            onPressed: () {
              final box = button.findRenderObject() as RenderBox;
              onMore(box.localToGlobal(Offset.zero) & box.size);
            },
            icon: const Icon(Icons.more_vert),
          ),
        );
      },
    );
  }
}
