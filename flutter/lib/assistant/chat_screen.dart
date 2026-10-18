import 'package:flutter/material.dart';

import '../atomic/atomic_client.dart';
import '../theme.dart';
import 'assistant_api.dart';

/// A chat, read-only: the text of each message, newest at the bottom.
class ChatScreen extends StatelessWidget {
  final AssistantApi api;
  final String subject;
  final String title;

  const ChatScreen({
    super.key,
    required this.api,
    required this.subject,
    this.title = '',
  });

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return Scaffold(
      backgroundColor: c.bgBody,
      appBar: AppBar(
        backgroundColor: c.bgBody,
        title: Text(title.isEmpty ? 'Untitled chat' : title),
      ),
      body: FutureBuilder<List<ChatMessage>>(
        future: api.messages(subject),
        builder: (context, snapshot) {
          if (snapshot.hasError) {
            return Center(
              child:
                  Text('${snapshot.error}', style: TextStyle(color: c.alert)),
            );
          }
          final messages = snapshot.data;
          if (messages == null) {
            return const Center(child: CircularProgressIndicator());
          }
          if (messages.isEmpty) {
            return Center(
              child:
                  Text('No messages', style: TextStyle(color: c.textSecondary)),
            );
          }
          return ListView.builder(
            reverse: true,
            padding: const EdgeInsets.all(16),
            itemCount: messages.length,
            itemBuilder: (context, i) {
              final m = messages[messages.length - 1 - i];
              final mine = m.role == 'user';
              return Align(
                alignment: mine ? Alignment.centerRight : Alignment.centerLeft,
                child: Container(
                  margin: const EdgeInsets.symmetric(vertical: 4),
                  padding:
                      const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                  constraints: BoxConstraints(
                      maxWidth: MediaQuery.of(context).size.width * 0.85),
                  decoration: BoxDecoration(
                    color: mine ? c.mainSelectedBg : c.bg1,
                    borderRadius: BorderRadius.circular(9),
                  ),
                  child: SelectableText(
                    m.text,
                    style: TextStyle(
                        color: mine ? c.mainSelectedFg : c.textPrimary),
                  ),
                ),
              );
            },
          );
        },
      ),
    );
  }
}
