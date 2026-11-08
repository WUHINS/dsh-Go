// Live OAuth Host: runs only when a real dsh-webui-oauth Host is provided.
//
//   DSH_OAUTH_URL=http://127.0.0.1:18080 \
//   DSH_OAUTH_TOKEN=<device token> \
//   flutter test test/remote/oauth_live_test.dart
//
// The token is a credential: never commit it or paste it into a report.

import 'dart:io';

import 'package:dsh_app/remote/link_status.dart';
import 'package:dsh_app/remote/oauth/oauth_host_config.dart';
import 'package:dsh_app/remote/oauth/oauth_link.dart';
import 'package:dsh_client/dsh_client.dart';
import 'package:dsh_oauth/dsh_oauth.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  // The test binding stubs HttpClient; this file is explicitly a live probe.
  HttpOverrides.global = null;

  final url = Platform.environment['DSH_OAUTH_URL'];
  final token = Platform.environment['DSH_OAUTH_TOKEN'];
  final skip = url == null || url.isEmpty || token == null || token.isEmpty
      ? 'set DSH_OAUTH_URL and DSH_OAUTH_TOKEN to run against a real Host'
      : null;

  test('connects to a real gated Host and lists sessions', () async {
    final base = OauthHostUrl.parse(url!);
    final link = OauthHostLink(
      config: OauthHostConfig(id: 'live', name: 'Live', baseUrl: base.toString()),
      loadToken: () async => token,
      backoff: Backoff(initial: const Duration(milliseconds: 200), maxAttempts: 2),
    );
    addTearDown(link.close);
    final client = await link.open();
    expect(link.status.phase, HostLinkPhase.connected);
    expect(await client.connection.checkHealth(timeout: const Duration(seconds: 5)), DshHealth.ok);
    await client.listSessions();
    expect(client.mux.state.name, 'connected');
  }, skip: skip);
}
