/// Live probe: device token → core session → DshClient → sessions.
///
/// ```bash
/// DSH_OAUTH_URL=http://127.0.0.1:18080 \
/// DSH_OAUTH_TOKEN=<device token> \
/// dart run tool/e2e_probe.dart
/// ```
///
/// It never prints the token or the cookie; set `DSH_OAUTH_TRACE=1` to print
/// the resolved authority and session count only.
library;

import 'dart:io';

import 'package:dsh_client/dsh_client.dart';
import 'package:dsh_oauth/dsh_oauth.dart';

Future<void> main() async {
  final base = Platform.environment['DSH_OAUTH_URL'];
  final token = Platform.environment['DSH_OAUTH_TOKEN'];
  if (base == null || token == null || token.isEmpty) {
    stderr.writeln('set DSH_OAUTH_URL and DSH_OAUTH_TOKEN');
    exit(64);
  }
  final uri = OauthHostUrl.parse(base);
  final api = OauthDeviceClient(uri);
  try {
    final core = await api.coreSession(token);
    stdout.writeln('core-session: ${core.cookieName} for ${core.authority}');

    final client = await DshClient.connect(
      baseUri: uri,
      cookie: core.toDshCookie(),
      bearer: token,
    );
    try {
      final health = await client.connection.checkHealth(
        timeout: const Duration(seconds: 5),
      );
      stdout.writeln('health: ${health.name}');
      final sessions = await client.listSessions();
      stdout.writeln('sessions: ${sessions.length}');
      stdout.writeln('mux: ${client.mux.state.name}');
      if (Platform.environment['DSH_OAUTH_TRACE'] == '1') {
        stdout.writeln('base: ${uri.origin}');
      }
    } finally {
      await client.close();
    }
  } on OauthException catch (error) {
    stderr.writeln('oauth failed: ${error.code} ${error.detail ?? ''}');
    exit(2);
  } finally {
    await api.close();
  }
}
