import 'package:dsh_app/l10n/l10n.dart';
import 'package:dsh_app/remote/link_status.dart';
import 'package:dsh_app/remote/oauth/oauth_host_config.dart';
import 'package:dsh_app/remote/oauth/oauth_link.dart';
import 'package:dsh_client/dsh_client.dart';
import 'package:dsh_oauth/dsh_oauth.dart';
import 'package:flutter_test/flutter_test.dart';

class _FakeApi extends OauthDeviceClient {
  _FakeApi(this.onCoreSession) : super(Uri.parse('http://127.0.0.1:9'));

  final Future<CoreSession> Function(String token) onCoreSession;
  int calls = 0;
  String? lastToken;

  @override
  Future<CoreSession> coreSession(String accessToken) {
    calls++;
    lastToken = accessToken;
    return onCoreSession(accessToken);
  }
}

class _Captured {
  Uri? baseUri;
  DshCookie? cookie;
  String? bearer;
  String? hostHeader;
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const config = OauthHostConfig(id: 'oauth-1', name: 'Studio', baseUrl: 'https://dsh.example.com', hostHeader: null);

  OauthHostLink link({
    required String? token,
    required _FakeApi api,
    OauthClientConnector? connect,
    OauthHostConfig host = config,
  }) => OauthHostLink(
    config: host,
    loadToken: () async => token,
    clientFactory: (_) => api,
    connectClient:
        connect ??
        ({required baseUri, required cookie, required bearer, hostHeader}) async {
          throw const HostLinkError(HostLinkErrorKind.loginFailed, 'stop here');
        },
    backoff: Backoff(initial: const Duration(milliseconds: 1), maxAttempts: 1),
    keepAliveInterval: const Duration(hours: 1),
  );

  test('a missing device token fails closed without calling the Host', () async {
    final api = _FakeApi((_) async => throw StateError('must not run'));
    final l = link(token: null, api: api);
    addTearDown(l.close);
    await expectLater(l.open(), throwsA(isA<HostLinkError>()));
    expect(api.calls, 0);
    expect(l.status.phase, HostLinkPhase.failed);
    expect(l.status.error?.kind, HostLinkErrorKind.notLoggedIn);
  });

  test('mints a core session, then connects with cookie and Bearer token', () async {
    final captured = _Captured();
    final api = _FakeApi(
      (_) async =>
          const CoreSession(cookieName: 'dsh-auth-abc', cookieValue: 'v1.payload.sig', authority: 'dsh.example.com'),
    );
    final l = link(
      token: 'device-token',
      api: api,
      connect: ({required baseUri, required cookie, required bearer, hostHeader}) async {
        captured
          ..baseUri = baseUri
          ..cookie = cookie
          ..bearer = bearer
          ..hostHeader = hostHeader;
        throw const HostLinkError(HostLinkErrorKind.loginFailed, 'stop here');
      },
    );
    addTearDown(l.close);
    await expectLater(l.open(), throwsA(isA<HostLinkError>()));
    expect(api.lastToken, 'device-token');
    expect(captured.baseUri, Uri.parse('https://dsh.example.com'));
    expect(captured.cookie?.header, 'dsh-auth-abc=v1.payload.sig');
    expect(captured.bearer, 'device-token');
    expect(captured.hostHeader, isNull);
  });

  test('a revoked token is terminal and says so', () async {
    final api = _FakeApi((_) async => throw const OauthException(OauthErrorCodes.deviceTokenRequired, 'revoked'));
    final l = link(token: 'gone', api: api);
    addTearDown(l.close);
    await expectLater(l.open(), throwsA(isA<HostLinkError>()));
    expect(l.status.error?.kind, HostLinkErrorKind.notLoggedIn);
    expect(l.status.error?.message, appL10n.remoteOauthRevoked);
    expect(l.status.error?.retryable, isFalse);
  });

  test('an old plugin (404) is reported as a version problem', () async {
    final api = _FakeApi((_) async => throw const OauthException(OauthErrorCodes.http, 'missing', statusCode: 404));
    final l = link(token: 'tok', api: api);
    addTearDown(l.close);
    await expectLater(l.open(), throwsA(isA<HostLinkError>()));
    expect(l.status.error?.message, appL10n.remoteOauthPluginMissing);
  });

  test('a rename applies in place; a new address needs a new link', () async {
    final api = _FakeApi((_) async => throw StateError('not called'));
    final l = link(token: null, api: api);
    addTearDown(l.close);
    l.updateConfig(config.copyWith(name: 'Desk'));
    expect(l.config.name, 'Desk');
    expect(l.config.connectionKey, config.connectionKey);
  });
}
