import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:dsh_oauth/dsh_oauth.dart';
import 'package:test/test.dart';

/// One scripted HTTP response.
class _Reply {
  _Reply(this.status, this.body);

  final int status;
  final Object body;
}

class _FakeHost {
  _FakeHost._(this.server);

  final HttpServer server;
  final List<
    ({
      String path,
      String method,
      Map<String, Object?> body,
      Map<String, String?> headers,
    })
  >
  requests = [];
  final Map<String, List<_Reply>> _scripted = {};
  final List<_Reply> _default = [];

  static Future<_FakeHost> start() async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final host = _FakeHost._(server);
    server.listen(host._handle);
    return host;
  }

  Uri get baseUri => Uri.parse('http://127.0.0.1:${server.port}');

  void on(String path, List<_Reply> replies) => _scripted[path] = replies;

  void always(String path, _Reply reply) => _default.add(reply);

  Future<void> close() => server.close(force: true);

  Future<void> _handle(HttpRequest request) async {
    final text = await utf8.decoder.bind(request).join();
    Map<String, Object?> body = const {};
    if (text.isNotEmpty) {
      final decoded = jsonDecode(text);
      if (decoded is Map) body = decoded.map((k, v) => MapEntry('$k', v));
    }
    requests.add((
      path: request.uri.path,
      method: request.method,
      body: body,
      headers: {
        'authorization': request.headers.value(HttpHeaders.authorizationHeader),
        'host': request.headers.value(HttpHeaders.hostHeader),
      },
    ));
    final scripted = _scripted[request.uri.path];
    final reply = (scripted != null && scripted.isNotEmpty)
        ? scripted.removeAt(0)
        : (_default.isEmpty
              ? _Reply(404, {'error': 'not_found'})
              : _default.first);
    request.response
      ..statusCode = reply.status
      ..headers.contentType = ContentType.json;
    request.response.write(jsonEncode(reply.body));
    await request.response.close();
  }
}

void main() {
  late _FakeHost host;
  late OauthDeviceClient client;

  setUp(() async {
    host = await _FakeHost.start();
    client = OauthDeviceClient(host.baseUri);
  });

  tearDown(() async {
    await client.close();
    await host.close();
  });

  test('authorize posts the documented body and parses the response', () async {
    host.on('/dsh-webui-oauth/device/authorize', [
      _Reply(200, {
        'device_code': 'dc-1',
        'user_code': 'ABCD-EFGH',
        'verification_uri': 'https://dsh.example.com/dsh-webui-oauth/device',
        'verification_uri_complete':
            'https://dsh.example.com/dsh-webui-oauth/device?user_code=ABCD-EFGH',
        'expires_in': 600,
        'interval': 5,
      }),
    ]);

    final auth = await client.authorize(
      clientName: 'DSH App (Pixel 9)',
      description: 'dsh-Go',
    );

    final sent = host.requests.single;
    expect(sent.path, '/dsh-webui-oauth/device/authorize');
    expect(sent.body['client_id'], 'dsh-app');
    expect(sent.body['client_name'], 'DSH App (Pixel 9)');
    expect(sent.body['client_description'], 'dsh-Go');
    expect(auth.deviceCode, 'dc-1');
    expect(auth.userCode, 'ABCD-EFGH');
    expect(auth.expiresIn, const Duration(minutes: 10));
    expect(auth.interval, const Duration(seconds: 5));
    expect(
      auth.verificationUriComplete?.queryParameters['user_code'],
      'ABCD-EFGH',
    );
  });

  test(
    'the base path is dropped: plugin endpoints live at the origin root',
    () async {
      await client.close();
      client = OauthDeviceClient(Uri.parse('${host.baseUri}/mounted/dsh'));
      host.on('/dsh-webui-oauth/device/authorize', [
        _Reply(200, {
          'device_code': 'dc',
          'user_code': 'A',
          'verification_uri': 'https://x/y',
          'expires_in': 600,
          'interval': 5,
        }),
      ]);
      await client.authorize(clientName: 'App');
      expect(host.requests.single.path, '/dsh-webui-oauth/device/authorize');
    },
  );

  test('pollToken surfaces authorization_pending and then the token', () async {
    host.on('/dsh-webui-oauth/device/token', [
      _Reply(400, {'error': 'authorization_pending'}),
      _Reply(200, {
        'access_token': 'tok-1',
        'token_type': 'Bearer',
        'scope': 'dsh',
        'device_id': 'dev-1',
      }),
    ]);
    await expectLater(
      client.pollToken('dc-1'),
      throwsA(
        isA<OauthException>().having(
          (e) => e.code,
          'code',
          OauthErrorCodes.authorizationPending,
        ),
      ),
    );
    final token = await client.pollToken('dc-1');
    expect(token.accessToken, 'tok-1');
    expect(token.deviceId, 'dev-1');
    expect(
      host.requests.last.body['grant_type'],
      OauthDeviceClient.deviceCodeGrant,
    );
    expect(host.requests.last.body['device_code'], 'dc-1');
  });

  test('slow_down is preserved for the polling loop', () async {
    host.on('/dsh-webui-oauth/device/token', [
      _Reply(400, {'error': 'slow_down'}),
    ]);
    await expectLater(
      client.pollToken('dc'),
      throwsA(isA<OauthException>().having((e) => e.code, 'code', 'slow_down')),
    );
  });

  test('coreSession sends the Bearer token and parses the cookie', () async {
    host.on('/dsh-webui-oauth/device/core-session', [
      _Reply(200, {
        'ok': true,
        'cookie_name': 'dsh-auth-abc',
        'cookie_value': 'v1.payload.sig',
        'authority': 'dsh.example.com',
      }),
    ]);
    final session = await client.coreSession('tok-1');
    expect(host.requests.single.headers['authorization'], 'Bearer tok-1');
    expect(host.requests.single.method, 'POST');
    expect(session.cookieName, 'dsh-auth-abc');
    expect(session.authority, 'dsh.example.com');
    expect(session.toDshCookie().header, 'dsh-auth-abc=v1.payload.sig');
  });

  test('a revoked device token is terminal', () async {
    host.on('/dsh-webui-oauth/device/core-session', [
      _Reply(401, {'error': 'device-token-required'}),
    ]);
    await expectLater(
      client.coreSession('gone'),
      throwsA(
        isA<OauthException>()
            .having((e) => e.code, 'code', OauthErrorCodes.deviceTokenRequired)
            .having(
              (e) => e.needsNewAuthorization,
              'needsNewAuthorization',
              isTrue,
            ),
      ),
    );
  });

  test('a missing field is a protocol error, not a silent default', () async {
    host.on('/dsh-webui-oauth/device/core-session', [
      _Reply(200, {'ok': true, 'cookie_name': 'dsh-auth-abc'}),
    ]);
    await expectLater(
      client.coreSession('tok'),
      throwsA(
        isA<OauthException>().having(
          (e) => e.code,
          'code',
          OauthErrorCodes.protocol,
        ),
      ),
    );
  });

  test('transport failures map to a retryable network error', () async {
    final port = host.server.port;
    await host.close();
    final offline = OauthDeviceClient(Uri.parse('http://127.0.0.1:$port'));
    addTearDown(offline.close);
    await expectLater(
      offline.authorize(clientName: 'App'),
      throwsA(
        isA<OauthException>()
            .having((e) => e.code, 'code', OauthErrorCodes.network)
            .having((e) => e.retryable, 'retryable', isTrue),
      ),
    );
  });

  test(
    'waitForDeviceToken polls until approval and honours cancellation',
    () async {
      host.on('/dsh-webui-oauth/device/token', [
        _Reply(400, {'error': 'authorization_pending'}),
        _Reply(400, {'error': 'slow_down'}),
        _Reply(200, {
          'access_token': 'tok-final',
          'token_type': 'Bearer',
          'scope': 'dsh',
          'device_id': 'dev-2',
        }),
      ]);
      final auth = DeviceAuthorization(
        deviceCode: 'dc',
        userCode: 'ABCD',
        verificationUri: Uri.parse(
          'https://dsh.example.com/dsh-webui-oauth/device',
        ),
        verificationUriComplete: null,
        expiresIn: const Duration(minutes: 10),
        interval: const Duration(milliseconds: 5),
      );
      final token = await waitForDeviceToken(client, auth);
      expect(token.accessToken, 'tok-final');
      expect(host.requests.length, 3);

      var cancelled = true;
      await expectLater(
        waitForDeviceToken(client, auth, cancelled: () => cancelled),
        throwsA(isA<DeviceFlowCancelled>()),
      );
    },
  );
}
