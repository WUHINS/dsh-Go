import 'dart:convert';
import 'dart:io';

import 'package:dsh_client/dsh_client.dart';
import 'package:test/test.dart';

void main() {
  test('sends Authorization: Bearer alongside the session cookie', () async {
    final seen = <String, String?>{};
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));
    server.listen((request) async {
      seen['authorization'] = request.headers.value(HttpHeaders.authorizationHeader);
      seen['cookie'] = request.headers.value(HttpHeaders.cookieHeader);
      seen['host'] = request.headers.value(HttpHeaders.hostHeader);
      request.response
        ..statusCode = 200
        ..headers.contentType = ContentType.json
        ..write(jsonEncode({'ok': true, 'value': null}));
      await request.response.close();
    });

    final connection = DshConnection(
      Uri.parse('http://127.0.0.1:${server.port}'),
      cookie: const DshCookie(name: 'dsh-auth-test', value: 'v1.payload.sig', authority: '127.0.0.1'),
      bearer: 'device-token',
      hostHeader: 'dsh.example.com',
    );
    addTearDown(connection.close);

    final response = await connection.postJson('/api/test/echo', const <String, Object?>{});
    expect(response.statusCode, 200);
    expect(seen['authorization'], 'Bearer device-token');
    expect(seen['cookie'], 'dsh-auth-test=v1.payload.sig');
    expect(seen['host'], 'dsh.example.com');
  });

  test('omits Authorization when no bearer is configured', () async {
    String? authorization = 'unset';
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));
    server.listen((request) async {
      authorization = request.headers.value(HttpHeaders.authorizationHeader);
      request.response
        ..statusCode = 200
        ..headers.contentType = ContentType.json
        ..write('{}');
      await request.response.close();
    });

    final connection = DshConnection(Uri.parse('http://127.0.0.1:${server.port}'));
    addTearDown(connection.close);
    await connection.postJson('/api/test/echo', const <String, Object?>{});
    expect(authorization, isNull);
  });
}
