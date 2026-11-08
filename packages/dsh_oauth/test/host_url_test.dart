import 'package:dsh_oauth/dsh_oauth.dart';
import 'package:test/test.dart';

void main() {
  group('https', () {
    test('accepts a public host and drops the default port', () {
      final uri = OauthHostUrl.parse('dsh.example.com');
      expect(uri.scheme, 'https');
      expect(uri.host, 'dsh.example.com');
      expect(uri.port, 443);
      expect(uri.path, '');
    });

    test('keeps a non-default port and a mounted path', () {
      final uri = OauthHostUrl.parse('https://dsh.example.com:8443/dsh/');
      expect(uri.port, 8443);
      expect(uri.path, '/dsh');
    });

    test('rejects credentials, query and fragment', () {
      expect(
        () => OauthHostUrl.parse('https://user:pass@dsh.example.com'),
        throwsA(
          isA<OauthHostUrlException>().having(
            (e) => e.error,
            'error',
            OauthHostUrlError.credentials,
          ),
        ),
      );
      expect(
        () => OauthHostUrl.parse('https://dsh.example.com/?token=x'),
        throwsA(
          isA<OauthHostUrlException>().having(
            (e) => e.error,
            'error',
            OauthHostUrlError.query,
          ),
        ),
      );
      expect(
        () => OauthHostUrl.parse('https://dsh.example.com/#top'),
        throwsA(
          isA<OauthHostUrlException>().having(
            (e) => e.error,
            'error',
            OauthHostUrlError.query,
          ),
        ),
      );
    });

    test('rejects another scheme', () {
      expect(
        () => OauthHostUrl.parse('ftp://dsh.example.com'),
        throwsA(
          isA<OauthHostUrlException>().having(
            (e) => e.error,
            'error',
            OauthHostUrlError.scheme,
          ),
        ),
      );
    });
  });

  group('http is local-network only', () {
    test('accepts RFC1918, loopback, link-local, CGNAT and IPv6 ULA', () {
      for (final host in [
        'http://127.0.0.1:3080',
        'http://10.0.0.5:3080',
        'http://172.16.4.9:3080',
        'http://192.168.1.20:3080',
        'http://169.254.10.1:3080',
        'http://100.64.0.7:3080',
        'http://localhost:3080',
        'http://[::1]:3080',
        'http://[fd00::1]:3080',
        'http://[fe80::1]:3080',
      ]) {
        expect(OauthHostUrl.parse(host).scheme, 'http', reason: host);
      }
    });

    test('refuses public addresses and host names', () {
      for (final host in [
        'http://8.8.8.8',
        'http://dsh.example.com',
        'http://172.32.0.1',
        'http://192.169.1.1',
      ]) {
        expect(
          () => OauthHostUrl.parse(host),
          throwsA(
            isA<OauthHostUrlException>().having(
              (e) => e.error,
              'error',
              OauthHostUrlError.insecurePublic,
            ),
          ),
          reason: host,
        );
      }
    });

    test('accepts IPv4-mapped private addresses', () {
      expect(
        OauthHostUrl.parse('http://[::ffff:192.168.1.4]:3080').scheme,
        'http',
      );
    });
  });

  test('empty input is refused', () {
    expect(
      () => OauthHostUrl.parse('   '),
      throwsA(
        isA<OauthHostUrlException>().having(
          (e) => e.error,
          'error',
          OauthHostUrlError.empty,
        ),
      ),
    );
  });
}
