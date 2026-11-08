# dsh_oauth

Pure-Dart client for the `dsh-webui-oauth` device flow. It lets a native client
reach a DSH Host behind the WebUI auth gate with an ordinary `DshClient`:

```
authorize() ──▶ person approves in a browser ──▶ pollToken()
    └─ device token (Bearer, stored in secure storage)
coreSession(token) ──▶ dsh-auth-* cookie ──▶ DshClient.connect(cookie:, bearer:)
```

The plugin (`WU-HINS/dsh-webui-oauth` 0.8.3+) performs the core launch-token
exchange server-side, so the launch token never reaches the App.

```dart
import 'package:dsh_client/dsh_client.dart';
import 'package:dsh_oauth/dsh_oauth.dart';

final base = OauthHostUrl.parse('https://dsh.example.com'); // http: local IPs only
final client = OauthDeviceClient(base);

final auth = await client.authorize(clientName: 'DSH App');
// Open auth.verificationUriComplete on the Host's browser.
final token = await waitForDeviceToken(client, auth);

final core = await client.coreSession(token.accessToken);
final dsh = await DshClient.connect(
  baseUri: base,
  cookie: core.toDshCookie(),
  bearer: token.accessToken,
);
```

## Rules

- `http://` is accepted only for literal local-network addresses (10/8,
  172.16/12, 192.168/16, 127/8, 169.254/16, 100.64/10, IPv6 `::1`, fc00::/7,
  fe80::/10, IPv4-mapped forms) and `localhost`. Everything else needs HTTPS.
- `authorization_pending` and `slow_down` keep the polling loop going;
  `expired_token`, `access_denied` and `invalid_grant` are terminal.
- `device-token-required` means the token was revoked on the Host; authorize
  again.
- Device tokens have no expiry of their own and are revocable only on the Host.
  Store them in secure storage and send them only over TLS.

## Tests

```bash
dart pub get && dart analyze && dart test
```

The tests run against an in-process HTTP server that scripts each endpoint
(`test/device_client_test.dart`); no network or real Host is needed.
