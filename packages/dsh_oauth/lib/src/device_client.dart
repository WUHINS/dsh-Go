/// Client for the `dsh-webui-oauth` device endpoints.
///
/// The flow, all on the Host's public HTTPS origin:
///
/// 1. `authorize()` → device code + user code + approval URL.
/// 2. The person approves in a browser that already has a plugin session.
/// 3. `pollToken()` → Bearer access token (stored in secure storage).
/// 4. `coreSession(token)` → the `dsh-auth-*` cookie for the core API.
///
/// The access token is a long-lived credential with no expiry: only an
/// explicit revocation on the Host invalidates it.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'models.dart';

/// Stable codes returned by [OauthException].
abstract final class OauthErrorCodes {
  /// The server asks the client to keep waiting (RFC 8628 §3.5).
  static const authorizationPending = 'authorization_pending';

  /// Polling faster than `interval`; wait one more interval.
  static const slowDown = 'slow_down';

  /// The device code expired; start a new authorization.
  static const expiredToken = 'expired_token';

  /// The person declined the request.
  static const accessDenied = 'access_denied';

  /// Unknown/expired device code, or an invalid grant type.
  static const invalidGrant = 'invalid_grant';
  static const unsupportedGrantType = 'unsupported_grant_type';
  static const invalidClient = 'invalid_client';
  static const invalidRequest = 'invalid_request';

  /// The device token is unknown or revoked.
  static const deviceTokenRequired = 'device-token-required';

  /// The plugin is installed but could not mint the core cookie (for example
  /// the Host's `connection` service is unavailable).
  static const coreSessionUnavailable = 'core-session-unavailable';

  /// Transport-level failure: DNS, TLS, timeout, closed socket.
  static const network = 'network';

  /// A response that is not the JSON shape the endpoints document.
  static const protocol = 'protocol';

  /// Any other HTTP error, carrying its status code.
  static const http = 'http';
}

/// A failed device-flow call.
class OauthException implements Exception {
  const OauthException(this.code, this.message, {this.statusCode, this.detail});

  final String code;
  final String message;
  final int? statusCode;

  /// Server-supplied description, already safe to show as a diagnostic.
  final String? detail;

  /// Whether retrying the same call can succeed (after the server's delay).
  bool get retryable =>
      code == OauthErrorCodes.network ||
      code == OauthErrorCodes.authorizationPending ||
      code == OauthErrorCodes.slowDown;

  /// Whether the credential must be replaced (revoked, expired, denied).
  bool get needsNewAuthorization =>
      code == OauthErrorCodes.deviceTokenRequired ||
      code == OauthErrorCodes.expiredToken ||
      code == OauthErrorCodes.accessDenied ||
      code == OauthErrorCodes.invalidGrant;

  @override
  String toString() => detail == null || detail!.isEmpty
      ? 'OauthException($code): $message'
      : 'OauthException($code): $message ($detail)';
}

/// Device-flow client for one Host origin.
class OauthDeviceClient {
  OauthDeviceClient(
    Uri baseUri, {
    HttpClient? httpClient,
    Duration timeout = const Duration(seconds: 15),
  }) : baseUri = baseUri.replace(path: '', query: null, fragment: null),
       _http = httpClient ?? HttpClient(),
       _ownsHttp = httpClient == null,
       _timeout = timeout {
    if (_ownsHttp) {
      _http
        ..connectionTimeout = timeout
        ..idleTimeout = const Duration(seconds: 15)
        ..userAgent = 'dsh-app/oauth';
    }
  }

  /// The client id the plugin expects (`DEVICE_CLIENT_ID`).
  static const clientId = 'dsh-app';

  /// RFC 8628 grant type the plugin accepts.
  static const deviceCodeGrant = 'urn:ietf:params:oauth:grant-type:device_code';

  /// Origin only; every plugin endpoint is registered at the server root.
  final Uri baseUri;
  final HttpClient _http;
  final bool _ownsHttp;
  final Duration _timeout;
  bool _closed = false;

  /// Starts an authorization. The person-facing name is mandatory: the Host
  /// shows it on the approval page and in its device list.
  Future<DeviceAuthorization> authorize({
    required String clientName,
    String? description,
    String scope = 'dsh',
  }) async {
    final name = clientName.trim();
    if (name.isEmpty) {
      throw const OauthException(
        OauthErrorCodes.invalidRequest,
        'client_name is required.',
      );
    }
    final json = await _post('/dsh-webui-oauth/device/authorize', {
      'client_id': clientId,
      'client_name': name,
      if (description != null && description.trim().isNotEmpty)
        'client_description': description.trim(),
      'scope': scope,
    });
    final deviceCode = _string(json, 'device_code');
    final userCode = _string(json, 'user_code');
    final verification = _uri(json, 'verification_uri');
    final complete = _optionalUri(json, 'verification_uri_complete');
    return DeviceAuthorization(
      deviceCode: deviceCode,
      userCode: userCode,
      verificationUri: verification,
      verificationUriComplete: complete,
      expiresIn: Duration(
        seconds: _positiveInt(json, 'expires_in', fallback: 600),
      ),
      interval: Duration(seconds: _positiveInt(json, 'interval', fallback: 5)),
    );
  }

  /// One poll. Throws [OauthException] with [OauthErrorCodes.authorizationPending]
  /// or [OauthErrorCodes.slowDown] while the person has not approved yet.
  Future<DeviceToken> pollToken(String deviceCode) async {
    final json = await _post(
      '/dsh-webui-oauth/device/token',
      {'grant_type': deviceCodeGrant, 'device_code': deviceCode},
      // Polling is a normal outcome, not a transport failure.
      tolerateCodes: const {
        OauthErrorCodes.authorizationPending,
        OauthErrorCodes.slowDown,
      },
    );
    return DeviceToken(
      accessToken: _string(json, 'access_token'),
      tokenType: _stringOr(json, 'token_type', 'Bearer'),
      scope: _stringOr(json, 'scope', 'dsh'),
      deviceId: _string(json, 'device_id'),
    );
  }

  /// Exchanges a device token for the core `dsh-auth-*` session cookie.
  ///
  /// The plugin performs the launch-token exchange server-side, so the launch
  /// token never reaches the App.
  Future<CoreSession> coreSession(String accessToken) async {
    final json = await _post(
      '/dsh-webui-oauth/device/core-session',
      const {},
      bearer: accessToken,
    );
    return CoreSession(
      cookieName: _string(json, 'cookie_name'),
      cookieValue: _string(json, 'cookie_value'),
      authority: _string(json, 'authority'),
    );
  }

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    if (_ownsHttp) _http.close(force: true);
  }

  // ---------------------------------------------------------------------------

  Future<Map<String, Object?>> _post(
    String path,
    Map<String, Object?> body, {
    String? bearer,
    Set<String> tolerateCodes = const {},
  }) async {
    if (_closed) {
      throw const OauthException(
        OauthErrorCodes.network,
        'The client is closed.',
      );
    }
    final uri = baseUri.replace(path: path);
    try {
      final request = await _http.postUrl(uri).timeout(_timeout);
      request
        ..followRedirects = false
        ..persistentConnection = false
        ..headers.contentType = ContentType.json
        ..headers.set(HttpHeaders.acceptHeader, 'application/json');
      if (bearer != null) {
        request.headers.set(HttpHeaders.authorizationHeader, 'Bearer $bearer');
      }
      final payload = utf8.encode(jsonEncode(body));
      request.contentLength = payload.length;
      request.add(payload);
      final response = await request.close().timeout(_timeout);
      final text = await _readCapped(response, 256 * 1024).timeout(_timeout);
      final json = _decodeObject(text);
      final error = _optionalString(json, 'error');
      if (error != null && error.isNotEmpty) {
        if (tolerateCodes.contains(error)) {
          throw OauthException(
            error,
            _optionalString(json, 'error_description') ?? error,
            statusCode: response.statusCode,
          );
        }
        throw OauthException(
          error,
          _messageFor(error),
          statusCode: response.statusCode,
          detail: _optionalString(json, 'error_description'),
        );
      }
      if (response.statusCode < 200 || response.statusCode >= 300) {
        throw OauthException(
          OauthErrorCodes.http,
          'The Host answered HTTP ${response.statusCode}.',
          statusCode: response.statusCode,
        );
      }
      return json;
    } on OauthException {
      rethrow;
    } on TimeoutException catch (error) {
      throw OauthException(
        OauthErrorCodes.network,
        'The Host did not answer in time.',
        detail: '$error',
      );
    } on SocketException catch (error) {
      throw OauthException(
        OauthErrorCodes.network,
        'Could not reach the Host.',
        detail: error.message,
      );
    } on HandshakeException catch (error) {
      throw OauthException(
        OauthErrorCodes.network,
        'The TLS handshake failed; check the certificate.',
        detail: error.message,
      );
    } on HttpException catch (error) {
      throw OauthException(
        OauthErrorCodes.network,
        'The connection failed.',
        detail: error.message,
      );
    }
  }

  static Future<String> _readCapped(
    HttpClientResponse response,
    int maxBytes,
  ) async {
    final builder = BytesBuilder(copy: false);
    await for (final chunk in response) {
      if (builder.length + chunk.length > maxBytes) break;
      builder.add(chunk);
    }
    return utf8.decode(builder.takeBytes(), allowMalformed: true);
  }

  static Map<String, Object?> _decodeObject(String text) {
    if (text.trim().isEmpty) return const {};
    final decoded = jsonDecode(text);
    if (decoded is! Map) {
      throw const OauthException(
        OauthErrorCodes.protocol,
        'The Host answered with something other than a JSON object.',
      );
    }
    return decoded.map((key, value) => MapEntry('$key', value));
  }

  static String _messageFor(String code) => switch (code) {
    OauthErrorCodes.authorizationPending => 'Waiting for approval.',
    OauthErrorCodes.slowDown => 'Polling too fast.',
    OauthErrorCodes.expiredToken => 'The code expired; start again.',
    OauthErrorCodes.accessDenied => 'The request was denied.',
    OauthErrorCodes.invalidGrant => 'The code is no longer valid.',
    OauthErrorCodes.unsupportedGrantType =>
      'The Host does not support the device flow.',
    OauthErrorCodes.invalidClient => 'This app is not accepted by the Host.',
    OauthErrorCodes.invalidRequest => 'The Host rejected the request.',
    OauthErrorCodes.deviceTokenRequired =>
      'The device token is unknown or revoked.',
    OauthErrorCodes.coreSessionUnavailable =>
      'The Host could not mint a session for this device.',
    _ => 'The Host refused the request.',
  };

  static String _string(Map<String, Object?> json, String key) {
    final value = _optionalString(json, key);
    if (value == null || value.isEmpty) {
      throw OauthException(
        OauthErrorCodes.protocol,
        'The Host response is missing "$key".',
      );
    }
    return value;
  }

  static String _stringOr(
    Map<String, Object?> json,
    String key,
    String fallback,
  ) => _optionalString(json, key) ?? fallback;

  static String? _optionalString(Map<String, Object?> json, String key) {
    final value = json[key];
    return value is String ? value : null;
  }

  static Uri _uri(Map<String, Object?> json, String key) {
    final raw = _string(json, key);
    final uri = Uri.tryParse(raw);
    if (uri == null || !uri.hasScheme) {
      throw OauthException(
        OauthErrorCodes.protocol,
        'The Host returned an invalid "$key".',
      );
    }
    return uri;
  }

  static Uri? _optionalUri(Map<String, Object?> json, String key) {
    final raw = _optionalString(json, key);
    if (raw == null || raw.isEmpty) return null;
    final uri = Uri.tryParse(raw);
    return uri != null && uri.hasScheme ? uri : null;
  }

  static int _positiveInt(
    Map<String, Object?> json,
    String key, {
    required int fallback,
  }) {
    final value = json[key];
    return value is int && value > 0 ? value : fallback;
  }
}
