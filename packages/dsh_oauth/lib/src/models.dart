/// Typed results of the `dsh-webui-oauth` device flow.
library;

import 'package:dsh_client/dsh_client.dart';

/// A pending device authorization (`POST /dsh-webui-oauth/device/authorize`).
class DeviceAuthorization {
  const DeviceAuthorization({
    required this.deviceCode,
    required this.userCode,
    required this.verificationUri,
    required this.verificationUriComplete,
    required this.expiresIn,
    required this.interval,
  });

  /// Opaque code the App polls with. Never shown to the person.
  final String deviceCode;

  /// Short code the person confirms on the approval page (`ABCD-EFGH`).
  final String userCode;

  /// Approval page; [verificationUriComplete] already carries the code.
  final Uri verificationUri;
  final Uri? verificationUriComplete;

  final Duration expiresIn;

  /// Minimum delay between token polls; the server answers `slow_down` below it.
  final Duration interval;

  @override
  String toString() => 'DeviceAuthorization($userCode, expires in $expiresIn)';
}

/// A device access token (`POST /dsh-webui-oauth/device/token`).
class DeviceToken {
  const DeviceToken({
    required this.accessToken,
    required this.tokenType,
    required this.scope,
    required this.deviceId,
  });

  /// Bearer credential. Persist only in secure storage.
  final String accessToken;
  final String tokenType;
  final String scope;
  final String deviceId;

  @override
  String toString() => 'DeviceToken($deviceId, $tokenType, scope: $scope)';
}

/// The core `dsh web` session minted by the plugin's bridge
/// (`POST /dsh-webui-oauth/device/core-session`).
///
/// [authority] is the `Host` the cookie is bound to; requests must present it.
class CoreSession {
  const CoreSession({
    required this.cookieName,
    required this.cookieValue,
    required this.authority,
  });

  final String cookieName;
  final String cookieValue;
  final String authority;

  /// The cookie in the shape [DshClient.connect] accepts.
  ///
  /// The plugin does not return the cookie's expiry; the client re-mints it
  /// after a 401 instead of guessing.
  DshCookie toDshCookie() =>
      DshCookie(name: cookieName, value: cookieValue, authority: authority);

  @override
  String toString() => 'CoreSession($cookieName for $authority)';
}
