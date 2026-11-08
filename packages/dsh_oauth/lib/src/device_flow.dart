/// Polling loop shared by the App UI and the link.
library;

import 'dart:async';

import 'device_client.dart';
import 'models.dart';

/// The person closed the sheet / the link was disposed while waiting.
class DeviceFlowCancelled implements Exception {
  const DeviceFlowCancelled();

  @override
  String toString() => 'DeviceFlowCancelled';
}

/// Polls [client] until the person approves, the code expires, or [cancelled]
/// returns true.
///
/// `slow_down` extends the interval by five seconds, as RFC 8628 §3.5 asks.
/// [onWait] receives the next delay so the UI can show a countdown.
Future<DeviceToken> waitForDeviceToken(
  OauthDeviceClient client,
  DeviceAuthorization authorization, {
  bool Function()? cancelled,
  void Function(Duration wait)? onWait,
  Duration? hardTimeout,
}) async {
  var interval = authorization.interval;
  final deadline = DateTime.now().add(hardTimeout ?? authorization.expiresIn);
  while (true) {
    if (cancelled?.call() ?? false) throw const DeviceFlowCancelled();
    if (DateTime.now().isAfter(deadline)) {
      throw const OauthException(
        OauthErrorCodes.expiredToken,
        'The approval code expired.',
      );
    }
    try {
      return await client.pollToken(authorization.deviceCode);
    } on OauthException catch (error) {
      switch (error.code) {
        case OauthErrorCodes.authorizationPending:
          break;
        case OauthErrorCodes.slowDown:
          interval += const Duration(seconds: 5);
          break;
        case OauthErrorCodes.expiredToken:
        case OauthErrorCodes.accessDenied:
        case OauthErrorCodes.invalidGrant:
          rethrow;
        default:
          if (!error.retryable) rethrow;
      }
    }
    if (cancelled?.call() ?? false) throw const DeviceFlowCancelled();
    onWait?.call(interval);
    await Future<void>.delayed(interval);
  }
}
