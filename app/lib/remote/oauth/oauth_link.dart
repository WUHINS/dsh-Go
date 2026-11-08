import 'dart:async';

import 'package:dsh_client/dsh_client.dart';
import 'package:dsh_oauth/dsh_oauth.dart';

import '../../l10n/l10n.dart';
import '../link_status.dart';
import 'oauth_host_config.dart';

/// Connects with a cookie the plugin minted (plus the device token, so the
/// gate accepts every request and the WebSocket upgrade).
typedef OauthClientConnector = Future<DshClient> Function({
  required Uri baseUri,
  required DshCookie cookie,
  required String bearer,
  String? hostHeader,
});

Future<DshClient> _defaultConnector({
  required Uri baseUri,
  required DshCookie cookie,
  required String bearer,
  String? hostHeader,
}) => DshClient.connect(baseUri: baseUri, cookie: cookie, bearer: bearer, hostHeader: hostHeader);

/// A DSH Host behind the `dsh-webui-oauth` gate, reached over HTTPS.
///
/// One attempt:
/// 1. read the device token (secure storage);
/// 2. `POST /dsh-webui-oauth/device/core-session` → a `dsh-auth-*` cookie;
/// 3. [DshClient.connect] with that cookie plus `Authorization: Bearer`, so
///    every HTTP call and the `/api/remote.mux` upgrade pass the gate;
/// 4. keep the session alive and re-mint it when the Host restarts.
///
/// Nothing here knows about SSH, relays or WebRTC: the carrier is the app's
/// ordinary HTTP carrier, which is the point — a Host behind the gate has the
/// full `dsh web` API.
class OauthHostLink implements HostLink {
  OauthHostLink({
    required this._config,
    required this._loadToken,
    OauthDeviceClient Function(Uri baseUri)? clientFactory,
    OauthClientConnector? connectClient,
    Stream<void>? kicks,
    Backoff? backoff,
    this.keepAliveInterval = const Duration(seconds: 25),
    this.keepAliveTimeout = const Duration(seconds: 8),
  }) : _clientFactory = clientFactory ?? OauthDeviceClient.new,
       _connectClient = connectClient ?? _defaultConnector,
       _backoff = backoff ?? Backoff() {
    _kickSub = kicks?.listen((_) => kick());
  }

  OauthHostConfig _config;
  final Future<String?> Function() _loadToken;
  final OauthDeviceClient Function(Uri baseUri) _clientFactory;
  final OauthClientConnector _connectClient;
  final Backoff _backoff;
  final Duration keepAliveInterval;
  final Duration keepAliveTimeout;

  final _statuses = StreamController<HostLinkStatus>.broadcast(sync: true);
  final _clients = StreamController<DshClient>.broadcast();
  final _delay = InterruptibleDelay();
  StreamSubscription<void>? _kickSub;
  StreamSubscription<DshConnectionState>? _muxSub;
  Timer? _keepAlive;

  HostLinkStatus _status = HostLinkStatus.idle;
  OauthDeviceClient? _api;
  DshClient? _client;
  Future<DshClient>? _opening;
  bool _closed = false;
  bool _recovering = false;
  int _missedPings = 0;

  OauthHostConfig get config => _config;

  /// A rename or a new `Host` override applies in place; a new URL needs a
  /// new link (the provider watches [OauthHostConfig.connectionKey]).
  void updateConfig(OauthHostConfig next) {
    _config = _config.copyWith(name: next.name, hostHeader: () => next.hostHeader, deviceId: next.deviceId);
  }

  @override
  HostLinkStatus get status => _status;

  @override
  Stream<HostLinkStatus> get statuses => _statuses.stream;

  @override
  Stream<DshClient> get clients => _clients.stream;

  @override
  DshClient? get currentClient => _status.isConnected ? _client : null;

  void _emit(HostLinkStatus next) {
    if (_closed) return;
    _status = next;
    _statuses.add(next);
  }

  @override
  Future<DshClient> open() {
    if (_closed) return Future.error(StateError('link closed'));
    final client = _client;
    if (client != null && _status.isConnected) return Future.value(client);
    return _opening ??= _run().whenComplete(() => _opening = null);
  }

  Future<DshClient> _run() async {
    _backoff.reset();
    var last = HostLinkError(HostLinkErrorKind.other, appL10n.commonConnectionFailed, retryable: true);
    while (!_closed) {
      try {
        return await _connectOnce();
      } on HostLinkError catch (error) {
        last = error;
      } catch (error) {
        last = HostLinkError(
          HostLinkErrorKind.other,
          appL10n.commonConnectionFailed,
          detail: '$error',
          retryable: true,
        );
      }
      if (_closed || !last.retryable || _backoff.exhausted) break;
      final delay = _backoff.next();
      _emit(
        HostLinkStatus(
          HostLinkPhase.reconnecting,
          attempt: _backoff.attempt,
          error: last,
          nextRetryAt: DateTime.now().add(delay),
        ),
      );
      await _delay.wait(delay);
    }
    _emit(HostLinkStatus(HostLinkPhase.failed, error: last));
    throw last;
  }

  Future<DshClient> _connectOnce() async {
    _emit(_status.withStep(HostLinkStep.connect, detail: _config.address));
    final token = await _loadToken();
    if (_closed) throw StateError('link closed');
    if (token == null || token.isEmpty) {
      throw HostLinkError(HostLinkErrorKind.notLoggedIn, appL10n.remoteOauthRevoked);
    }
    final api = _api ??= _clientFactory(_config.baseUri);
    _emit(_status.withStep(HostLinkStep.login, detail: appL10n.remoteOauthStarting));

    final CoreSession session;
    try {
      session = await api.coreSession(token);
    } on OauthException catch (error) {
      throw _map(error);
    }
    if (_closed) throw StateError('link closed');

    _emit(_status.withStep(HostLinkStep.login, detail: appL10n.remoteOauthConnecting));
    final DshClient client;
    try {
      client = await _connectClient(
        baseUri: _config.baseUri,
        cookie: session.toDshCookie(),
        bearer: token,
        hostHeader: _config.hostHeader,
      );
    } on DshHttpException catch (error) {
      final status = error.statusCode;
      if (status == 401 || status == 403) {
        // The plugin minted a cookie the core refused: the Host's authority
        // and the address we dial disagree (a rewriting proxy without a
        // `Host` override), or the gate changed between the two calls.
        throw HostLinkError(
          HostLinkErrorKind.loginFailed,
          appL10n.remoteOauthSessionRejected,
          detail: '$error',
          retryable: false,
        );
      }
      throw HostLinkError(
        HostLinkErrorKind.loginFailed,
        appL10n.commonConnectionFailed,
        detail: '$error',
        retryable: true,
      );
    } on DshException catch (error) {
      throw HostLinkError(
        HostLinkErrorKind.unreachable,
        appL10n.commonConnectionFailed,
        detail: '$error',
        retryable: true,
      );
    }
    if (_closed) {
      await client.close().catchError((_) {});
      throw StateError('link closed');
    }

    final previous = _client;
    _client = client;
    _watchMux(client);
    _emit(HostLinkStatus(HostLinkPhase.connected, completed: HostLinkStep.values.toSet()));
    _startKeepAlive();
    if (previous != null) {
      _clients.add(client);
      unawaited(previous.close().catchError((_) {}));
    }
    return client;
  }

  /// Maps the device-flow errors a link can meet to the shared vocabulary.
  HostLinkError _map(OauthException error) {
    switch (error.code) {
      case OauthErrorCodes.deviceTokenRequired:
      case OauthErrorCodes.expiredToken:
      case OauthErrorCodes.accessDenied:
      case OauthErrorCodes.invalidGrant:
        return HostLinkError(HostLinkErrorKind.notLoggedIn, appL10n.remoteOauthRevoked, detail: error.detail);
      case OauthErrorCodes.coreSessionUnavailable:
        return HostLinkError(HostLinkErrorKind.other, appL10n.remoteOauthCoreUnavailable, detail: error.detail);
      case OauthErrorCodes.network:
        return HostLinkError(
          HostLinkErrorKind.unreachable,
          appL10n.commonConnectionFailed,
          detail: error.detail,
          retryable: true,
        );
      case OauthErrorCodes.http:
        if (error.statusCode == 404) {
          return HostLinkError(HostLinkErrorKind.other, appL10n.remoteOauthPluginMissing, detail: error.detail);
        }
        return HostLinkError(
          HostLinkErrorKind.other,
          appL10n.commonConnectionFailed,
          detail: error.toString(),
          retryable: error.statusCode == null || error.statusCode! >= 500,
        );
      default:
        return HostLinkError(
          HostLinkErrorKind.other,
          appL10n.commonConnectionFailed,
          detail: error.detail ?? error.message,
          retryable: error.retryable,
        );
    }
  }

  void _watchMux(DshClient client) {
    unawaited(_muxSub?.cancel());
    _muxSub = client.mux.states.listen((state) {
      if (state == DshConnectionState.unauthorized && identical(client, _client)) {
        _lost(HostLinkError(HostLinkErrorKind.loginFailed, appL10n.remoteOauthSessionExpired, retryable: true));
      }
    });
  }

  void _startKeepAlive() {
    _keepAlive?.cancel();
    _missedPings = 0;
    _keepAlive = Timer.periodic(keepAliveInterval, (_) => unawaited(_tick()));
  }

  Future<void> _tick() async {
    final client = _client;
    if (client == null || _status.phase != HostLinkPhase.connected) return;
    final health = await client.connection.checkHealth(timeout: keepAliveTimeout);
    if (!identical(client, _client) || _closed) return;
    switch (health) {
      case DshHealth.ok:
        _missedPings = 0;
      case DshHealth.unauthorized:
        // The 30-day core cookie can outlive a `dsh web` restart only while
        // the signing secret stays; other changes need a fresh session.
        _lost(HostLinkError(HostLinkErrorKind.loginFailed, appL10n.remoteOauthSessionExpired, retryable: true));
      case DshHealth.unreachable:
        _missedPings++;
        if (_missedPings >= 2) {
          _lost(HostLinkError(HostLinkErrorKind.unreachable, appL10n.commonConnectionFailed, retryable: true));
        }
    }
  }

  void _lost(HostLinkError reason) {
    if (_closed || _recovering || _status.phase != HostLinkPhase.connected) return;
    _teardownClient();
    unawaited(_recover(reason).then((_) {}, onError: (_) {}));
  }

  Future<DshClient> _recover(HostLinkError reason) async {
    _recovering = true;
    var last = reason;
    try {
      while (!_closed) {
        if (_backoff.exhausted) {
          _emit(HostLinkStatus(HostLinkPhase.failed, error: last));
          throw last;
        }
        final delay = _backoff.next();
        _emit(
          HostLinkStatus(
            HostLinkPhase.reconnecting,
            attempt: _backoff.attempt,
            error: last,
            nextRetryAt: DateTime.now().add(delay),
          ),
        );
        await _delay.wait(delay);
        if (_closed) break;
        try {
          final client = await _connectOnce();
          _backoff.reset();
          return client;
        } on HostLinkError catch (error) {
          if (!error.retryable) {
            _emit(HostLinkStatus(HostLinkPhase.failed, error: error));
            rethrow;
          }
          last = error;
        }
      }
      throw StateError('link closed');
    } finally {
      _recovering = false;
    }
  }

  void _teardownClient() {
    _keepAlive?.cancel();
    _keepAlive = null;
    _muxSub?.cancel();
    _muxSub = null;
    final client = _client;
    _client = null;
    if (client != null) unawaited(client.close().catchError((_) {}));
  }

  @override
  void kick() {
    if (_closed) return;
    switch (_status.phase) {
      case HostLinkPhase.connected:
        unawaited(_tick());
      case HostLinkPhase.reconnecting:
        _backoff.reset();
        _delay.skip();
      case HostLinkPhase.failed:
        if (_status.error?.retryable ?? false) retry();
      case HostLinkPhase.idle || HostLinkPhase.connecting:
        break;
    }
  }

  @override
  void retry() {
    if (_closed || (_status.isBusy && _status.phase != HostLinkPhase.reconnecting)) return;
    if (_status.phase == HostLinkPhase.reconnecting) {
      _backoff.reset();
      _delay.skip();
      return;
    }
    if (_status.phase == HostLinkPhase.connected) unawaited(_tick());
    if (_status.phase == HostLinkPhase.failed || _status.phase == HostLinkPhase.idle) {
      unawaited(open().then((_) {}, onError: (_) {}));
    }
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _emit(HostLinkStatus.idle);
    _closed = true;
    _delay.cancel();
    await _kickSub?.cancel();
    _teardownClient();
    final api = _api;
    _api = null;
    await api?.close();
    await _statuses.close();
    await _clients.close();
  }
}
