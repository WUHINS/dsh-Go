import 'dart:math' as math;

import 'package:dsh_oauth/dsh_oauth.dart';

/// One DSH Host reached over HTTPS through the `dsh-webui-oauth` gate.
///
/// Unlike an SSH host there is nothing to launch: the Host is already running
/// `dsh web` behind its reverse proxy. The App holds a device token
/// ([OauthSecrets.tokenKey]) and asks the plugin for a fresh core session per
/// connection, so the launch token never leaves the Host.
class OauthHostConfig {
  const OauthHostConfig({
    required this.id,
    required this.name,
    required this.baseUrl,
    this.hostHeader,
    this.deviceId,
    this.deviceName,
  });

  /// Stable id (`oauth-<hex>`); also the secret-store namespace.
  final String id;

  /// What the person calls it.
  final String name;

  /// Normalized origin, e.g. `https://dsh.example.com` or
  /// `http://192.168.1.20:3080` (local network only).
  final String baseUrl;

  /// `Host` header override for a reverse proxy that rewrites it to a
  /// loopback address; the core cookie is bound to this authority.
  final String? hostHeader;

  /// `device_id` the Host assigned when the token was issued.
  final String? deviceId;

  /// The name shown on the Host's device list.
  final String? deviceName;

  Uri get baseUri => OauthHostUrl.parse(baseUrl);

  String get address => hostHeader == null ? baseUrl : '$baseUrl · Host: $hostHeader';

  /// Changing where we connect needs a new link; a rename does not.
  String get connectionKey => '$baseUrl\u0000${hostHeader ?? ''}';

  OauthHostConfig copyWith({
    String? name,
    String? baseUrl,
    String? Function()? hostHeader,
    String? deviceId,
    String? deviceName,
  }) => OauthHostConfig(
    id: id,
    name: name ?? this.name,
    baseUrl: baseUrl ?? this.baseUrl,
    hostHeader: hostHeader != null ? hostHeader() : this.hostHeader,
    deviceId: deviceId ?? this.deviceId,
    deviceName: deviceName ?? this.deviceName,
  );

  Map<String, Object?> toJson() => {
    'id': id,
    'name': name,
    'baseUrl': baseUrl,
    if (hostHeader != null) 'hostHeader': hostHeader,
    if (deviceId != null) 'deviceId': deviceId,
    if (deviceName != null) 'deviceName': deviceName,
  };

  static OauthHostConfig? fromJson(Object? raw) {
    if (raw is! Map) return null;
    final id = raw['id'];
    final baseUrl = raw['baseUrl'];
    if (id is! String || id.isEmpty || baseUrl is! String || baseUrl.isEmpty) return null;
    String? text(Object? value) => value is String && value.trim().isNotEmpty ? value.trim() : null;
    final name = text(raw['name']);
    return OauthHostConfig(
      id: id,
      name: name ?? baseUrl,
      baseUrl: baseUrl,
      hostHeader: text(raw['hostHeader']),
      deviceId: text(raw['deviceId']),
      deviceName: text(raw['deviceName']),
    );
  }

  static String newId([math.Random? random]) {
    final r = random ?? math.Random.secure();
    final hex = List.generate(8, (_) => r.nextInt(256).toRadixString(16).padLeft(2, '0')).join();
    return 'oauth-$hex';
  }

  @override
  bool operator ==(Object other) =>
      other is OauthHostConfig &&
      other.id == id &&
      other.name == name &&
      other.baseUrl == baseUrl &&
      other.hostHeader == hostHeader &&
      other.deviceId == deviceId &&
      other.deviceName == deviceName;

  @override
  int get hashCode => Object.hash(id, name, baseUrl, hostHeader, deviceId, deviceName);
}

/// The secret material for one OAuth Host.
class OauthSecrets {
  const OauthSecrets({this.token});

  /// Long-lived device token issued by the plugin; revocable on the Host.
  final String? token;

  static String tokenKey(String hostId) => 'oauth.$hostId.token';
}
