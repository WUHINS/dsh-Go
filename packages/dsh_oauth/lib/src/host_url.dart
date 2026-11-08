/// Base URL rules for a DSH Host behind `dsh-webui-oauth`.
///
/// The auth gate only adds authentication; the transport is still plain
/// HTTP(S). The App therefore refuses to send a device token over cleartext
/// unless the Host is an address that cannot leave the local network:
/// loopback, RFC 1918, link-local, IPv6 ULA, or CGNAT. Every other Host must
/// use `https`.
library;

import 'dart:io';

/// Why a Host URL was refused.
enum OauthHostUrlError {
  /// Nothing was entered.
  empty,

  /// Not `http` or `https`.
  scheme,

  /// `user:password@host`.
  credentials,

  /// A query string or fragment.
  query,

  /// No host name or address.
  host,

  /// `http` for a Host that is not a local-network address.
  insecurePublic,
}

/// A refused Host URL, with a code the UI can translate.
class OauthHostUrlException implements Exception {
  const OauthHostUrlException(this.error, this.message);

  final OauthHostUrlError error;
  final String message;

  @override
  String toString() => 'OauthHostUrlException(${error.name}): $message';
}

/// Parses and normalizes the address of a DSH Host.
///
/// Accepted forms:
/// * `https://dsh.example.com`
/// * `https://dsh.example.com:8443/dsh` (a mounted Host keeps its path)
/// * `http://192.168.1.20:3080` (local-network address only)
///
/// A missing scheme means `https`. Trailing slashes are removed; default
/// ports are dropped so the same Host always produces the same key.
abstract final class OauthHostUrl {
  static Uri parse(String input) {
    final text = input.trim();
    if (text.isEmpty) {
      throw const OauthHostUrlException(
        OauthHostUrlError.empty,
        'Enter the Host address.',
      );
    }
    final withScheme = RegExp(r'^[a-zA-Z][a-zA-Z0-9+.-]*://').hasMatch(text)
        ? text
        : 'https://$text';
    final uri = Uri.tryParse(withScheme);
    if (uri == null) {
      throw const OauthHostUrlException(
        OauthHostUrlError.host,
        'That is not a valid address.',
      );
    }
    if (uri.scheme != 'http' && uri.scheme != 'https') {
      throw OauthHostUrlException(
        OauthHostUrlError.scheme,
        'Use http:// or https:// (got ${uri.scheme}).',
      );
    }
    if (uri.userInfo.isNotEmpty) {
      throw const OauthHostUrlException(
        OauthHostUrlError.credentials,
        'Remove the user name and password from the address.',
      );
    }
    if (uri.hasQuery || uri.hasFragment) {
      throw const OauthHostUrlException(
        OauthHostUrlError.query,
        'The Host address cannot carry a query string or fragment.',
      );
    }
    if (uri.host.isEmpty) {
      throw const OauthHostUrlException(
        OauthHostUrlError.host,
        'The address has no host.',
      );
    }
    if (uri.scheme == 'http' && !isLocalNetworkHost(uri.host)) {
      throw const OauthHostUrlException(
        OauthHostUrlError.insecurePublic,
        'http:// is only allowed for local-network addresses; use https:// here.',
      );
    }
    var path = uri.path;
    while (path.endsWith('/')) {
      path = path.substring(0, path.length - 1);
    }
    final defaultPort = uri.scheme == 'https' ? 443 : 80;
    return Uri(
      scheme: uri.scheme,
      host: uri.host,
      port: uri.hasPort ? uri.port : defaultPort,
      path: path,
    ).replace(
      port: uri.hasPort && uri.port != defaultPort ? uri.port : defaultPort,
    );
  }

  /// Whether [host] is a literal local-network address.
  ///
  /// Host names are deliberately not accepted for `http` (a LAN-only name can
  /// still resolve to a public address). `localhost` is the one exception
  /// because it is defined as loopback.
  static bool isLocalNetworkHost(String host) {
    final lower = host.toLowerCase();
    if (lower == 'localhost') return true;
    final unbracketed = lower.startsWith('[') && lower.endsWith(']')
        ? lower.substring(1, lower.length - 1)
        : lower;
    final address = InternetAddress.tryParse(unbracketed);
    if (address == null) return false;
    final bytes = address.rawAddress;
    if (address.type == InternetAddressType.IPv6) {
      if (bytes.length != 16) return false;
      // ::1
      if (bytes.take(15).every((b) => b == 0) && bytes.last == 1) return true;
      // IPv4-mapped ::ffff:a.b.c.d — apply the IPv4 rules to the tail.
      if (bytes.take(10).every((b) => b == 0) &&
          bytes[10] == 0xff &&
          bytes[11] == 0xff) {
        return _isPrivateIpv4(bytes[12], bytes[13], bytes[14], bytes[15]);
      }
      // fc00::/7 (unique local)
      if ((bytes[0] & 0xfe) == 0xfc) return true;
      // fe80::/10 (link-local)
      if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80) return true;
      return false;
    }
    if (bytes.length != 4) return false;
    return _isPrivateIpv4(bytes[0], bytes[1], bytes[2], bytes[3]);
  }

  static bool _isPrivateIpv4(int a, int b, int c, int d) {
    // 0.0.0.0/8 ("this network") and 127/8 (loopback).
    if (a == 0 || a == 127) return true;
    // 10/8
    if (a == 10) return true;
    // 172.16/12
    if (a == 172 && b >= 16 && b <= 31) return true;
    // 192.168/16
    if (a == 192 && b == 168) return true;
    // 169.254/16 (link-local)
    if (a == 169 && b == 254) return true;
    // 100.64/10 (carrier-grade NAT; common on home routers and tunnels).
    if (a == 100 && b >= 64 && b <= 127) return true;
    return false;
  }
}
