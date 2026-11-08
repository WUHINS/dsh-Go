/// Client for a DSH Host behind the `dsh-webui-oauth` WebUI auth gate.
///
/// The plugin authenticates browsers with a session cookie and native clients
/// with a device token (RFC 8628). This package implements the device-token
/// half and the plugin's core-session bridge, so the App can build an ordinary
/// `DshClient` over HTTPS — no SSH, no relay, no allow-list.
library;

export 'src/device_client.dart';
export 'src/device_flow.dart';
export 'src/host_url.dart';
export 'src/models.dart';
