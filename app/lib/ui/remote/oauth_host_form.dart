import 'dart:async';

import 'package:dsh_oauth/dsh_oauth.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:url_launcher/url_launcher.dart';

import '../../l10n/l10n.dart';
import '../../state/hosts_state.dart';
import '../common/app_dialog.dart';
import '../providers/provider_widgets.dart' show FormFieldBlock, FormFieldGroup;
import '../settings/settings_widgets.dart';
import '../shell/page_frame.dart';
import '../theme/app_icons.dart';
import '../theme/theme.dart';

/// Add or re-authorize a DSH Host behind `dsh-webui-oauth`.
///
/// The device flow is the whole point: the App never asks for the Host's
/// WebUI password and never sees the core launch token. It shows the short
/// code, opens the approval page, and waits for the Host to hand back a
/// device token.
class OauthHostFormPage extends ConsumerStatefulWidget {
  const OauthHostFormPage({super.key, this.existing});

  /// Null to add a new host; set to edit or re-authorize.
  final OauthHostConfig? existing;

  @override
  ConsumerState<OauthHostFormPage> createState() => _OauthHostFormPageState();
}

class _OauthHostFormPageState extends ConsumerState<OauthHostFormPage> {
  late final String _id = widget.existing?.id ?? OauthHostConfig.newId();
  late final _name = TextEditingController(text: widget.existing?.name ?? '');
  late final _address = TextEditingController(text: widget.existing?.baseUrl ?? '');
  late final _hostHeader = TextEditingController(text: widget.existing?.hostHeader ?? '');

  OauthDeviceClient? _client;
  Uri? _clientOrigin;
  String? _authorizedFor;
  int _flowEpoch = 0;
  Uri? _approvalUri;
  DeviceAuthorization? _authorization;
  DeviceToken? _token;
  bool _starting = false;
  bool _waiting = false;
  bool _saving = false;
  bool _cancel = false;
  String? _error;
  String? _addressError;

  bool get _editing => widget.existing != null;
  bool get _hasStoredToken => widget.existing != null && widget.existing!.deviceId != null;

  /// Changing where we connect invalidates the device token: it was issued by
  /// the old Host.
  bool get _addressChanged => _editing && _address.text.trim() != widget.existing!.baseUrl;

  bool get _canSave =>
      !_starting &&
      !_waiting &&
      !_saving &&
      ((_token != null && _authorizedFor == _address.text.trim()) || (_hasStoredToken && !_addressChanged));

  @override
  void initState() {
    super.initState();
    _address.addListener(_addressEdited);
  }

  /// A token belongs to the Host that issued it: editing the address after an
  /// authorization makes it stale, and the person authorizes again.
  void _addressEdited() {
    _flowEpoch++;
    if (_addressError != null) setState(() => _addressError = null);
    if (_token != null && _authorizedFor != _address.text.trim()) {
      setState(() {
        _token = null;
        _authorization = null;
        _approvalUri = null;
      });
    }
  }

  OauthDeviceClient _deviceClient(Uri address) {
    final origin = address.replace(path: '', query: null, fragment: null);
    final current = _client;
    if (current != null && _clientOrigin == origin) return current;
    unawaited(current?.close());
    _clientOrigin = origin;
    return _client = OauthDeviceClient(origin);
  }

  /// The approval page is built from the request Host; a reverse proxy that
  /// rewrites it can hand back a loopback URL. Send the browser to the
  /// configured origin instead (same path, code and query).
  Uri _browserApprovalUri(DeviceAuthorization authorization, Uri address) {
    final raw = authorization.verificationUriComplete ?? authorization.verificationUri;
    final loopback = raw.host == '127.0.0.1' || raw.host == '::1' || raw.host == 'localhost';
    if (!loopback || raw.host == address.host) return raw;
    return raw.replace(scheme: address.scheme, host: address.host, port: address.port);
  }

  @override
  void dispose() {
    _address.removeListener(_addressEdited);
    _cancel = true;
    unawaited(_client?.close());
    _name.dispose();
    _address.dispose();
    _hostHeader.dispose();
    super.dispose();
  }

  Uri? _parseAddress() {
    try {
      return OauthHostUrl.parse(_address.text);
    } on OauthHostUrlException catch (error) {
      setState(
        () => _addressError = switch (error.error) {
          OauthHostUrlError.empty => appL10n.remoteOauthAddressInvalid,
          OauthHostUrlError.insecurePublic => appL10n.remoteOauthHttpOnlyLocal,
          _ => appL10n.remoteOauthAddressInvalid,
        },
      );
      return null;
    }
  }

  Future<void> _authorize() async {
    setState(() {
      _addressError = null;
      _error = null;
    });
    final address = _parseAddress();
    if (address == null) return;
    final epoch = ++_flowEpoch;
    setState(() {
      _starting = true;
      _authorization = null;
      _token = null;
      _authorizedFor = null;
    });
    final client = _deviceClient(address);
    try {
      final name = _name.text.trim();
      final authorization = await client.authorize(
        clientName: name.isEmpty ? 'DSH App' : 'DSH App · $name',
        description: 'dsh-Go',
      );
      if (!mounted) return;
      final approval = _browserApprovalUri(authorization, address);
      setState(() {
        _authorization = authorization;
        _approvalUri = approval;
        _starting = false;
        _waiting = true;
      });
      unawaited(_openApproval(approval));
      final token = await waitForDeviceToken(client, authorization, cancelled: () => _cancel || !mounted);
      if (!mounted || epoch != _flowEpoch) return;
      setState(() {
        _token = token;
        _authorizedFor = address.toString();
        _waiting = false;
      });
    } on OauthException catch (error) {
      if (!mounted || epoch != _flowEpoch) return;
      setState(() {
        _waiting = false;
        _starting = false;
        _error = switch (error.code) {
          OauthErrorCodes.accessDenied => appL10n.remoteOauthDenied,
          OauthErrorCodes.expiredToken => appL10n.remoteOauthExpired,
          OauthErrorCodes.deviceTokenRequired => appL10n.remoteOauthRevoked,
          OauthErrorCodes.coreSessionUnavailable => appL10n.remoteOauthCoreUnavailable,
          _ => error.detail ?? error.message,
        };
      });
    } on DeviceFlowCancelled {
      if (mounted && epoch == _flowEpoch) setState(() => _waiting = false);
    } catch (error) {
      if (mounted && epoch == _flowEpoch) {
        setState(() {
          _waiting = false;
          _starting = false;
          _error = '$error';
        });
      }
    }
  }

  Future<void> _openApproval(Uri uri) async {
    try {
      await launchUrl(uri, mode: LaunchMode.externalApplication);
    } catch (_) {
      // The code row stays on screen with a copy button; nothing to do here.
    }
  }

  Future<void> _save() async {
    if (_saving) return;
    final address = _parseAddress();
    if (address == null) return;
    setState(() {
      _saving = true;
      _error = null;
    });
    final config = OauthHostConfig(
      id: _id,
      name: _name.text.trim().isEmpty ? address.host : _name.text.trim(),
      baseUrl: address.toString(),
      hostHeader: _hostHeader.text.trim().isEmpty ? null : _hostHeader.text.trim(),
      deviceId: _token?.deviceId ?? widget.existing?.deviceId,
      deviceName: _name.text.trim().isEmpty ? null : _name.text.trim(),
    );
    final ok = await ref.read(hostsProvider.notifier).saveOauth(config, token: _token?.accessToken);
    if (!mounted) return;
    setState(() => _saving = false);
    if (!ok) {
      setState(() => _error = appL10n.commonConnectionFailed);
      return;
    }
    Navigator.of(context).pop(config);
  }

  Future<void> _delete() async {
    final l10n = context.l10n;
    final ok = await showAppDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (dialog) => AlertDialog(
        title: Text(l10n.remoteDeleteHost),
        content: Text(l10n.remoteOauthDeleteConfirm),
        actions: [
          TextButton(onPressed: () => Navigator.pop(dialog, false), child: Text(l10n.commonCancel)),
          FilledButton(
            style: FilledButton.styleFrom(
              backgroundColor: DshColors.of(dialog).danger,
              foregroundColor: DshColors.of(dialog).onDanger,
            ),
            onPressed: () => Navigator.pop(dialog, true),
            child: Text(l10n.commonDelete),
          ),
        ],
      ),
    );
    if (ok != true || !mounted) return;
    await ref.read(hostsProvider.notifier).removeOauth(_id);
    if (mounted) Navigator.of(context).pop();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    final theme = Theme.of(context);
    final colors = DshColors.of(context);
    final monoStyle = AppType.mono(size: 15, color: theme.colorScheme.onSurface, height: 1.4);
    final authorization = _authorization;
    return AppPage(
      title: _editing ? l10n.remoteOauthHost : l10n.remoteOauthAdd,
      subtitle: Text(l10n.remoteOauthRequirements),
      slivers: [
        SliverList.list(
          children: [
            FormFieldGroup(
              children: [
                FormFieldBlock(
                  label: l10n.commonName,
                  child: TextField(
                    key: const ValueKey('oauth-name'),
                    controller: _name,
                    textInputAction: TextInputAction.next,
                    decoration: InputDecoration(hintText: l10n.remoteOauthNameHint),
                  ),
                ),
                FormFieldBlock(
                  label: l10n.remoteOauthAddress,
                  error: _addressError,
                  child: TextField(
                    key: const ValueKey('oauth-address'),
                    controller: _address,
                    keyboardType: TextInputType.url,
                    autocorrect: false,
                    textInputAction: TextInputAction.next,
                    style: monoStyle,
                    onChanged: (_) {
                      if (_addressError != null) setState(() => _addressError = null);
                    },
                    decoration: InputDecoration(hintText: l10n.remoteOauthAddressHint),
                  ),
                ),
                FormFieldBlock(
                  label: l10n.remoteOauthHostHeader,
                  helper: l10n.remoteOauthRequirements,
                  child: TextField(
                    key: const ValueKey('oauth-host-header'),
                    controller: _hostHeader,
                    autocorrect: false,
                    style: monoStyle,
                    decoration: const InputDecoration(hintText: '127.0.0.1:3080'),
                  ),
                ),
              ],
            ),
            if (authorization != null && _token == null)
              SettingsSection(
                title: l10n.remoteOauthWaiting,
                footer: Text(l10n.remoteOauthWaitingHint),
                children: [
                  SettingsTile(
                    icon: AppIcons.apiKey,
                    tinted: false,
                    title: l10n.remoteOauthUserCode,
                    subtitle: authorization.userCode,
                    value: Text(
                      authorization.userCode,
                      style: theme.textTheme.titleMedium?.copyWith(letterSpacing: 3, fontFeatures: const []),
                    ),
                    onTap: () => Clipboard.setData(ClipboardData(text: authorization.userCode)),
                  ),
                  SettingsTile(
                    icon: AppIcons.webConsole,
                    tinted: false,
                    title: l10n.remoteOauthOpenBrowser,
                    subtitle: (authorization.verificationUriComplete ?? authorization.verificationUri).host,
                    onTap: _approvalUri == null ? null : () => unawaited(_openApproval(_approvalUri!)),
                  ),
                ],
              ),
            if (_token != null)
              SettingsSection(
                title: l10n.remoteOauthApproved,
                children: [
                  SettingsTile(
                    icon: AppIcons.selected,
                    tinted: false,
                    title: _name.text.trim().isEmpty ? _address.text.trim() : _name.text.trim(),
                    subtitle: _address.text.trim(),
                  ),
                ],
              ),
            if (_waiting)
              const Padding(padding: EdgeInsets.fromLTRB(24, 8, 24, 24), child: LinearProgressIndicator(minHeight: 2)),
            if (_error case final error?)
              Padding(
                padding: const EdgeInsets.fromLTRB(24, 0, 24, 16),
                child: Text(error, style: theme.textTheme.bodySmall?.copyWith(color: colors.danger)),
              ),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 24),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  FilledButton.tonalIcon(
                    key: const ValueKey('oauth-authorize'),
                    onPressed: _starting || _waiting ? null : _authorize,
                    icon: _starting
                        ? const SizedBox.square(dimension: 16, child: CircularProgressIndicator(strokeWidth: 2))
                        : const Icon(AppIcons.link, size: 19),
                    label: Text(_token == null ? l10n.remoteOauthStart : l10n.remoteOauthStart),
                  ),
                  const SizedBox(height: 12),
                  FilledButton(
                    key: const ValueKey('oauth-save'),
                    onPressed: _canSave ? _save : null,
                    child: Text(_saving ? l10n.remoteConnecting : l10n.commonSave),
                  ),
                  if (_editing) ...[
                    const SizedBox(height: 8),
                    TextButton.icon(
                      style: TextButton.styleFrom(foregroundColor: colors.danger),
                      onPressed: _delete,
                      icon: const Icon(AppIcons.delete, size: 19),
                      label: Text(l10n.remoteOauthDelete),
                    ),
                  ],
                ],
              ),
            ),
            const SizedBox(height: 24),
          ],
        ),
      ],
    );
  }
}
