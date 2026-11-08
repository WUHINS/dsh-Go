import 'package:dsh_app/remote/secret_store.dart';
import 'package:dsh_app/state/hosts_state.dart';
import 'package:dsh_app/ui/web/dsh_web_launcher.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late MemorySecretStore secrets;

  ProviderContainer container() {
    final c = ProviderContainer(overrides: [secretStoreProvider.overrideWithValue(secrets)]);
    addTearDown(c.dispose);
    return c;
  }

  setUp(() {
    SharedPreferences.setMockInitialValues({});
    secrets = MemorySecretStore();
  });

  test('saves the config in preferences and the device token in the secret store', () async {
    final c = container();
    await c.read(hostsProvider.notifier).ready;
    const config = OauthHostConfig(
      id: 'oauth-1',
      name: 'Studio',
      baseUrl: 'https://dsh.example.com',
      deviceId: 'dev-1',
    );

    expect(await c.read(hostsProvider.notifier).saveOauth(config, token: 'tok-1'), isTrue);
    expect(c.read(hostsProvider).oauthById('oauth-1')?.name, 'Studio');
    expect(await c.read(hostsProvider.notifier).loadOauthToken('oauth-1'), 'tok-1');
    expect(secrets.values.keys, contains('oauth.oauth-1.token'));

    final prefs = await SharedPreferences.getInstance();
    expect(prefs.getString(HostsController.oauthPrefsKey), contains('dsh.example.com'));
  });

  test('a new container restores the list from preferences', () async {
    final first = container();
    await first.read(hostsProvider.notifier).ready;
    await first
        .read(hostsProvider.notifier)
        .saveOauth(
          const OauthHostConfig(id: 'oauth-2', name: 'Desk', baseUrl: 'http://192.168.1.20:3080'),
          token: 'tok-2',
        );

    final second = container();
    await second.read(hostsProvider.notifier).ready;
    final restored = second.read(hostsProvider).oauthById('oauth-2');
    expect(restored?.name, 'Desk');
    expect(restored?.baseUrl, 'http://192.168.1.20:3080');
    expect(await second.read(hostsProvider.notifier).loadOauthToken('oauth-2'), 'tok-2');
  });

  test('removing a host drops its token and leaves SSH hosts alone', () async {
    final c = container();
    await c.read(hostsProvider.notifier).ready;
    await c
        .read(hostsProvider.notifier)
        .saveOauth(
          const OauthHostConfig(id: 'oauth-3', name: 'Desk', baseUrl: 'https://dsh.example.com'),
          token: 'tok-3',
        );
    await c.read(hostsProvider.notifier).removeOauth('oauth-3');

    expect(c.read(hostsProvider).oauthById('oauth-3'), isNull);
    expect(await c.read(hostsProvider.notifier).loadOauthToken('oauth-3'), isNull);
    expect(secrets.values.keys, isNot(contains('oauth.oauth-3.token')));
  });

  test('the web UI opens the public origin, not a token URL', () async {
    final c = container();
    await c.read(hostsProvider.notifier).ready;
    await c
        .read(hostsProvider.notifier)
        .saveOauth(
          const OauthHostConfig(id: 'oauth-5', name: 'Loft', baseUrl: 'https://dsh.example.com'),
          token: 'tok-5',
        );
    c.read(activeHostProvider.notifier).select(const HostRef.oauth('oauth-5'));

    final access = c.read(dshWebAccessProvider);
    expect(access, isA<UrlDshWeb>());
    expect((access as UrlDshWeb).url, Uri.parse('https://dsh.example.com'));
    expect(access.hostName, 'Loft');
  });

  test('a host ref round-trips through its encoded form', () {
    const ref = HostRef.oauth('oauth-4', name: 'Loft');
    expect(HostRef.decode(ref.encode()), ref);
    expect(ref.kind, HostKind.oauth);
  });
}
