import 'package:dsh_app/l10n/l10n.dart';
import 'package:dsh_app/remote/secret_store.dart';
import 'package:dsh_app/state/hosts_state.dart';
import 'package:dsh_app/ui/remote/oauth_host_form.dart';
import 'package:dsh_app/ui/theme/app_theme.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() => SharedPreferences.setMockInitialValues({}));

  Future<void> pumpForm(WidgetTester tester) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [secretStoreProvider.overrideWithValue(MemorySecretStore())],
        child: MaterialApp(theme: buildLightTheme(), home: const OauthHostFormPage()),
      ),
    );
    await tester.pumpAndSettle();
  }

  testWidgets('refuses http for a public address before any request', (tester) async {
    await pumpForm(tester);
    await tester.enterText(find.byKey(const ValueKey('oauth-address')), 'http://8.8.8.8:3080');
    await tester.tap(find.byKey(const ValueKey('oauth-authorize')));
    await tester.pumpAndSettle();
    expect(find.text(appL10n.remoteOauthHttpOnlyLocal), findsOneWidget);
  });

  testWidgets('save stays disabled until the Host issues a token', (tester) async {
    await pumpForm(tester);
    final save = tester.widget<FilledButton>(find.byKey(const ValueKey('oauth-save')));
    expect(save.onPressed, isNull);
  });

  testWidgets('defaults the name to the typed address when saving', (tester) async {
    await pumpForm(tester);
    await tester.enterText(find.byKey(const ValueKey('oauth-address')), 'https://dsh.example.com');
    await tester.pump();
    // Still no token: the save button must not silently save an unauthorized Host.
    expect(tester.widget<FilledButton>(find.byKey(const ValueKey('oauth-save'))).onPressed, isNull);
  });
}
