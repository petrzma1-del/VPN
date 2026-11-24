# L2TP/IPsec VPN klient pro Android

Vlastní aplikace bez externích knihoven. Otevře tunel L2TP/IPsec (PSK, MS-CHAPv2) např. ke Kerio Control 9.3.x.

## Sestavení
- **GitHub Actions**: nahrajte projekt do repozitáře, workflow `.github/workflows/build.yml` vytvoří `app-debug.apk` (artefakt).
- **Android Studio**: otevřít složku, Gradle 8.7, JDK 17, Build > Build APK.
- **Terminál**: `./gradlew assembleDebug` → `app/build/outputs/apk/debug/app-debug.apk`.

## Instalace a použití
1. Povolte instalaci z neznámých zdrojů, nainstalujte APK.
2. Vyplňte server, uživatele, heslo a PSK (ukládají se šifrovaně v Keystore).
3. Volitelně trasy (výchozí 0.0.0.0/0), DNS a omezení na vybrané aplikace.
4. Připojit. Při problému použijte „Sdílet log“ (log neobsahuje hesla ani PSK).

## Ověřeno
- Primitiva (RFC 2759 vektory), ESP proti scapy, IKEv1 proti strongSwan, L2TP řízení proti xl2tpd, celý zásobník proti mock serveru (testy v `tests/`).

## Neověřeno / omezení
- APK nebylo v prostředí sestaveno (nedostupné Maven/Google repozitáře); Android vrstva jen kontrola překladu.
- Netestováno proti skutečnému Kerio; pokud vyžaduje MPPE (CCP), spojení selže.
- Bez rekeyingu IKE SA – po vypršení životnosti se klient znovu připojí.
- Zastaralá kryptografie (3DES/SHA1/DH2) kvůli starému Kerio. Bezpečnější alternativa je WireGuard.
