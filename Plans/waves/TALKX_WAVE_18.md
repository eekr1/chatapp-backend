# TalkX Wave 18 Plan — Android Release Zinciri ve WebView Davranış Eşliği

> Bu belge yalnız Wave 18 için hazırlanmış uygulama planıdır.
> Canonical sıra Plan C `C-MOB-001` → Plan A `A-MOB-001` şeklindedir.
> Ana ilke: Android paketi hangi kaynak, release, frontend bundle, backend environment ve imza ile üretildiğini kanıtlar; aynı React ürünü WebView içinde back/lifecycle/network/push/media davranışını kaybetmez.
> Plan hazırdır. Wave 18 aktif değildir, Wave 01–17 kapanmamıştır ve uygulama başlamamıştır. Wave 19 ayrı belgede planlanmıştır; burada aktive edilmez veya uygulanmaz.

## 1. Durum ve yürütme sınırı

- **Wave:** 18
- **Wave adı:** Android release zinciri ve WebView davranış eşliği
- **Plan katılımı:** Plan C + Plan A
- **Canonical sıra:** `C-MOB-001` → `A-MOB-001`
- **Plan durumu:** Hazır
- **Wave durumu:** Bekliyor
- **Uygulama durumu:** Başlamadı
- **Uygulama yetkisi:** Verilmedi
- **Giriş kapısı:** Wave 17 `QA kapalı` ve kullanıcıdan açık "Wave 18'i başlat" talimatı
- **Mevcut blokaj:** Wave 01–17 uygulanıp kapanmadı; Wave 18 uygulanamaz
- **Önceki wave:** Wave 17 — planı hazır, aktif değil
- **Sonraki wave:** Wave 19 — ayrı planı hazır; aktif değil ve başlatılmadı

Bu dosyanın hazırlanması Wave 18 aktivasyonu, version bump, frontend/Gradle build, Capacitor sync, dependency/lockfile değişikliği, signing/keystore erişimi, secret/config değişikliği, emulator/cihaz çalıştırma, Firebase/Play Console işlemi, AAB/APK upload, rollout, production deploy veya Wave 19 aktivasyonu için yetki değildir.

## 2. Canonical referanslar ve otorite

1. `C-MOB-001` — versionName/versionCode, ortak version kaynağı, frontend build, Capacitor sync, asset hash, environment URL, signing, debug/release, manifest/permissions, Data Safety/content rating, cihaz smoke, Play rollout/rollback ve release notes
2. `A-MOB-001` — native/no-origin, safe-area/100dvh, Android back, background/foreground, network değişimi, push deep-link, media/camera izinleri, WebView sürümü ve bundle/backend compatibility
3. Master §12 — repo/release/operation sahipliği, version birliği, tag/changelog/deploy SHA ve environment
4. Master §15 — temiz kurulum, system UI/keyboard/back, izin, lifecycle/network, push, sürüm/asset ve deep-link manuel matrisi
5. Wave 01 `C-COMP-001` — target audience, content rating, bölgesel dağıtım, Data Safety ve store beyanı otoritesi
6. Wave 02 `B-SEC-001/B-API-001/B-AUTH-001/B-WS-001` — native no-origin, API/auth/socket güvenliği
7. Wave 03 `A-FND-002/A-A11Y-001` — tema, safe-area, 100dvh, touch/focus ve reduced motion
8. Wave 05 `B-WS-002/A-MATCH-004` — reconnect, active search/offer/chat recovery ve back state izolasyonu
9. Wave 08–13 — scope, offer, outbox/media, legal/account, locale/push/System deep-link akışları
10. Wave 16 `B-OBS-002/C-REL-001` — Android crash/release/symbol ve recovery görünürlüğü
11. Wave 17 `A-QA-001/B-QA-001/C-CI-001` — build/test/artifact/secret kapıları ve Android handoff
12. Wave 19 `C-QA-001` — sonraki bütünleşik son QA; Wave 18 içine çekilmez

Çelişki çözümü:

- C-MOB-001 önce artifact/release gerçeğini kurar; A-MOB-001 aynı artifact üzerinde kullanıcı davranış eşliğini kanıtlar.
- `versionName`, `versionCode`, package version, commit SHA ve deploy kimliği ayrı anlamlardır; biri diğerinin yerine geçmez.
- Asset dosya adlarının eşitliği tek başına doğru release/config/bundle kanıtı değildir.
- Debug build veya browser testi signed release WebView QA yerine geçmez.
- Google Services/Crashlytics dosyasının bulunması doğru Firebase project/environment veya collection kanıtı değildir.
- Manifestte izin görünmesi runtime iznin gerçekten gerektiğini veya Data Safety beyanını otomatik doğrulamaz.
- Android no-origin desteği CORS/auth/origin güvenliğini gevşeten genel bypass olamaz.
- Store beyanı C-COMP-001 kapanmadan varsayım veya yanlış bilgiyle tamamlanmaz.
- Wave 19 manuel/bütünleşik kapanışını Wave 18 önceden yapmaz.

## 3. Wave sonucu

Wave 18 sonunda:

- Web, Android ve backend release kimlikleri tek manifest/provenance zincirinde ilişkilendirilecek.
- Version bump build öncesi deterministik, doğrulanmış ve başarısız build'de güvenli olacak.
- Production frontend build, Capacitor sync ve Android bundle aynı immutable release girdisini kullanacak.
- AAB/APK içindeki bundle hash, config/environment ve release manifesti kaynak artifact ile eşleşecek.
- Eski/stale frontend asset'i yeni Android artifact'a giremeyecek.
- Debug endpoint, sourcemap, test flag veya localhost production artifact'ta bulunmayacak.
- Release signing secret repo/log/artifact'a sızmadan yetkili ortamda uygulanacak ve imza doğrulanacak.
- Manifest/merged manifest izin ve component export yüzeyi gerçek kullanımla karşılaştırılacak.
- Data Safety/content rating/store metadatası canonical ürün ve dependency davranışıyla tutarlı olacak.
- Web ve Android ana kullanıcı akışları aynı release/backend contract'ıyla eşdeğer çalışacak.
- Android back search/offer/chat/modal/drawer state'ini güvenli ve deterministik kapatacak.
- Background/foreground ve network değişimi stale UI, duplicate socket/message/match üretmeyecek.
- Push tap doğru, yetkili ve idempotent deep-link'e; invalid/stale hedef güvenli fallback'e gidecek.
- Kamera/medya izin grant/deny/permanent-deny ve dönüş akışları kontrollü olacak.
- Safe-area, 100dvh, keyboard resize, status/navigation bar ve WebView sürüm farkları cihazda kanıtlanacak.
- Internal test artifact, rollout, halt/rollback ve release notes prosedürü açık olacak.
- Wave 19 başlamayacak.

## 4. Doğrulanmış başlangıç fotoğrafı

### 4.1 Repo, sürüm ve build sırası

- Aktif Git root `C:/Users/Enis/Desktop/chatapp`, branch `main`, origin backend adlı GitHub repository'sine işaret ediyor.
- Root/backend package sürümü `1.0.0`, frontend `0.0.0`, Android `versionName 1.0.5`, `versionCode 7`.
- `mobile:release:android` sırası frontend build → Capacitor sync → asset verify → Android bump → `bundleRelease`.
- Android bump frontend build/sync sonrasında olduğu için tek release kaynağı ve bundle'a gömülü aynı version garanti değil.
- Bump script versionCode'u artırıyor ve versionName patch'ini otomatik artırabiliyor; build başarısızlığında dosya değişikliği kalabilir.

### 4.2 Asset ve Gradle

- Capacitor `webDir` `chatapp-frontend/dist`; app ID `com.talkx.app`.
- Gradle `compileSdk/targetSdk 36`, `minSdk 24`, Gradle wrapper `9.2.1`.
- Release build `minifyEnabled true` ve native symbol table üretimi ayarlı.
- Gradle preBuild asset kontrolü ve PowerShell verifier yalnız dist/bundled index içindeki JS/CSS asset adlarını karşılaştırıyor.
- Full asset tree hash, release/config manifest, removed stale files ve deterministic provenance doğrulanmıyor.
- Explicit release `signingConfig` görünmüyor; repository altında `.jks/.keystore` bulunmadı ve `key.properties` yok.

### 4.3 Firebase, manifest ve izinler

- Firebase BOM/Crashlytics dependency ve Gradle plugin classpath mevcut.
- `android/app/google-services.json` mevcut; içeriği plan aşamasında okunmadı veya paylaşılmadı.
- Main manifest `INTERNET` ve `POST_NOTIFICATIONS` izinlerini açıkça tanımlıyor; Camera plugin merged manifest ekleri ayrıca incelenmeli.
- `allowBackup=false`, cleartext kapalı, MainActivity exported launcher ve `singleTask`; deep-link intent filter görünmüyor.
- Runtime permission/camera/push bridge kodu mevcut; store beyanı ve merged manifest parity'si kanıtlanmadı.

### 4.4 WebView davranış yüzeyi

- CSS safe-area tokenları ve `100dvh` kullanıyor; gerçek cutout/gesture/keyboard cihaz sonucu yok.
- Native bridge platform algılama, StatusBar/Keyboard, back listener, push action ve camera/gallery fonksiyonları içeriyor.
- Ağ değişimi için Capacitor Network plugin/sözleşmesi ve explicit appStateChange listener repo taramasında doğrulanmadı.
- Browser `navigator.onLine` veya socket recovery tek başına Android lifecycle gerçeği değildir.
- Push action ve singleTask Activity birlikte idempotent navigation/cold-start/duplicate tap testi ister.

### 4.5 Çalışma ağacı ve canlı sınır

- Root geniş silinmiş/untracked kullanıcı değişiklikleri taşıyor; Wave 18 bunları temizlemez veya sahiplenmez.
- Plan aşamasında keystore, signing password, Firebase/Play Console, production backend veya gerçek kullanıcı/notification verisi açılmaz.
- Version bump, sync ve build çalışma ağacını/artifactları değiştirir; yalnız aktivasyon ve exact snapshot sonrası çalıştırılır.

## 5. Release kimliği ve sürüm otoritesi

### 5.1 Canonical release manifest

Tek release girdisi en az:

- `releaseVersion` — SemVer/ürün sürümü
- `androidVersionCode` — monoton artan Play kimliği
- `commitSha`, `buildId`, `builtAt`
- `environment`, `channel`, `backendBaseUrlId`
- `frontendBundleHash`, `androidArtifactHash`
- `applicationId`, `minSdk`, `targetSdk`
- `sourceMapId`, `nativeSymbolId`
- `signingCertificateSha256` — secret olmayan fingerprint

Kurallar:

1. Manifest source-controlled sürüm dosyası + CI build metadata'dan deterministik üretilir.
2. Frontend `__APP_VERSION__`, Android versionName/versionCode ve backend release lookup aynı girdiye bağlanır.
3. `0.0.0`, `unknown`, kirli/kimliği belirsiz source veya tekrar kullanılan versionCode production blocker'dır.
4. Marketing version değişmeden hotfix build olabilir; versionCode yine monoton ve benzersizdir.
5. Build sonrası kaynak dosyayı otomatik bump etmek yerine release intent önce doğrulanır; başarısız build yarım sürüm bırakmaz.
6. Tag/release notes artifact kimliğini tüketir; sonradan elle farklı isim verilmez.

### 5.2 Environment ve backend URL

- Local/staging/production config build-time allowlist ve manifest ID ile ayrılır.
- Production artifact localhost, private IP, debug host, staging URL veya runtime serbest override taşımaz.
- Base URL HTTPS ve expected host allowlist'tir; cleartext kapalı kalır.
- Native no-origin request yalnız app identity/auth/rate güvenliğiyle kabul edilir; browser CORS bypass'ı değildir.
- Backend compatibility minimum/maximum client contract'ı ve unsupported-upgrade sonucu tanımlıdır.
- Config değeri log/release notes'a secret olarak yazılmaz; endpoint kimliği kanıtlanabilir olur.

## 6. Deterministik frontend build ve Capacitor sync

### 6.1 Temiz build girdisi

- Lockfile ve pinned Node/npm/Java/Gradle/Android SDK versions doğrulanır.
- Frontend build output temiz, reproducible çalışma dizinine üretilir.
- Release environment ve manifest build başlamadan validate edilir.
- Lint/test/build/encoding/secret/version kapıları Wave 17 artifact'ı üzerinde geçmeden sync başlamaz.
- Public source map, debug flag, test endpoint ve development banner negatif taranır.

### 6.2 Sync ve stale-asset koruması

Sıra:

`release intent` → `quality gates` → `frontend artifact` → `manifest/hash` → `Capacitor sync` → `bundled-tree verify` → `Gradle release` → `signed artifact verify`

Verifier:

- tüm bundled web tree için path + byte hash manifesti
- dist'te olmayan stale Android asset'in kalmadığı kontrolü
- index'teki JS/CSS referansları ve dosya varlığı
- bundle içindeki release/environment/config değerleri
- Capacitor plugin/native dependency lock uyumu
- sync öncesi ve sonrası expected diff sınırı

Aynı source/lock/config girdisi aynı logical bundle manifestini üretmelidir. Timestamp gibi değişken alanlar hash kapsamından açıkça ayrılır.

## 7. Signing ve artifact güvenliği

### 7.1 Signing modeli

- Upload key/keystore ve password source repo, `.env`, docs, console, cache veya artifact'a girmez.
- Secret yalnız protected release environment/job'a minimum scope ile enjekte edilir.
- Untrusted PR veya local varsayılan build signing secret alamaz.
- Temp keystore exact temp path'te, restricted permission ile oluşturulur ve job sonunda güvenli temizlenir.
- Gradle config secret değerini command line/process list/log'a basmaz.
- Play App Signing ile local upload key rolleri ayrılır; owner ve recovery prosedürü kaydedilir.

### 7.2 Artifact doğrulama

Üretilen AAB/APK için:

- package/application ID, versionName/versionCode
- signing certificate fingerprint
- debuggable=false ve release build type
- manifest/permissions/exported components
- embedded bundle/release/config manifest
- min/target SDK ve ABI/resource yüzeyi
- checksum, size, source commit ve CI run
- source map/native symbol referansı

kanıtlanır. Unsigned, debug-signed, yanlış fingerprint'li veya provenance'sız artifact upload edilemez.

## 8. Manifest, izin ve store beyanı

### 8.1 Merged manifest otoritesi

Kontrol source manifestle sınırlı değildir; release variant merged manifest ve packaged artifact incelenir:

- tüm permissions ve maxSdk/uses-feature ilişkisi
- exported activity/service/receiver/provider ve intent filter
- FileProvider authority/path ve grant sınırı
- backup/cleartext/network security config
- notification, camera/photos/media izinleri ve OS version koşulları
- Firebase/Capacitor pluginlerinin eklediği component/metadata
- deep-link/app-link host/scheme doğrulaması

Beklenmeyen permission/component blocker olur. `tools:node` ile gizlemek yerine dependency kaynağı ve gerçek ihtiyaç belirlenir.

### 8.2 Runtime permission modeli

- İzin ilk açılışta topluca istenmez; kullanıcı ilgili özelliği başlatınca bağlamla istenir.
- `granted`, `denied`, `prompt`, `limited`, `permanently_denied`, `unavailable` durumları platform sürümüne göre normalize edilir.
- Reddetme core uygulamayı kilitlemez; push olmadan Sistem inbox, kamera olmadan uygun mevcut medya alternatifi veya açıklama korunur.
- Ayarlara yönlendirme yalnız kalıcı red sonrası kullanıcı aksiyonuyla yapılır.
- Permission sonucu background dönüşünde yeniden okunur; stale granted UI tutulmaz.
- Telemetry permission'ın hassas değerini veya seçilen medyayı taşımaz.

### 8.3 Data Safety ve content rating

Beyan matrisi kaynak olarak şunları karşılaştırır:

- uygulamanın topladığı/işlediği veri sınıfları
- backend/provider ve SDK dependency davranışı
- encryption, retention, deletion ve sharing amacı
- kullanıcı kontrolü ve hesap silme
- bildirim, medya, crash/analytics verisi
- target audience, anonim sohbet/moderasyon/CSAE süreçleri
- store listing, Privacy/Terms/Community/Child Safety metinleri

C-COMP-001 kapanmadan production store beyanı "tamam" sayılmaz. Hukuki/store policy kararı koddan tahmin edilmez; owner/reviewer/evidence ve tarih taşır.

## 9. C-MOB-001 — Release pipeline

### 9.1 Build variant ve channel

- Debug/local, staging/internal ve production/release application ID/config/channel ayrımı açık olur.
- Debug araçları production'da compile/package edilmez veya erişilemez.
- Internal artifact production signing/endpoint diye sunulmaz.
- Variant aynı manifestin environment/channel alanını taşır.
- Release build yalnız Wave 17 required checks artifact'ını tüketir.

### 9.2 Önerilen job akışı

`release intent` → `version uniqueness` → `Wave 17 quality artifact` → `frontend provenance` → `Capacitor sync` → `merged-manifest/asset audit` → `Gradle bundleRelease` → `sign/verify` → `device smoke` → `internal upload approval` → `rollout approval`

- Her job explicit timeout, immutable input ve artifact checksum taşır.
- Build bir kez yapılır; smoke/upload aynı AAB/APK'yi tüketir.
- Signing ve Play jobs protected environment ve manual approval kullanır.
- Upload/rollout otomatik devam zinciri değildir; her dış mutation ayrı sonuç/read-back taşır.
- Failure version/artifact durumunu `failed/rejected` olarak kaydeder; başka source aynı ID'yi reuse etmez.

### 9.3 Release notes ve change trace

Release notes:

- versionName/versionCode, commit/tag ve build run
- kullanıcıya dönük TR/EN değişiklikleri
- migration/backend compatibility gereksinimi
- bilinen risk/known issue ve desteklenen Android/WebView sınırı
- permission/Data Safety/listing değişimi
- rollout cohort/ülke/channel
- halt/rollback/forward-fix owner ve runbook linki

Secret, internal token, ham crash/event, kullanıcı verisi veya doğrulanmamış iddia içermez.

## 10. A-MOB-001 — Web/Android eşlik modeli

### 10.1 Parity sözleşmesi

Ana akış matrisi Web ve aynı Android release için:

- splash/bootstrap/config
- register/login/legal/reaccept
- Home/profile/settings/support
- Global/Country search, offer, accept/pass/cancel
- anonymous chat/report/block/friend transition
- friends/history/outbox/read/media
- locale/System inbox/push navigation
- account deletion ve recovery

"Eşdeğer" piksel aynı demek değildir; durum anlamı, backend sonucu, primary action, error/fallback, accessibility ve veri güvenliği aynı olur. Native affordance farklıysa neden ve expected result kaydedilir.

### 10.2 State ve lifecycle otoritesi

Client lifecycle en az:

- `foreground_active`
- `foreground_inactive`
- `background`
- `resuming_revalidate`
- `offline`
- `reconnecting`

Background'a geçiş socket'i koşulsuz yeni session gibi yeniden yaratmaz; pending search/offer/chat/outbox state stable kimlikle korunur. Resume önce local görüntüyü "kesin güncel" saymaz, server-authoritative recovery/revalidation tamamlanınca state'i açar. Duplicate appState event idempotent olur.

## 11. Android back davranışı

Back öncelik sırası görünür ve testlidir:

1. açık permission/settings helper, menu, popover
2. modal/dialog/drawer
3. image/media viewer
4. nested settings/detail
5. active chat için güvenli leave/confirm sözleşmesi
6. pending offer için canonical cancel/pass sonucu
7. active search için cancel sonucu
8. Home/root'ta double-back/OS exit politikası

- Back listener her render'da çoğalmaz; cleanup ve single consumer vardır.
- Bir back olayı iki mutation/navigation üretmez.
- Native back ile UI close/back button aynı command contract'ını kullanır.
- Unknown-result mesaj/send/match durumunda otomatik tekrar yapılmaz.
- Keyboard açıkken OS/Capacitor davranışı cihaz/version matrisinde doğrulanır.
- Browser history veya hard reload server state'i yetkisiz tahmin etmez.

## 12. Background/foreground ve network değişimi

### 12.1 Resume state machine

`background` → `resume detected` → `config/session check` → `socket recovery` → `active state reconcile` → `targeted refresh` → `ready`

Her adım abort/revision ve timeout taşır. Eski request geç gelen response ile yeni state'i ezmez. Auth revoked/legal reaccept/account state değişimi ilgili güvenli ekrana yönlenir.

### 12.2 Network state

- Browser/Capacitor network sinyali yalnız bağlantı ipucudur; backend reachability kanıtı değildir.
- Offline UI gerçek server sonucu uydurmaz; queued operation kapsamını açıklar.
- Wi-Fi/mobile/VPN/airplane/weak network transition reconnect backoff+jitter kullanır.
- Aynı transition duplicate socket, queue join, offer accept, message veya push registration üretmez.
- Captive portal/online-but-unreachable durumu ayrı error/retry state'idir.
- Reconnect exhaustion recovery ve Release Health sinyaline canonical kodla bağlanır; normal kısa kopma crash değildir.

## 13. Push deep-link ve cold-start

### 13.1 Canonical navigation envelope

Push action yalnız allowlist taşır:

- `schemaVersion`, `notificationId`, `type`
- stable entity/display reference
- optional route intent/CTA allowlist
- sent/expiry time ve idempotency key

Serbest URL, javascript scheme, token, mesaj metni veya hassas kullanıcı kimliği route değildir.

### 13.2 Durumlar

- foreground notification/tap
- background tap
- killed/cold-start tap
- duplicate tap/delivery
- expired/deleted/unauthorized entity
- logged-out, legal-reaccept veya account-restricted user
- stale release/unsupported CTA

Navigation bootstrap/auth/legal tamamlanmadan protected screen açmaz. Geçersiz hedef Home/System inbox gibi dürüst fallback verir; boş/crash ekranı üretmez. Aynı notification ID bir kez navigation command üretir.

## 14. Kamera, galeri ve medya

- Camera/gallery source kullanıcı aksiyonuyla seçilir; permission bağlamı açıktır.
- Android OS sürümüne göre photo picker/scoped access ve gereken minimum permission kullanılır.
- Denied/permanent-denied/unavailable/cancel sonuçları hata/crash değil ayrı UX state'tir.
- Activity recreation/process return sonrasında seçili media result bir kez tüketilir.
- MIME, boyut, decode/orientation, metadata ve upload güvenlik sınırı Web ile aynı contract'a gider.
- Medya geçici URI izinleri gereğinden uzun tutulmaz; app-private cache retention/cleanup tanımlıdır.
- Preview/send retry aynı media/message'i duplicate etmez.
- Anonim modda fotoğraf kapalı ürün kararı korunur.

## 15. Safe-area, viewport, keyboard ve system UI

### 15.1 Layout invariant'ları

- Top/bottom safe-area status/navigation/cutout/gesture modunda gerçek insetle uygulanır.
- `100dvh` destek/fallback davranışı WebView sürüm matrisinde test edilir.
- Keyboard `adjustResize` ve Capacitor native resize composer/CTA'yı görünür tutar.
- Double inset, status bar altına taşma ve bottom gesture collision olmaz.
- Orientation/config change aktif form/search/chat state'ini gereksiz sıfırlamaz.
- 320 px, kısa telefon, büyük yazı, display zoom ve landscape kritik CTA'yı kesmez.

### 15.2 System UI ve tema

- Splash-to-app geçişinde white flash/theme mismatch olmaz.
- Status/navigation bar icon contrast light/dark arka planla okunur.
- TalkX koyu/neon/glass teması native system surface ile kavga etmez.
- Reduced motion ve screen reader live-region kuralları Android WebView'de korunur.
- Keyboard aç/kapat, back ve focus return erişilebilirlik akışını bozmaz.

## 16. WebView ve backend compatibility

### 16.1 Sürüm matrisi

Her desteklenen Android release için:

- Android OS/API ve WebView major aralığı
- Capacitor core/plugin versions
- minimum/maximum backend contract version
- feature/capability handshake
- unsupported client davranışı
- mandatory/optional update policy

belgelenir. WebView update sistem/Play bileşeni olabilir; app release bunu tek başına kontrol ediyor gibi davranmaz.

### 16.2 Compatibility davranışı

- Backend additive schema ile desteklenen eski bundle'ı kırmaz; breaking değişim versioned contract ve rollout sırası ister.
- Client bilmediği optional field/event'i güvenli ignore eder; bilinmeyen kritik state'i başarı tahmin etmez.
- Backend minimum sürüm üstündeki client'i yanlış reddetmez; altındaki client için güvenli update ekranı/code verir.
- Feature flag/config release/environment/capability ile geri izlenebilir; stale cache yanlış özellik açmaz.
- Web ve Android aynı backend deployment'a bağlandığında contract sonucu karşılaştırılır.

## 17. Cihaz ve OS test matrisi

Minimum boyutlar:

| Boyut | Zorunlu örnek |
|---|---|
| API | minSdk 24, orta, güncel target/API 36 |
| Form factor | kısa telefon, standart telefon, tablet/landscape |
| Navigation | 3-button ve gesture |
| Display | default, büyük font/zoom, cutout/safe-area |
| WebView | desteklenen en eski, yaygın, güncel major |
| Network | Wi-Fi, mobile, switch, airplane, weak/captive |
| Lifecycle | foreground, background, process death, cold/warm start |
| Permission | grant, deny, permanent deny, OS settings dönüşü |
| Notification | foreground, background, killed, duplicate/expired tap |
| Build | debug yalnız teşhis; signed release acceptance |

Gerçek cihaz en az bir güncel ve mümkünse minimum/orta API sınıfında kullanılır; emulator donanım/push/process-death sınırı açıkça etiketlenir. Cihaz modeli/OS/WebView kaydedilir fakat kişisel device ID/log paylaşılmaz.

## 18. Rollout, halt ve rollback

### 18.1 Aşamalar

1. local unsigned/debug geliştirme kanıtı
2. CI signed internal artifact
3. internal tester/device smoke
4. closed/canary rollout — açık onay
5. health observation window
6. staged percentage increase — ayrı onay/policy
7. full rollout — ayrı sonuç/read-back

Wave 18 planı hiçbir aşamayı otomatik başlatmaz. Production Play upload/rollout external mutation'dır.

### 18.2 Go/no-go sinyalleri

- install/update/startup ve login/legal
- crash-free/ANR ve Release Health telemetry coverage
- auth/API/socket reachability
- search/offer/chat/message/push/media core smoke
- permission/deep-link regressions
- backend/version compatibility
- support/report trendi ve known issue

Telemetry yokluğu sağlıklı değildir. Low sample "izleniyor"; kritik core-flow veya signing/config mismatch no-go olur.

### 18.3 Rollback gerçeği

- Play versionCode geri kullanılamaz; rollback çoğunlukla eski koddan daha yüksek versionCode ile forward release'tir.
- Server compatibility ve feature/config kill switch hızlı containment sağlayabilir; kullanıcı cihazındaki installed binary anında geri alınamaz.
- Halt rollout, remove track/update, backend compatibility ve forward-fix adımları ayrılır.
- Exact last-known-good source/artifact/config/signing fingerprint ve migration uyumu önceden kaydedilir.
- Destructive DB rollback Wave 18 yetkisi değildir.

## 19. Sıralı uygulama paketleri

### Paket 0 — Aktivasyon ve snapshot

1. Wave 17 QA kapanışı ve açık Wave 18 başlangıç talimatını doğrula.
2. Repo/branch/remote/dirty, runtime/SDK/Gradle/JDK/WebView ve current versions snapshot al.
3. Android/root/frontend/backend ownership ve external console sahipliğini netleştir.
4. Signing/Play/Firebase/production işlemlerini kapalı tut.

### Paket 1 — Release manifest ve version akışı

1. Tek version/release intent kaynağını kur.
2. Web/Android/backend manifest adapter'larını bağla.
3. Unique/monotonic versionCode ve invalid version blocker ekle.
4. Bump/build failure davranışını atomik/geri alınabilir yap.
5. Tag/release notes/provenance contract'ını oluştur.

### Paket 2 — Build, sync ve artifact güveni

1. Pinned toolchain ve clean frontend release build kur.
2. Full-tree asset manifest/hash ve stale-file verifier ekle.
3. Capacitor sync expected-diff/plugin parity kapısını kur.
4. Merged manifest, debug endpoint, secret ve permission audit ekle.
5. Signing injection/cleanup ve certificate verify uygula.
6. Tek immutable AAB/APK artifact ve checksum üret.

### Paket 3 — C-MOB-001 release operasyonu

1. Debug/staging/internal/production variant/channel sözleşmesini uygula.
2. Data Safety/content rating/listing evidence matrisini tamamla.
3. Internal artifact install/update/uninstall smoke hazırla.
4. Play upload/rollout/halt/forward-fix runbook ve approval gates kur.
5. Release notes, known issue ve health observation planını tamamla.

### Paket 4 — A-MOB-001 davranış eşliği

1. Native lifecycle/network state machine'i bağla.
2. Android back öncelik/command sözleşmesini uygula.
3. Push cold/warm/foreground deep-link idempotency'sini kur.
4. Permission/media return ve safe cleanup davranışını uygula.
5. Safe-area/keyboard/system UI/WebView compatibility'yi düzelt ve test et.
6. Web/Android ana akış parity matrisini aynı backend release'inde çalıştır.

### Paket 5 — Kanıt ve kapanış

1. Wave 17 automated gates ve Android artifact audit'i çalıştır.
2. Signed release artifact üzerinde emulator + cihaz matrisini tamamla.
3. Internal track kullanılacaksa exact onay al, upload/read-back kanıtını kaydet.
4. Production rollout yapmadan staged rollout prosedürünü dry-run doğrula.
5. Canonical checkbox/evidence'i yalnız gerçek kanıtla senkronize et.
6. Kullanıcı manuel QA sonucunu al ve Wave 19'u başlatmadan dur.

## 20. Komut ve artifact sözleşmesi

Aktivasyonda exact tooling ile kesinleşecek mantıksal komutlar:

- `mobile:version:check`
- `mobile:build:web-release`
- `mobile:sync:android-clean`
- `mobile:verify:android-assets`
- `mobile:verify:manifest`
- `mobile:verify:config`
- `mobile:bundle:release`
- `mobile:verify:signature`
- `mobile:smoke:emulator`
- `mobile:smoke:device`
- `mobile:release:package`

Tek public `mobile:release:package` sıralı fail-closed zinciri çalıştırır; raw destructive bump veya upload varsayılan komuta gizlenmez. Her adım input/output manifest, exit code, duration ve artifact hash üretir. Local/CI aynı underlying komutları kullanır.

## 21. Dosya ve servis etki alanı

| Alan | Muhtemel değişiklik | Kanıt |
|---|---|---|
| Root package/scripts | Release orchestrator/version check | Dry-run ve failure rollback |
| Shared release manifest | Version/config/provenance | Web/Android/backend parity |
| Frontend Vite/config | Embedded release/environment | Bundle inspection |
| Capacitor config/plugins | WebDir/native behavior | Sync diff/plugin parity |
| Android Gradle | Version/signing/variant/artifact | Bundle/signature audit |
| Android manifest/resources | Permission/export/deep-link/system UI | Merged manifest |
| Native bridge/client state | Back/lifecycle/network/push/media | Device parity tests |
| CI workflows | Protected signed build/artifacts | Provenance/checksum |
| Docs/runbook | Store/rollout/rollback/release notes | Review/read-back |
| Play/Firebase settings | External mutation | Ayrı onay + exact read-back |

Keystore/password, `google-services.json` içeriği, signing temp files ve console credentials evidence dosyasına girmez. Kullanıcıya ait unrelated değişiklikler korunur.

## 22. Otomatik kanıt kapıları

### 22.1 Version, build ve asset

- VersionName/versionCode/release/commit/environment manifest parity geçer.
- `0.0.0/unknown`, reused/non-monotonic code ve dirty-unknown source fail eder.
- Full bundled tree dist manifestiyle eşleşir; stale/missing/extra asset fail eder.
- Production bundle debug/test/localhost/staging/public sourcemap taşımıyor.
- Same input logical bundle manifesti reproducible.

### 22.2 Gradle, manifest ve signing

- Pinned toolchain clean environment'ta build olur.
- Merged manifest permission/export/backup/cleartext/deep-link allowlist'e uyar.
- AAB package/version/build type/config doğru.
- Signature expected certificate fingerprint ile doğrulanır.
- Secret sentinel source/log/cache/artifact'a sızarsa fail eder.
- Source map/native symbol exact release'e bağlanır ve public değildir.

### 22.3 Client davranışı

- Back search/offer/chat/modal/root önceliğinde tek command üretir.
- Background/resume revalidation stale response'u reddeder.
- Network switch duplicate socket/queue/message/push registration üretmez.
- Push cold/warm/foreground, duplicate/expired/unauthorized route güvenlidir.
- Permission grant/deny/permanent-deny/cancel doğru fallback verir.
- Activity recreation media resultını bir kez tüketir.
- Compatibility handshake old/unsupported/current client fixture'larında doğrudur.

### 22.4 Pipeline ve rollout

- Wave 17 required checks olmadan signed build/upload job açılmaz.
- Internal/staging/prod artifact environment/signing karışamaz.
- Build edilen tek artifact smoke ve upload'da checksum ile aynıdır.
- Missing/cancelled/failed smoke rollout'u bloke eder.
- Rollout/halt/read-back komutları idempotent ve explicit approval'lıdır.
- Release note ve artifact provenance aynı release kaydına bağlıdır.

## 23. Manuel QA matrisi

### 23.1 Install, update ve identity

1. Clean install, first launch, splash ve config.
2. Previous supported version üstüne update; local/session/outbox güvenliği.
3. Uninstall/reinstall ve beklenen app-private data sonucu.
4. VersionName/versionCode/release/build/backend ID ekran/support/health parity.
5. AAB/APK signature, package, checksum ve source commit doğrulaması.
6. Stale asset fixture'ının build'i durdurması.
7. Debug/staging URL veya flag'in production artifact'ta bulunmaması.

### 23.2 System UI ve accessibility

8. Status/navigation bar, cutout, gesture ve 3-button navigation.
9. Keyboard resize; auth/support/chat composer/CTA görünürlüğü.
10. Portrait/landscape, 320 px/kısa telefon/tablet, büyük font ve display zoom.
11. TalkBack focus order, live region, dialog/drawer ve back sonucu.
12. Reduced motion ve theme/system contrast.

### 23.3 Lifecycle, back ve network

13. Home root back/exit politikası.
14. Search, offer, chat, modal, drawer, media viewer ve nested settings back sırası.
15. Background/foreground kısa ve uzun süre; session/legal/account değişimi.
16. Process death/cold start ve active state recovery.
17. Wi-Fi → mobile, airplane, weak/captive ve backend unreachable.
18. Reconnect'te duplicate queue/offer/socket/message/push registration olmaması.

### 23.4 Push, permission ve media

19. Notification permission grant/deny/permanent-deny/settings dönüşü.
20. Push foreground/background/killed tap ve doğru System/chat route.
21. Duplicate, expired, deleted, unauthorized ve logged-out deep-link fallback.
22. Camera/gallery grant/deny/permanent-deny/cancel/unavailable.
23. Photo picker/camera dönüşü, orientation/activity recreation ve tek result.
24. MIME/size/decode/orientation/upload/expire ve duplicate send koruması.
25. Anonim modda media kapalı; arkadaş modunda canonical yaşam döngüsü.

### 23.5 Release/rollout

26. Internal signed artifact install ve core smoke.
27. minSdk/orta/güncel API ile WebView matrix.
28. Release Health crash/symbol/release ilişkisinin controlled staging testi.
29. Store/Data Safety/content rating/permission evidence review.
30. Rollout dry-run, halt, last-known-good ve forward-fix rehearsal.
31. Release notes TR/EN, known issue, artifact ve backend compatibility doğruluğu.

Her sonuç date, commit, release/versionCode, artifact checksum, build variant, device model, Android API, WebView version, network, expected/actual, screenshot/video/log reference ve pass/fail taşır. Device ID, keystore, password, token, mesaj veya gerçek kullanıcı verisi evidence'e girmez.

## 24. Canonical kabul kriteri izleme

### 24.1 C-MOB-001

- [ ] Web/Android/backend release kimliği ilişkilendirilebilir.
- [ ] Eski frontend asset'i yeni APK/AAB içine girmiyor.
- [ ] Keystore/şifre repo/log'da değil.
- [ ] Debug endpoint production release'te yok.
- [ ] Permission beyanı gerçek kullanım kadar.
- [ ] Back/push/media/match smoke cihazda.
- [ ] Rollout ve rollback adımları belgeli.
- [ ] C-COMP-001 mağaza kararları tamamlanmadan yanlış beyanla yayın yok.

### 24.2 A-MOB-001

- [ ] Aynı release'te Web ve Android ana akışları eşdeğer.
- [ ] Back tuşu aktif sohbet/offer/search state'ini güvenli kapatıyor.
- [ ] Background dönüşü stale UI göstermiyor.
- [ ] İzin reddi kontrollü fallback veriyor.
- [ ] C-MOB-001 release/version sonucu kullanıcı yüzeyiyle eşleşiyor.

Kriterler plan hazırlandığı için işaretlenmez. Browser/debug/emulator sonucu tek başına release cihaz QA'i değildir; store upload da kullanıcı onayı ve canonical kanıt olmadan yapılmaz.

## 25. Giriş ve çıkış kapıları

### 25.1 Giriş

- [ ] Wave 17 `QA kapalı`.
- [ ] Kullanıcı açıkça Wave 18'i başlattı.
- [ ] Repo/ownership/branch/remote/dirty snapshot kayıtlı.
- [ ] Wave 17 required checks ve artifact handoff hazır.
- [ ] Toolchain/version/config/dependency inventory doğrulandı.
- [ ] Signing/Play/Firebase/production mutation kapalı.

### 25.2 Yerel tamam

- [ ] C-MOB-001 version/build/sync/signing/manifest zinciri kanıtlı.
- [ ] A-MOB-001 back/lifecycle/network/push/media parity kanıtlı.
- [ ] Full asset tree ve artifact provenance doğrulandı.
- [ ] Merged manifest/permission/Data Safety evidence matrisi hazır.
- [ ] Emulator/device otomatik ve manuel smoke evidence'i var.
- [ ] Secret/credential/PII hiçbir log/artifact/evidence'e girmedi.

### 25.3 QA kapalı

- [ ] Signed release artifact gerçek cihazda ana akış smoke geçti.
- [ ] Minimum/orta/güncel API ve WebView risk matrisi sonuçlandı.
- [ ] Internal track gerekiyorsa açık onay + upload/read-back kanıtlı; onay yoksa yapılmadı kaydı var.
- [ ] Rollout/halt/forward-fix runbook dry-run doğrulandı.
- [ ] Store beyanı C-COMP-001 ve gerçek dependency/permission davranışıyla uyumlu.
- [ ] Kullanıcı manuel QA sonucunu açıkça onayladı.
- [ ] Canonical Plan A/C, Master, Wave Map ve sonuç alanı senkronize edildi.
- [ ] Wave 19 başlatılmadan duruldu.

## 26. Kapsam dışı ve successor guard

Wave 18'e dahil değildir:

- Wave 19 `C-QA-001` bütünleşik admin/operasyon/release son QA
- Yeni Android-native ürün ekranı veya React uygulamasını native rewrite
- iOS release zinciri
- Otomatik full production rollout veya kullanıcı onaysız Play upload
- Yeni analytics/ads SDK veya gereksiz permission
- C-COMP-001 dışında yeni hukuk/store policy kararı
- Backend breaking schema veya DB migration'ı mobil workaround ile gizlemek
- Kullanıcıya zorunlu update politikası için yeni ürün kararı
- Keystore/secret içeriğini docs/artifact/evidence'e almak

Wave 18 kapanışında Wave 19 için kod, test, refactor veya uygulama hazırlığı yapılmaz. Ayrı Wave 19 planı hazırdır; yine de yalnız açık kullanıcı talimatı ve Wave 18 QA kapanışıyla aktive edilebilir.

## 27. Risk ve rollback

| Risk | Erken sinyal | Koruma | Rollback/forward-fix |
|---|---|---|---|
| Version drift | 0.0.0/1.0.5/1.0.0 | Tek manifest + gate | Build stop; version intent düzelt |
| Bump yarım kalır | Build fail, source changed | Prevalidated/atomic flow | Exact Wave 18 change restore |
| Stale bundle | Hash/tree farkı | Full-tree manifest | Sync clean/rebuild |
| Yanlış backend | Prod AAB staging host | Config allowlist/audit | Artifact reject/rebuild |
| Unsigned/yanlış key | Fingerprint mismatch | Protected signing + verify | Upload refuse/key incident |
| Secret sızar | Log/cache/artifact sentinel | Least privilege + scan | Job stop/rotation prosedürü |
| Fazla permission | Merged manifest sürprizi | Allowlist + usage map | Dependency/config fix |
| Store beyanı yanlış | Runtime/data matrisi farklı | C-COMP evidence gate | Publish halt/correct declaration |
| Back çift işlem | İki leave/cancel | Single command/idempotency | Listener off/state fix |
| Resume stale UI | Eski response ezer | Revision/revalidate | Safe loading/reconnect |
| Network duplicate | İki socket/queue/message | Stable IDs/backoff | Duplicate path disable |
| Push yanlış route | Stale/forged target | Allowlist/auth/expiry | Home/inbox fallback |
| Media URI sızıntısı | Cache/permission kalır | Scoped URI/retention | Cleanup/feature off |
| WebView regress | Min version crash | Version matrix/fallback | Min support/update plan |
| Rollback yanlış anlaşılır | Eski code reuse | Higher-code forward release | Halt + last-known-good rebuild |
| Dirty repo işi örter | Unrelated diff | Exact ownership snapshot | Yalnız Wave 18 farkını geri al |

Published versionCode geri alınamaz; rollback çoğu kez daha yüksek versionCode ile forward-fix'tir. Production rollout veya artifact removal ayrıca Play yetkisi ve açık kullanıcı onayı ister.

## 28. Canlı ve external mutation sınırı

Ayrı kullanıcı yetkisi isteyen işlemler:

- versionName/versionCode/tag/changelog/release kaydı mutation'ı
- dependency/Capacitor/Gradle/SDK/lockfile güncellemesi
- frontend build, Capacitor sync, Gradle bundle ve signed artifact üretimi
- keystore/upload key/signing password erişimi veya rotation
- Firebase/Google Services project/config değişikliği
- Play Console listing, Data Safety/content rating, tester/track/country ayarı
- APK/AAB upload, promote, staged/full rollout, halt veya deactivation
- production backend config/deploy/restart veya live smoke
- gerçek push/crash/media/user verisiyle test

Yetki öncesi exact repository/commit/environment, release/versionCode, artifact/source hash, signing fingerprint, Play application/track/country/percentage, tester impact, data/permission değişimi, cost, rollback/forward-fix ve stop condition raporlanır. Plan hazırlığı bunları yetkilendirmez.

## 29. Sonuç/evidence alanı

Wave 18 yürütüldüğünde en az:

- başlangıç/final Git ve exact changed files
- repo/ownership/toolchain/SDK/version inventory
- canonical release manifest ve Web/Android/backend parity
- version uniqueness/atomic failure sonucu
- Wave 17 required-check artifact handoff
- clean frontend build ve full-tree asset manifest
- Capacitor sync expected diff ve stale-asset negatif testi
- merged manifest permission/export/deep-link audit
- production bundle debug/URL/secret/source-map negatif taraması
- signed AAB/APK checksum, certificate fingerprint ve provenance
- Firebase/Crashlytics project/release/symbol bağlantısı; secret içermeyen kanıt
- Web/Android ana akış parity sonuçları
- back/lifecycle/network/reconnect/duplicate matrisi
- push cold/warm/foreground/deep-link matrisi
- media permission/result/cache/duplicate sonucu
- safe-area/keyboard/system UI/a11y/WebView screenshots
- install/update/process-death/min-mid-current API cihaz sonuçları
- Data Safety/content rating/listing evidence review
- internal upload/rollout yapılmadı veya exact onay/read-back kaydı
- halt/rollback/forward-fix dry-run ve last-known-good kayıt
- canonical checkbox ve kullanıcı manuel QA onayı
- Wave 19'un başlatılmadığı açık durma kaydı

Kriter yalnız kanıtla `[x]` olur. Build success, emulator screenshot, asset dosya adı eşitliği veya Play Console'da artifact görünmesi tek başına uçtan uca release/parity kanıtı değildir.

## 30. Durma kuralı

Wave 17 QA kapanışı ve kullanıcının açık Wave 18 başlatma talimatı birlikte gelene kadar:

- Wave 18 için kod, test, dependency, version, build, sync, signing, Firebase/Play setting, upload, rollout veya deploy değişikliği yapılmaz.
- Wave 18 `Aktif` işaretlenmez; belge yalnız `Hazır — aktif değil` kalır.
- Canonical `[ ]` maddeler kanıtsız kapatılmaz.
- Mevcut Android asset verifier, Crashlytics dependency veya unsigned bundle ihtimali release kanıtı sayılmaz.
- Keystore, password, Google Services içeriği veya gerçek kullanıcı verisi docs/log/evidence'e alınmaz.
- Wave 19 planı ayrı dosyada hazırdır; Wave 19 aktive edilmez veya uygulanmaz.
