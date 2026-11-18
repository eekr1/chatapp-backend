# TalkX Backend

TalkX'in Node.js/Express, WebSocket ve PostgreSQL backend servisidir. Kimlik doğrulama, profil, anonim eşleşme, arkadaş mesajları, medya, push, destek, moderasyon, yasal kayıtlar, davranış analitiği, yönetim paneli ve **eşleşme hakkı (kota) + ödüllü reklam** katmanını içerir.

Backend artık Render'da değil, **Enis'in Windows PC'sinde** çalışır; dışarıya **Cloudflare Tunnel** ile `https://api.talkx.chat` üzerinden açılır. Veritabanı **Neon Postgres**, web istemcisi ise **Render static site** olarak sunulur.

## Genel bakış

- API ve WebSocket tek bir Node.js sürecinde aynı origin üzerinden çalışır.
- Gerçek zamanlı eşleşme tek instance üzerinde yürür (`REALTIME_TOPOLOGY=single`); iki üretim eşleştirme instance'ı aynı anda çalıştırılmaz.
- Eşleşme hakkı kotası (`match_quota`) ve ödüllü reklam ödülleri (`ad_reward_sessions`, `ad_reward_ledger`) Neon'da tutulur.
- Yönetim paneli backend ile aynı origin'den `/admin` altında sunulur; frontend statik dosyaları backend'e paketlenmez.

## Mimari

```text
                    ┌──────────────────────────────┐
                    │  Kullanıcı / Web (Render      │
                    │  static site: talkx.chat)     │
                    └───────────────┬──────────────┘
                                    │ HTTPS + WSS
                    ┌───────────────▼──────────────┐
                    │  Cloudflare Tunnel            │
                    │  (named tunnel, api.talkx.chat)│
                    └───────────────┬──────────────┘
                                    │ loopback :3000
                    ┌───────────────▼──────────────┐
                    │  Windows PC (Enis)            │
                    │  TalkXBackend (WinSW service) │
                    │  node index.js  127.0.0.1     │
                    └───────────────┬──────────────┘
                                    │ TLS (Neon)
                    ┌───────────────▼──────────────┐
                    │  Neon Postgres (public schema)│
                    └──────────────────────────────┘
```

Önemli davranışlar:

- Servis yalnızca `127.0.0.1:3000` üzerinde dinler; `HOST` boş bırakılmaz.
- `TRUST_CLOUDFLARE_TUNNEL=true` yalnızca peer `127.0.0.1`/`::1` ise `cf-connecting-ip` header'ına güvenir.
- Web istemcisi Render'da statik olarak durur; backend `../chatapp-frontend/dist` varsa onu da statik olarak sunar, yoksa `/` altında bilgilendirme metni döner.
- DB bağlantısı Neon `DATABASE_URL` üzerinden kurulur; migration'lar servis başlangıcında `ensureTables()` ile uygulanır.

Detaylı PC barındırma, tunnel ve deploy poller akışı için `ops/windows/README.md` dosyasına bakın.

## Gereksinimler

- Node.js 20 veya üzeri (CI 24.11.1 kullanır)
- npm
- PostgreSQL (Neon; `public` schema)
- Push kullanılacaksa buyer-owned Firebase service account
- Support e-postası kullanılacaksa buyer-owned Brevo anahtarı

## Yerel geliştirme

```powershell
Copy-Item .env.example .env
npm ci
npm run migration:status
npm start
```

`.env` içindeki `DATABASE_URL`, `CORS_ALLOWED_ORIGINS` ve güçlü admin değerlerini yerel ortama göre düzenleyin. Gerçek secret'ları repository'ye eklemeyin. Yerelde `.env` kullanılır; production'da secret'lar `C:\TalkX\secrets\backend.env` altında, Git dışında tutulur.

Kota ve ödüllü reklam özelliklerini yerelde denemek için `.env` içinde en az şunları açın:

```text
MATCH_QUOTA_ENABLED=true
MATCH_DAILY_FREE=30
MATCH_WELCOME_FREE=0
AD_REWARD_MATCHES=3
AD_DAILY_MAX=5
ADMOB_SSV_ENABLED=false
```

## Test ve kalite kapıları

```powershell
npm test          # node --test test/*.test.js
npm run quality:all
```

`quality:all` sırasıyla `quality:policy`, `quality:syntax`, `quality:core`, `quality:critical` ve `quality:audit` adımlarını çalıştırır. Core/critical suite'ler canlı PostgreSQL, Firebase veya Brevo'ya bağlanmaz; `DATABASE_URL`, `FIREBASE_SERVICE_ACCOUNT*`, `GOOGLE_APPLICATION_CREDENTIALS` ve `BREVO_API_KEY` ortam değişkenleri tanımlıyken quality gate bilinçli olarak başarısız olur.

Yeni test dosyaları `scripts/quality-gate.mjs` içindeki `coreTests` ve `criticalTests` manifestlerine de eklenmelidir; manifest her `.test.js` dosyasını içermek zorundadır.

## Deploy akışı

Canonical release branch `sale-release` dalıdır. Deploy tamamen otomatik değildir; şu sıra izlenir:

1. Değişiklikler `sale-release` dalına push edilir.
2. GitHub Actions `Backend quality` (`quality.yml`) işi `sale-release` push'unda tetiklenir; `npm run quality:all` çalışır.
3. PC'deki `TalkXDeploy` poller'ı (LocalService) her iki dakikada bir `sale-release` head'ini ve o **tam SHA** için **başarılı** CI koşusunu kontrol eder.
4. CI başarılıysa poller: release'i klonlar, kilitli production dependency'leri kurar, migration uyumluluğunu migration çalıştırmadan doğrular, servisi durdurup release pointer'ını değiştirir, servisi başlatır ve yerel readiness ile `https://api.talkx.chat` üzerinde HTTP/CORS/WS smoke testi yapar.
5. Smoke başarısızsa poller önceki release'e geri döner; **veritabanı şeması geri alınmaz**. Başarısız aday release'ler incelenmek üzere saklanır.

Aynı anda eski Render backend'i eşleştirme için çalıştırmayın. Poller mevcut sağlıklı backend olmadan ilk geçişi yapamaz; ilk geçiş operatör tarafından `ops/windows/Deploy.ps1` ile yapılır.

Deploy sonrası sıralı kontrol: `/health/live`, ardından `/health/ready` (migration head eşleşmeli), sonra CORS ve WebSocket handshake.

## Sağlık kontrolleri

| Yol | Amaç |
|---|---|
| `/health` | Uyumluluk sağlık özeti |
| `/health/live` | Veritabanından bağımsız servis canlılığı |
| `/health/ready` | Veritabanı, schema ve migration hazırlığı |

Satış öncesi test ve kabul kanıtları kaynak arşivinden ayrı olarak due-diligence dosyalarında tutulur.

## Ortam değişkenleri

Operatör tarafından ayarlanabilen değişkenler ve güvenli örnekler `.env.example` dosyasındadır. Değerler bu dokümana yazılmaz. IP ülke veritabanının `ILA_*` değişkenleri uygulama tarafından güvenli biçimde yönetilir ve normal kurulumda ayrıca ayarlanmaz.

### Çekirdek

| Değişken | Amaç | Zorunlu |
|---|---|---|
| `DATABASE_URL` | Neon Postgres bağlantı dizesi (`public` schema) | evet |
| `NODE_ENV` / `APP_ENV` | Ortam etiketi; production'da `production` | evet |
| `HOST` | Dinlenecek adres; production'da `127.0.0.1` | evet |
| `PORT` | Dinlenecek port (varsayılan `3000`) | evet |
| `TRUST_CLOUDFLARE_TUNNEL` | Loopback peer ise tunnel header'ına güven | production'da `true` |
| `TRUST_PROXY_HOPS` | Trusted proxy zincir uzunluğu | hayır |
| `CORS_ALLOWED_ORIGINS` | İzinli origin listesi | evet |
| `ADMIN_PANEL_ENABLED`, `ADMIN_USER`, `ADMIN_PASSWORD` | Yönetim paneli erişimi | evet |
| `FIREBASE_SERVICE_ACCOUNT_PATH` / `_JSON` / `_BASE64` | Push için **tek** credential kaynağı | push için |
| `BREVO_API_KEY`, `SUPPORT_*` | Support e-postası | destek için |
| `ERASURE_HMAC_KEY`, `LOG_PSEUDONYM_SALT` | Kişisel veri koruma anahtarları | evet |
| `DB_POOL_MAX`, `DB_*_TIMEOUT_MS` | Neon bağlantı havuzu ve zaman aşımları | hayır |

### Eşleşme hakkı (kota)

| Değişken | Varsayılan | Amaç |
|---|---|---|
| `MATCH_QUOTA_ENABLED` | `true` | `false` ise tüm kota kontrolleri kapanır, davranış eskisi gibi olur |
| `MATCH_WELCOME_FREE` | `0` | İlk kota satırı okunduğunda verilen tek seferlik hoş geldin hakkı (0 = kapalı) |
| `MATCH_DAILY_FREE` | `30` | Günlük ücretsiz hak; `Europe/Istanbul` gece yarısında sıfırlanır, üst üste binmez |
| `AD_REWARD_MATCHES` | `3` | Doğrulanmış her ödüllü video için eklenen bonus hak (birikir) |
| `AD_DAILY_MAX` | `5` | Kullanıcı başına günlük ödüllü reklam ödülü üst sınırı |

### AdMob SSV (ödüllü reklam doğrulama)

| Değişken | Varsayılan | Amaç |
|---|---|---|
| `ADMOB_SSV_ENABLED` | `false` | `false` ise SSV hiçbir hak yazmaz; kesin geçersiz sonuçlar 200 döner, geçici hata 503 |
| `ADMOB_REWARDED_AD_UNITS` | boş | Virgülle ayrılmış ödüllü ad unit id'leri; boşsa herhangi bir `ad_unit` kabul edilir |
| `ADMOB_SSV_KEY_CACHE_TTL_MS` | `86400000` | Google doğrulama anahtarı önbellek ömrü |
| `ADMOB_SSV_VERIFIER_KEYS_URL` | Google resmi endpoint'i | Doğrulama anahtarı kaynağı |

### Kayıt yaş doğrulama (geçiş dönemi)

| Değişken | Varsayılan | Amaç |
|---|---|---|
| `REQUIRE_AGE_CONFIRMATION` | `false` | `true` ise `ageConfirmed=true` zorunludur. `false` (geçiş) iken alanı hiç göndermeyen eski istemciler kaydolabilir; açıkça gönderilen her `true` dışı değer `AGE_CONFIRMATION_REQUIRED` ile reddedilir |

Ayrıntılı kurallar, akış ve işletim notları için `docs/MONETIZATION.md` dosyasına bakın.

## API uçları özeti

### Sağlık

| Yöntem | Yol | Auth | Amaç |
|---|---|---|---|
| GET | `/health` | yok | Sağlık özeti |
| GET | `/health/live` | yok | Servis canlılığı |
| GET | `/health/ready` | yok | DB/schema/migration hazırlığı |

### Kimlik ve profil

| Yöntem | Yol | Auth | Amaç |
|---|---|---|---|
| POST | `/auth/register` | yok | Kayıt (18+ onayı, yasal kabul) |
| POST | `/auth/login` | yok | Oturum açma |
| POST | `/auth/logout`, `/auth/logout-all` | token | Oturum kapatma |
| GET | `/api/me`, `/api/me/summary`, `/api/me/legal-status`, `/api/me/match-country` | token | Profil özetleri |
| POST | `/api/me/legal-accept` | token | Yasal kabul kaydı |
| PUT | `/api/me/profile`, `/api/me/password` | token | Profil/şifre güncelleme |
| POST | `/api/me/delete-request` | token | Hesap silme talebi |

### Eşleşme hakkı ve ödüllü reklam

| Yöntem | Yol | Auth | Amaç |
|---|---|---|---|
| GET | `/api/match-quota` | token | Güncel kota nesnesini döner |
| POST | `/api/ads/reward-session` | token | Ödüllü reklam için nonce üretir (30 dk TTL) |
| GET | `/api/ads/admob-ssv` | yok (Google çağırır) | AdMob SSV doğrulama ve ödül yazma |

### Arkadaşlık, medya, push, destek

| Yöntem | Yol | Auth | Amaç |
|---|---|---|---|
| GET/POST | `/friends/list`, `/friends/request`, `/friends/accept`, `/friends/reject`, `/friends/block`, `/friends/unblock` | token | Arkadaşlık ve engelleme |
| GET/POST | `/friends/conversations`, `/friends/history/:friendId`, `/friends/read` | token | Mesajlaşma |
| POST | `/api/push/register`, `/api/push/unregister` | token | Push token kaydı |
| POST | `/support/report` | opsiyonel | Destek/şikâyet bildirimi |
| — | `/admin/*` | admin | Yönetim paneli API'leri |

### WebSocket olayları

| Olay | Yön | Açıklama |
|---|---|---|
| `hello` / `welcome` | sunucu → istemci | Bağlantı ve oturum açılışı, `capabilities` listesi |
| `matched` | sunucu → istemci | Eşleşme tamamlandı |
| `quota_update` | sunucu → istemci | Eşleşme sonrası tüketilen hak ve güncel kota |
| `search_error` | sunucu → istemci | Arama hatası; `errorCode: MATCH_QUOTA_EXHAUSTED` ile hak kalmadığını bildirir (`retryable: false`, `quota` gövdesiyle) |
| `match_offer`, `match_finalizing`, `match_offer_closed` | sunucu → istemci | Eşleşme teklif durumu makinesi |
| `message`, `direct_message`, `image_sent` | çift yönlü | Mesaj ve medya |
| `presence_update` | sunucu → istemci | Çevrimiçi durumu |

WebSocket adresi `wss://api.talkx.chat`. İzinli origin listesi `talkx.chat`, `www.talkx.chat`, localhost ve Capacitor originlerini içerir.

## Veritabanı ve migration

```powershell
npm run migration:status
npm run migration:run
```

Migration veya `DATABASE_URL` değişikliği öncesinde güncel şifreli backup, restore provası ve kaynak/hedef kritik tablo sayımı gerekir. TalkX için PostgreSQL `public` schema kullanılmalıdır. Production değişiklikleri bakım penceresi ve açık onay olmadan yapılmaz.

Kota ve ödül tabloları `011` migration'ı ile gelir:

- `match_quota(user_id, welcome_remaining, day_key, daily_used, bonus_balance, ads_today, updated_at)`
- `ad_reward_sessions(nonce, user_id, created_at, expires_at, used_at)`
- `ad_reward_ledger(id, user_id, transaction_id UNIQUE, ad_unit, reward_amount, nonce, created_at)`

## Önemli yollar

- `index.js`: HTTP/WebSocket runtime ve ana ürün akışları
- `db.js`: PostgreSQL bağlantısı, migration listesi ve schema bootstrap
- `routes/`: REST modülleri (`ads.js` kota + AdMob uçları)
- `utils/matchQuota.js`: Kota hesabı, tüketim ve ödül kredilendirme
- `utils/adRewards.js`: SSV imza doğrulama, nonce ve ledger işlemleri
- `utils/`: güvenlik, push, lifecycle, analitik ve operasyon servisleri
- `migrations/`: migration runner ve migration dosyaları
- `ops/windows/`: PC barındırma, tunnel, deploy poller ve smoke betikleri
- `admin.html`, `admin.js`: yönetim paneli
- `public/`: yönetim paneli ve statik varlıklar

## Güvenlik ve devir

- Şahsi Render, Neon ve Firebase hesap parolaları devredilmez.
- Alıcı kendi servis hesaplarını kurar; proje transferi veya doğrulanmış migration/cutover uygulanır.
- `.env`, Firebase service-account, database dump, kullanıcı export'u, mesaj içeriği ve admin parolası kaynak paketine eklenmez.
- Kapanışta buyer-owned secretlar oluşturulur ve satıcının eski erişimleri kaldırılır.
- Production secret'lar PC'de `C:\TalkX\secrets` altında, Git dışında ve NTFS ACL ile korunur.
- `firebase-service-account.json` yalnız yerel geliştirme fallback'idir, Git tarafından yok sayılır ve satış paketine girmez.

Doğrudan bağımlılık lisans özeti için `THIRD_PARTY_NOTICES.md` dosyasına bakın.
Kaynak arşivinin kapsamı için `SOURCE_PACKAGE_NOTE.md` dosyasına bakın.

## Eski/yedek barındırma (Render)

Render dönemi sona ermiştir; backend üretimde Render'da çalışmaz. Aşağıdaki bilgiler yalnızca geçmiş referans ve olası geri dönüş prosedürü için saklanır, aktif yapılandırma değildir.

- Render web service: build adımı `npm ci`, start komutu `npm start`.
- Ortam değişkenleri provider panelinde tutulurdu; Firebase credential JSON veya Base64 olarak verilirdi.
- Sağlık kontrolü sırası aynıydı: `/health/live`, ardından `/health/ready`.
- Render'ın kendi instance/servis komutları kullanılmaz; bu backend artık `ops/windows` betikleriyle Windows servisi olarak yönetilir.
- Render'a geri dönülürse: eski web service ayarları geri alınır, DNS yeniden Render origin'ine yönlendirilir, PC'deki `TalkXBackend` servisi durdurulur ve iki eşleştirme instance'ının aynı anda çalışmadığı doğrulanır.
