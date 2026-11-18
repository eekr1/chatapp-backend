# TalkX Backend Değişiklik Kaydı — 2026-11

Bu dal (`feat/eslesme-hakki-reklam`) ticari kural değişikliklerini içerir: günlük eşleşme hakkı (kota), AdMob ödüllü reklam SSV ile hak kazanma ve kayıt yaş doğrulama geçiş kapısı. Bu dal **kod ve veritabanı** değişikliklerini taşır; dokümantasyon eşlikçisi olarak `README.md`, `docs/MONETIZATION.md` ve bu dosya güncellenmiştir.

Bu kayıt, dalın içeriğini belgeler; üretim değişikliği, migration çalıştırma veya dağıtım yetkisi vermez.

## Yeni yetenekler

### Günlük eşleşme hakkı (kota)

- `utils/matchQuota.js` yeni modül olarak eklendi: günlük hak, hoş geldin hakkı ve reklam bonusu birlikte yönetilir.
- Hak tüketimi yalnız **başarıyla finalize edilen eşleşmede** gerçekleşir. Başarısız arama, iptal, requeue, arkadaş mesajı ve DM hiçbir hak tüketmez.
- Tüketim sırası **welcome → daily → bonus** şeklindedir ve her bucket kendi atomik `UPDATE ... WHERE` koşuluyla korunur; eşzamanlı tüketiciler aynı birimi iki kez alamaz.
- Gün anahtarı `Europe/Istanbul` saat dilimine göre üretilir; gün değişiminde `daily_used` ve `ads_today` lazy reset ile sıfırlanır, `welcome_remaining` ve `bonus_balance` korunur.
- `MATCH_QUOTA_ENABLED=false` ile tüm kontroller kapanır ve davranış özellik öncesi hâle döner.
- Yeni migration `011` (`match_quota_and_ad_rewards`) `match_quota`, `ad_reward_sessions` ve `ad_reward_ledger` tablolarını ekler.

### AdMob ödüllü reklam SSV

- `utils/adRewards.js` yeni modül olarak eklendi: ECDSA/SHA-256 imza doğrulaması, Google doğrulama anahtarı önbelleği, nonce yönetimi ve ledger (idempotenslik) işlemleri.
- `routes/ads.js` yeni yönlendirici olarak eklendi ve `/api` altına mount edildi:
  - `GET /api/match-quota` — güncel kota nesnesi.
  - `POST /api/ads/reward-session` — 30 dakika TTL'li nonce üretimi.
  - `GET /api/ads/admob-ssv` — Google'ın çağırdığı, imza doğrulamalı SSV ucu.
- Kesin geçersiz sonuçlar `200` döner (AdMob tekrar denemez, hak verilmez); geçici hatalar `503` döner (AdMob tekrar dener).
- Ödül kredisi tek bir transaction içinde yazılır: `ad_reward_ledger` (UNIQUE `transaction_id`), `match_quota.bonus_balance` ve `ad_reward_sessions.used_at` ya hep ya hiç güncellenir.
- `AD_DAILY_MAX` tavanı hem nonce isteğinde hem kredilendirmede ayrıca korunur.
- `ADMOB_SSV_ENABLED=false` iken uç çalışır ancak hiçbir hak yazmaz.

### Kayıt yaş doğrulama (geçiş dönemi)

- `POST /auth/register` artık 18+ onayını destekler.
- `REQUIRE_AGE_CONFIRMATION=true` iken `ageConfirmed=true` zorunludur.
- `REQUIRE_AGE_CONFIRMATION=false` (geçiş, varsayılan) iken alanı hiç göndermeyen eski istemciler kaydolabilir; açıkça gönderilen her `true` dışı değer `AGE_CONFIRMATION_REQUIRED` ile reddedilir.
- `i18n/messages.en.js` ve `i18n/messages.tr.js` içine `AGE_CONFIRMATION_REQUIRED` mesajı eklendi.

## WebSocket olayları

- `quota_update`: eşleşme finalize edildikten sonra taraf başına bir hak düşülür ve istemciye güncel kota nesnesi gönderilir. Tüketim hatası eşleşmeyi bozmaz.
- `search_error` / `MATCH_QUOTA_EXHAUSTED`: kuyruğa girişte hak kalmadıysa gönderilir. `retryable: false` ve güncel `quota` gövdesini taşır.

## Yapılandırma

`.env.example` içine yeni anahtarlar eklendi:

| Anahtar | Varsayılan |
|---|---|
| `MATCH_QUOTA_ENABLED` | `true` |
| `MATCH_WELCOME_FREE` | `0` |
| `MATCH_DAILY_FREE` | `30` |
| `AD_REWARD_MATCHES` | `3` |
| `AD_DAILY_MAX` | `5` |
| `ADMOB_SSV_ENABLED` | `false` |
| `ADMOB_REWARDED_AD_UNITS` | boş |
| `ADMOB_SSV_KEY_CACHE_TTL_MS` | `86400000` |
| `ADMOB_SSV_VERIFIER_KEYS_URL` | Google resmi endpoint |
| `REQUIRE_AGE_CONFIRMATION` | `false` |

## Testler

Yeni ve güncellenen test dosyaları (deterministik, canlı servis bağlantısı yok):

- `test/matchQuota.test.js` — gün anahtarı/reset, quota sözleşmesi, lazy reset, tüketim sırası, günlük kap, sıfır hak ve `MATCH_QUOTA_ENABLED=false` davranışı.
- `test/adRewardsSsv.test.js` — imza doğrulama, anahtar önbelleği, geçerli/bozuk/tekrar eden geri çağırma, günlük kap, nonce kapasitesi, 200/503 eşlemesi.
- `test/ageConfirmation.test.js` — strict mod, geçiş modu ve yasal kabul etkileşimi.

## Dokümantasyon

- `README.md` yeniden düzenlendi: Render dönemi sona erdi; mimari (Windows PC + Cloudflare Tunnel + Neon + Render static web), yerel geliştirme, test/kapılar, `sale-release` → CI → `TalkXDeploy` poller → geçiş deploy akışı, ortam değişkeni tabloları ve API uçları özeti eklendi. Render talimatı "Eski/yedek barındırma (Render)" başlığı altında küçültüldü.
- `docs/MONETIZATION.md` eklendi: kota kuralları, akış diyagramı, SSV güvenlik modeli ve HTTP durum eşlemesi, AdMob panel ayarları, işletim notları.
- Bu değişiklik kaydı eklendi.

## Bilinen sınırlar ve açık kalanlar

- Yeni test dosyaları `scripts/quality-gate.mjs` içindeki `coreTests`/`criticalTests` manifestlerine **eklenmemiştir** (manifest her `.test.js` dosyasını içermek zorundadır). Bu dosya bu dalın sahiplik alanı dışındadır; `npm run quality:core` bu haliyle "backend core test manifest must include every .test.js file" hatasıyla kapanır.
- `MATCH_QUOTA_EXHAUSTED` ve `AD_LIMIT_REACHED` için `i18n/messages.*.js` içinde kullanıcı metni yoktur; frontend bu kodları kendi sözlüğüyle karşılamalıdır.
- `ADMOB_SSV_ENABLED` ve `REQUIRE_AGE_CONFIRMATION` varsayılan olarak kapalıdır; üretimde açılmaları operatör kararıdır.
- `MATCH_WELCOME_FREE` varsayılanı `0`'dır; hoş geldin hakkı açılırsa yalnız ilk kota satırı okunduğunda bir kez verilir.
