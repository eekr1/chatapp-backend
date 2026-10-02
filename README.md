# TalkX Backend

TalkX'in Node.js/Express, WebSocket ve PostgreSQL backend servisidir. Kimlik doğrulama, profil, anonim eşleşme, arkadaş mesajları, medya, push, destek, moderasyon, yasal kayıtlar, davranış analitiği ve yönetim panelini içerir.

## Gereksinimler

- Node.js 20 veya üzeri
- npm
- PostgreSQL
- Push kullanılacaksa buyer-owned Firebase service account
- Support e-postası kullanılacaksa buyer-owned Brevo anahtarı

## Yerel kurulum

```powershell
Copy-Item .env.example .env
npm ci
npm start
```

Başlatmadan önce `.env` içindeki `DATABASE_URL`, CORS ve güçlü admin değerlerini yerel ortama göre düzenleyin. Gerçek secretları repository'ye eklemeyin.

## Sağlık kontrolleri

| Yol | Amaç |
|---|---|
| `/health` | Uyumluluk sağlık özeti |
| `/health/live` | Veritabanından bağımsız servis canlılığı |
| `/health/ready` | Veritabanı, schema ve migration hazırlığı |

Production deploy sonrasında önce `live`, ardından `ready` kontrol edilir.

Satış öncesi test ve kabul kanıtları kaynak arşivinden ayrı olarak due-diligence dosyalarında tutulur.

## Veritabanı ve migration

```powershell
npm run migration:status
npm run migration:run
```

Migration veya `DATABASE_URL` değişikliği öncesinde güncel şifreli backup, restore provası ve kaynak/hedef kritik tablo sayımı gerekir. TalkX için PostgreSQL `public` schema kullanılmalıdır. Production değişiklikleri bakım penceresi ve açık onay olmadan yapılmaz.

## Ortam yapılandırması

Operatör tarafından ayarlanabilen değişkenler ve güvenli örnekler `.env.example` dosyasındadır. IP ülke veritabanının `ILA_*` değişkenleri uygulama tarafından güvenli biçimde yönetilir ve normal kurulumda ayrıca ayarlanmaz. Production için başlıca zorunlu alanlar:

- `DATABASE_URL`
- `NODE_ENV=production` ve `APP_ENV=production`
- `CORS_ALLOWED_ORIGINS`
- `ADMIN_PANEL_ENABLED`, `ADMIN_USER`, güçlü `ADMIN_PASSWORD`
- Firebase credential kaynaklarından yalnız biri
- Support kullanılacaksa Brevo ve support adresleri
- `ERASURE_HMAC_KEY` ve `LOG_PSEUDONYM_SALT`

Firebase için Render'da JSON veya Base64 ortam değişkeni tercih edilir. `firebase-service-account.json` yalnız yerel geliştirme fallback'idir, Git tarafından yok sayılır ve satış paketine girmez.

## Önemli yollar

- `index.js`: HTTP/WebSocket runtime ve ana ürün akışları
- `db.js`: PostgreSQL bağlantısı ve schema bootstrap
- `routes/`: REST modülleri
- `utils/`: güvenlik, push, lifecycle, analitik ve operasyon servisleri
- `migrations/`: migration runner ve migration dosyaları
- `admin.html`, `admin.js`: yönetim paneli
- `public/`: yönetim paneli ve statik varlıklar

## Deploy

Canonical release branch `sale-release` dalıdır. Render web service için build adımı `npm ci`, start komutu `npm start` olarak yapılandırılır. Sağlayıcı ortam değişkenleri repository dışında tutulur. Deploy sonrasında `/health/live` ve ardından `/health/ready` kontrol edilir.

## Güvenlik ve devir

- Şahsi Render, Neon ve Firebase hesap parolaları devredilmez.
- Alıcı kendi servis hesaplarını kurar; proje transferi veya doğrulanmış migration/cutover uygulanır.
- `.env`, Firebase service-account, database dump, kullanıcı export'u, mesaj içeriği ve admin parolası kaynak paketine eklenmez.
- Kapanışta buyer-owned secretlar oluşturulur ve satıcının eski erişimleri kaldırılır.

Doğrudan bağımlılık lisans özeti için `THIRD_PARTY_NOTICES.md` dosyasına bakın.
Kaynak arşivinin kapsamı için `SOURCE_PACKAGE_NOTE.md` dosyasına bakın.
