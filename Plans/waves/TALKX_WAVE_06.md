# TalkX Wave 06 Plan — Veri Sahipliği, Canonical Ülke, Privacy ve Hesap Silme

> Bu belge yalnız Wave 06 için hazırlanmış uygulama planıdır.
> Canonical ayrıntı Plan B ve Plan C stable ID maddelerindedir; burada Wave 07 search lifecycle veya Wave 08 Global/Country queue ve selector uygulaması üretilmez.
> Plan hazırdır. Wave 06 aktif değildir, Wave 01–05 kapanmamıştır ve uygulama başlamamıştır.

## 1. Durum ve yürütme sınırı

- **Wave:** 06
- **Wave adı:** Veri sahipliği, canonical ülke, privacy ve hesap silme
- **Plan katılımı:** Plan B + Plan C
- **Plan durumu:** Hazır
- **Wave durumu:** Bekliyor
- **Uygulama durumu:** Başlamadı
- **Uygulama yetkisi:** Verilmedi
- **Giriş kapısı:** Wave 05 **AUTO-VERIFIED / COMMITTED** ve kullanıcıdan açık “Wave 06'yı başlat” talimatı
- **Mevcut blokaj:** Wave 05 henüz committed değil; Wave 06 uygulanamaz
- **Önceki wave:** Wave 05 — planı hazır, aktif değil
- **Sonraki wave:** Wave 07 — planı hazır, aktif değil ve başlatılmadı

Bu dosyanın hazırlanması Wave 06 aktivasyonu, kod/test/dependency değişikliği, veri taraması, DB migrationı, retention job'ı, hesap silme, backup/restore, dış servis veya canlı sistem işlemi, deploy ya da Wave 07 uygulaması için yetki değildir.

## 1.1 Sale Release override — TAM / ÇEKİRDEK

- **Satış öncesi uygulanır:** Canonical country sahipliği, Global/Country veri zemini, account deletion, retention/anonymization davranışı ve privacy metni ile gerçek DB davranışının eşliği.
- **Post-acquisition Roadmap / Deferred:** Geniş privacy automation, policy management veya enterprise data-governance platformu.
- **Canlı sınır:** Gerçek kullanıcı silme, production retention çalıştırma veya DB migration/cutover ayrıca açık kullanıcı yetkisi ister.
- **Kapanış:** Veri yaşam döngüsü ve migration testleri geçer, tek Wave 06 commit'i alınır ve **DUR**. Manuel/privacy owner kontrolleri Checkpoint A/Wave 19'a gider.

## 2. Canonical referanslar

Uygulama sırası değişmez: `B-DATA-001 → B-DATA-002 → C-COMP-002 → B-DATA-003 → C-TRUST-002`.

1. `B-DATA-001` — Plan B / veri sahipliği ve retention matrisi / bütün kabul kriterleri
2. `B-DATA-002` — Plan B / canonical matchmaking country / bütün kabul kriterleri
3. `C-COMP-002` — Plan C / Privacy, Data Safety ve retention uyumu / bütün kabul kriterleri
4. `B-DATA-003` — Plan B / hesap silme ve anonimleştirme / bütün kabul kriterleri
5. `C-TRUST-002` — Plan C / destek ve hesap silme operasyonu / bütün kabul kriterleri

Yürütme kaynağı: `../TALKX_WAVE_MAP.md` / Wave 06.
Canonical ayrıntı kaynakları: `../TALKX_PLAN_B_PLATFORM_REALTIME_DATA.md` ve `../TALKX_PLAN_C_ADMIN_TRUST_RELEASE.md`.
Kilitli karar ve başlangıç kanıtı: `../TALKX_MASTER_BACKLOG.md` / §5, §6, §9, §10, §14 ve QA-017 §11.

Bağımlılık yorumu:

- Wave 04'ün migration/runbook çekirdeği otomatik doğrulanmış ve committed olmalıdır; schema, retention job, backup ve restore bu kapıları tüketir.
- Wave 05'in recovery/presence çekirdeği otomatik doğrulanmış ve committed olmalıdır; hesap silme runtime socket/queue/room/presence temizliğini bundan ister.
- Wave 02 admin authorization/re-auth/audit çekirdeği otomatik doğrulanmış ve committed olmalıdır; destructive action sınırı yeniden icat edilmez.
- `B-MM-002`, `A-MATCH-003` ve `C-ANL-002` Wave 08'in otoritesidir. Wave 06 yalnız canonical country kaynağını ve privacy sınırını hazırlar; queue partition, fallback, scope telemetry veya selector kurmaz.
- Retention süreleri yasal/ürün owner onayı olmadan AI agent tarafından uydurulmaz. Wave kapanışında hiçbir veri sınıfı `TBD`, belirsiz veya ownersız bırakılamaz.

## 3. Wave sonucu

Wave 06 sonunda:

- Bütün kalıcı, geçici, log, analytics, audit, dış servis ve backup veri sınıfları tek sürümlü sahiplik/retention matrisine bağlanacak.
- Her veri sınıfının amacı, veri sahibi, teknik owner'ı, saklama başlangıç/bitiş tetikleyicisi, silme/anonimleştirme davranışı, legal-hold istisnası, admin erişimi ve backup sonucu açık olacak.
- Machine-readable policy registry ile insan tarafından okunur privacy/Data Safety matrisi aynı stable key ve policy version üzerinden izlenebilecek.
- Retention enforcement dry-run, bounded batch, advisory lock, ölçüm, retry ve audit ile çalışacak; canlı tabloda kontrolsüz toplu silme yapılmayacak.
- Matchmaking için yalnız ISO 3166-1 alpha-2 kodu taşıyan, server-policy otoriteli ve freshness/status bilgili ayrı canonical country kaydı bulunacak.
- `legal_acceptances.location_country` veya admin geo cache doğrudan queue key yapılmayacak; unresolved/private/local veya normalize edilemeyen değer canonical ülke sayılmayacak.
- Client başka ülke seçemeyecek; yalnız kendi server-resolved ülke durumu ve yerelleştirilmiş display name'i görebilecek.
- Mevcut Privacy, Data Safety ve ürün anonimlik iddiaları gerçek kod/DB/dış servis/retention akışıyla satır satır eşleştirilecek; insan/legal incelemesi gereken kararlar açık kalacak.
- Hesap silme; request, review, processing, verification ve completion aşamalarına sahip idempotent bir state machine olacak.
- Talep anında yeni session ve aktif runtime state güvenle kapatılacak; silme worker'ı tablo politikasına göre delete/anonymize/retain işlemlerini kanıtlayacak.
- Moderasyon, support, audit veya legal amaçla tutulan veri doğrudan hesap kimliği ve gereksiz içerikten arındırılacak; gerekçe, süre ve erişim sahibi kaydedilecek.
- Eski backup restore edildiğinde tamamlanmış silmelerin geri gelmesini engelleyen erasure replay/watermark kapısı bulunacak.
- Support kaydının ürün DB sonucu ile Brevo teslim durumu ayrılacak; duplicate, owner, note, sensitive media ve deletion ilişkisi izlenebilir olacak.
- Wave 07 veya Wave 08'e ait search/scope/fallback/eşleşme davranışı başlatılmayacak.

## 4. Doğrulanmış başlangıç fotoğrafı

### 4.1 Mevcut veri yüzeyi

`chatapp-backend/db.js` bugün en az şu veri ailelerini tek PostgreSQL bağlantısında tutuyor:

- Hesap, session, profile ve friendship: `users`, `sessions`, `profiles`, `friendships`
- Legacy anonymous identity: `users_anon`
- Conversation/message/media: `conversations`, `messages`, `ephemeral_media`
- Trust: `reports`, `bans`, `blocks`
- Push: `push_devices`, `push_delivery_logs`
- Support: `support_reports`, `support_report_media`
- Legal/config: `legal_acceptances`, `app_settings`, `notification_schedules`
- Deletion/audit: `account_deletion_requests`, `admin_action_audit`
- Performance/analytics: `http_request_events`, `http_request_metrics_minute`, `behavior_events`

Wave 05 kapanışında presence lease tabloları eklenmişse başlangıç envanterine ayrıca dahil edilir. Sonraki wave'lerin system message/release-health tabloları henüz yoksa varmış gibi yazılmaz; retention registry yeni stable key eklenmesini zorunlu kılacak biçimde tasarlanır.

Başlangıç sorunları:

- Tabloların tamamını kapsayan canonical retention süresi/owner/action matrisi veya machine-readable enforcement registry görünmüyor.
- FK davranışları tutarlı değil: bazı child kayıtlar cascade/set-null, bazı kimlik alanları FK'siz ve bazı ilişkiler admin kodunda elle siliniyor.
- `admin_action_audit` update/delete'i trigger ile engellenmiş; mevcut payload'larda subject/user kimliği tutulabilmesi deletion/pseudonymization kararı gerektiriyor.
- `reports`, `bans`, `blocks`, `conversations`, `behavior_events`, `push_delivery_logs` ve deletion/audit kayıtlarında FK dışı veya snapshot kimlikleri bulunabiliyor.
- Support kaydı user silinince `user_id` alanını `NULL` yapabiliyor fakat username, email, IP, user-agent, description ve media ayrıca kalabiliyor.
- Ephemeral media için runtime cleanup mevcut olsa da bütün veri aileleri için ortak dry-run/enforcement/audit mekanizması yok.
- Backup artifact'ı ve restore geçmişi mevcut; tamamlanmış kullanıcı silmelerinin eski backup restore'unda yeniden görünmesini önleyen erasure replay kanıtı görünmüyor.

### 4.2 Canonical country gerçeği

- `users` ve `profiles` içinde canonical matchmaking country alanı/tablosu yok.
- `legal_acceptances` içinde `location_city`, `location_country`, `location_label`, `location_source`, `location_resolved_at`, IP ve user-agent bulunuyor.
- Bu kayıt legal kabul anının tarihsel snapshot/cache'idir; ülke serbest metindir ve ISO alpha-2 bütünlüğü yoktur.
- Admin geo zinciri bugün IP üzerinden `ipapi.co`, `ipwho.is` ve `ip-api.com` gibi provider'ları deneyebiliyor.
- Tarihsel düzeltmede `unresolved`/`none` lookup sonuçlarının taze final gerçek olarak cache'lenmemesi sağlandı; bu davranış canonical modelde de korunmalıdır.
- Local/private IP ve çözülemeyen provider sonucu ülke uygunluğu kanıtlamaz.
- Mevcut geo resolver display country name döndürüyor; canonical ISO country-code contractı ve policy version üretmiyor.
- QA-017, `legal_acceptances.location_country` alanının normalize/doğrulama olmadan eşleşme otoritesi yapılmasını açıkça yasaklıyor.

### 4.3 Hesap silme gerçeği

- `/api/me/delete-request` mevcut parolayı ve sabit confirmation metnini doğruluyor.
- Aynı kullanıcı için tek açık `requested` kaydı partial unique index ile korunuyor.
- Talep kullanıcıyı `pending_deletion` yapıyor ve DB session'larını siliyor; response doğru biçimde yalnız talebin alındığını söylüyor.
- Mevcut açık authenticated WebSocket, queue, room, pending offer ve process-memory client state talep transaction'ı tarafından doğrudan kapatılmıyor.
- Admin approval transaction'ı friendship, block, user-sent messages, conversation ve session kayıtlarını elle siliyor, deletion request'i completed yapıp audit yazıyor ve user kaydını siliyor.
- User silmenin cascade etkisi profile, legal acceptance, push device ve bazı media kayıtlarını temizleyebilir; FK'siz report/ban/analytics/log/audit/snapshot alanları ayrıca policy gerektirir.
- Deletion request özellikle user FK'sinden ayrılmış ve username snapshot taşıyor; completion sonrası veri minimization süresi/işlemi tanımlı değil.
- Approval tek transaction içinde çalışsa da tablo-bazlı sonuç sayımı, orphan scan, dış servis sonucu, runtime disconnect ack veya restore-erasure kaydı üretmiyor.
- Rejected/reactivate yolları user durumunu tekrar `active` yapıyor; destructive processing başladıktan sonraki geri dönüş sınırı state machine ile kilitli değil.
- Frontend talep response'undan sonra logout oluyor; gerçek backend deletion completion sonucu için ayrı kullanıcı görünürlüğü bulunmuyor.

### 4.4 Privacy, processor ve support gerçeği

- Kod yüzeyinde PostgreSQL hosting, Render runtime, Firebase push, Brevo email, üç geo provider ve DiceBear avatar çağrısı gibi veri akışları bulunuyor; gerçek production enablement, bölge, hesap, sözleşme ve config başlangıçta yeniden doğrulanmalıdır.
- Support API raporu ve medyayı önce PostgreSQL'e yazıyor; Brevo teslimini `pending/sent/failed` alanlarıyla ayrı kaydediyor.
- Support; optional email, user/username snapshot, app/platform/device/network/error, IP/user-agent, description ve binary media taşıyabiliyor.
- Duplicate submit için stable idempotency/fingerprint, admin owner/workflow veya retention/hold sözleşmesi görünmüyor.
- Admin support kaydını doğrudan silebiliyor; destructive re-auth/impact preview ve retained-evidence sonucu canonical değildir.
- Privacy/Data Safety beyanlarını bütün bu kod yollarına ve gerçek retention davranışına bağlayan sürümlü kanıt matrisi görünmüyor.

### 4.5 Repo ve operasyon sınırı

- Root, backend ve frontend ayrı Git bağlamları taşıyor; geniş kullanıcı değişiklikleri korunmalıdır.
- Wave 04 migration/backup/runbook ve Wave 05 runtime cleanup altyapısı yalnız gerçek QA kapanışından sonra tüketilebilir.
- Canlı veri sayımı, IP/geo export'u, retention dry-run, hesap silme veya backup incelemesi bu planın hazırlanmasıyla yetkilendirilmez.
- Privacy/Data Safety veya yasal metin değişikliği yalnız mühendislik kararı değildir; yetkili insan/legal owner incelemesi gerekir.

## 5. Kilitli Wave 06 sözleşmeleri

### 5.1 Data-class registry ve sahiplik matrisi

Her veri sınıfı tek stable `dataClassKey` taşır. Tablo adı tek başına veri sınıfı değildir; aynı tabloda farklı amaç/retention taşıyan kolonlar ayrı class olabilir.

Zorunlu alanlar:

| Alan | Anlam |
|---|---|
| `dataClassKey` | Değişmeyen machine-readable kimlik |
| `stores` | Tablo/kolon, process memory, dosya, log, backup ve dış processor yolları |
| `purpose` | Kullanıcıya/operasyona dönük açık amaç |
| `dataSubject` | Hesap, anon cihaz, admin, support contact veya sistem |
| `sensitivity` | Public/internal/personal/sensitive/restricted sınıfı |
| `productOwner` / `technicalOwner` | Politika ve uygulama sahipleri |
| `collectionSource` | Client, server-derived, admin veya third party |
| `retentionStart` | Clock başlangıcı: create, last activity, close, resolve vb. |
| `retentionDuration` | Onaylı açık süre veya event-bound kural |
| `expiryAction` | Delete, anonymize, aggregate, archive veya retain-with-hold |
| `accountDeletionAction` | Delete/anonymize/retain + gerekçe |
| `legalHoldPolicy` | Allowlist reason, owner, approval ve expiry |
| `adminAccess` | Rol, maske, reveal, audit ve export sınırı |
| `processorsAndRegions` | Dış servis ve doğrulanmış veri bölgesi |
| `backupBehavior` | Backup içinde kalma süresi ve restore sonrası işlem |
| `evidenceQuery` | Dry-run/count/orphan doğrulama yolu |
| `policyVersion` | Onay, effective date ve değişiklik izi |

Minimum registry kapsamı:

- Account/session/profile/canonical country/presence lease
- Friendship/block ve friend conversation/message
- Anonymous identity/conversation/message
- Ephemeral/support media
- Report/ban/moderation evidence
- Support description/contact/diagnostic/delivery metadata
- Push token ve delivery log
- Legal acceptance/IP/user-agent/geo cache
- Behavior analytics ve performance telemetry
- System message ve release-health için gelecekte zorunlu kayıt kapısı
- Admin audit ve deletion operation/receipt
- Config/schedule
- Application/infra log
- Backup ve restore artifact

Kurallar:

- Registry sürümlü repo kaynağıdır; aynı stable key privacy/Data Safety ve enforcement job tarafından tüketilir.
- DB schema inventory'sinde kullanıcı/cihaz/mesaj/medya/IP alanı olup registry'de olmayan her kolon kalite kapısını kırar.
- Süre, owner veya action alanı `TBD`, boş ya da yorum içine gizlenmişse Wave kapanmaz.
- Yasal dayanak uydurulmaz; gereken owner/human review kayıt altına alınır.
- Anonymous ve friend mesaj aynı policy satırında birleştirilmez.
- Moderasyon/legal hold genel ve süresiz istisna olamaz; reason/owner/expiry zorunludur.
- Admin varsayılan görünümü masked/minimum olur; reveal/export ayrıca yetki ve audit ister.

### 5.2 Retention enforcement sözleşmesi

- Her enforcement run benzersiz `runId`, `policyVersion`, mode (`dry_run|execute`), cutoff snapshot ve server time taşır.
- Default mode dry-run'dır. Production `execute` ayrı açık kullanıcı yetkisi, current backup/rollback planı ve impact preview ister.
- Job tek scheduler instance varsaymaz; PostgreSQL advisory lock veya Wave 04'te doğrulanmış tek-runner mekanizması kullanır.
- Her class bounded batch, deterministic order, transaction sınırı, timeout, retry/backoff ve stop threshold taşır.
- İlk dry-run candidate count, oldest/newest, estimated bytes ve class key üretir; raw içerik, IP, token, email veya message body loglamaz.
- Delete/anonymize işleminden sonra affected count, orphan check ve remaining-expired count kanıtlanır.
- Partial failure run'ı başarılı göstermez; son güvenli cursor ve retryable/non-retryable reason saklanır.
- Legal hold, yalnız yetkili ve süresi belli hold kaydını hariç tutar; expired hold otomatik normal policy'ye döner.
- Retention job canlı request path'ini bloklamaz; query plan, index ve load sınırı staging'de ölçülür.
- Audit, silinen hassas içeriği kopyalamaz; class/run/count/cutoff/actor/policy sonucu taşır.
- Feature/data owner onayı olmadan default süre seçilmez. Policy değeri eksik class için job fail-closed olur.

Backup kuralı:

- Eski backup fiziksel olarak satır satır değiştirilmeye çalışılmaz.
- Her backup artifact policy version, createdAt, expiresAt, encryption/access ve erasure watermark metadata'sı taşır.
- Backup retention canlı deletion policy'sinden uzun kalacaksa gerekçe, maksimum süre ve erişim kısıtı açık onay ister.
- Restore trafiğe açılmadan tamamlanmış deletion/expiry journal'ı replay edilir ve kritik erasure query'leri sıfır/eşleşmiş sonuç verir.
### 5.3 Canonical matchmaking country modeli

Canonical kayıt legal acceptance veya admin profile görünümüne ek kolon gibi davranmaz; eşleşme amacı ve retention'ı ayrı olan tek-user kaydıdır.

Minimum logical schema:

```text
user_match_country
- user_id                    UUID PRIMARY KEY, users(id) ON DELETE CASCADE
- country_code               CHAR(2) NULL
- source                     controlled enum
- status                     eligible | stale | unavailable | disputed
- confidence                 policy_verified | inferred | unknown
- source_observed_at         TIMESTAMPTZ NULL
- resolved_at                TIMESTAMPTZ NULL
- updated_at                 TIMESTAMPTZ NOT NULL
- policy_version             TEXT NOT NULL
```

Kurallar:

- `country_code` yalnız uppercase ISO 3166-1 alpha-2 allowlist değeridir; regex tek başına yeterli değildir.
- `eligible` durumda geçerli code, izinli source, uygun confidence, freshness ve current policy version zorunludur.
- `stale`, `unavailable` veya `disputed` queue için ülke uygunluğu vermez; code tanısal amaçla tutulacaksa API tüketicisine effective değer diye sunulmaz.
- `policy_verified`, KYC/vatandaşlık/kimlik doğrulaması demek değildir; yalnız tanımlı server policy'nin matchmaking için kabul ettiği canonical sonuçtur.
- Client country code/source/status yazamaz ve başka ülke seçen mutation endpoint'i bulunmaz.
- Server-seen request IP veya onaylı başka source'tan resolver çalışabilir; canonical tabloda raw IP, GPS, şehir veya adres tutulmaz.
- Provider contract display ülke adı değil ISO alpha-2 döndürür; provider name/string'i strict ISO catalog'a map edilemiyorsa sonuç unavailable olur.
- Display name storage alanı değildir; TR/EN ve sonraki locale'lerde ortak ISO/CLDR/`Intl.DisplayNames` kataloğundan üretilir.
- Provider timeout/rate limit/unresolved sonucu mevcut eligible kaydı sessizce başka ülkeye veya unavailable'a çeviremez; freshness policy geçince stale transition uygulanır.
- VPN/seyahat sinyali aktif session veya ilerideki aktif search'i sessizce değiştirmez. Yeni country version yalnız kontrollü refresh sonucu olur; Wave 08 active search snapshot kuralını tüketir.
- Logout/account switch local cache'i taşımamalıdır; authenticated server response otoritedir.

Kaynak önceliği ve provenance:

- İzin verilen source listesi policy registry'de sürümlüdür; örneğin server-observed registration/session IP resolver veya açıkça onaylanmış admin correction.
- Source detail yalnız provider key, policy version ve observed timestamp gibi minimum provenance taşır; IP veya provider'ın ham cevabı kopyalanmaz.
- Manual/admin düzeltme varsa role, reason, before/after, policy ve expiry audit'i gerekir; serbest ülke metni doğrudan yazılamaz.
- Canonical kayıt değişiminde previous/new status+code ve policy reason auditlenir; kullanıcı kimliği default log görünümünde maskelenir.

Legacy backfill:

1. `legal_acceptances.location_country/source/resolved_at` yalnız candidate olarak read-only taranır.
2. `unresolved`, `none`, `local`, `private`, boş, stale veya kaynağı belirsiz kayıt otomatik eligible olmaz.
3. Free-text değer strict, sürümlü alias kataloğuyla ISO'ya çevrilir; fuzzy guess yapılmaz.
4. Bir kullanıcıda çelişen candidate varsa `disputed/unavailable`; en yakın veya son değer tahmin edilmez.
5. Dry-run yalnız aggregate eligible/stale/unavailable/disputed ve reason count üretir; ham IP/username rapora girmez.
6. Onaylı migration idempotent upsert yapar, mevcut daha yeni canonical kaydı ezmez ve policy version taşır.
7. Backfill sonrası source-vs-target aggregate/parity ve örneklenmiş maskeli manuel inceleme yapılır.

Kullanıcıya sunulan read contract en az şunları taşır:

```json
{
  "countryMatching": {
    "status": "eligible",
    "code": "TR",
    "displayName": "Türkiye",
    "updatedAt": "2026-09-12T12:00:00.000Z",
    "policyVersion": "country-v1"
  }
}
```

- Response yalnız kullanıcının kendi ülke uygunluğunu taşır; raw source/confidence/admin reason varsayılan client payload'ında bulunmaz.
- Capability Wave 06'da üretilebilir fakat Wave 08'e kadar selector, COUNTRY join veya fallback davranışı açılmaz.

### 5.4 Privacy ve Data Safety kanıt matrisi

Her dış beyan tek bir `claimKey` ile veri sınıfına bağlanır:

| Alan | Zorunlu içerik |
|---|---|
| Claim | Privacy/store/Data Safety/user-facing metin özeti |
| Data classes | Registry stable key listesi |
| Collected/derived | Kullanıcıdan alınan ve server'ın türettiği ayrımı |
| Purpose | Ürün, güvenlik, support, analytics veya operasyon amacı |
| Sharing/processor | Dış servis, gönderilen alanlar ve tetikleyici |
| Optional/required | Özelliğin çalışması için gereklilik |
| Retention/deletion | Registry policy key ve hesap silme sonucu |
| Region/transfer | Canlı config/hesap üzerinden doğrulanmış bölge ve mekanizma |
| User control | Görüntüleme, kapatma, silme veya destek yolu |
| Evidence | Kod, DB, config, provider paneli ve test kanıtı |
| Owner/review | Product/privacy/legal owner ve son review zamanı |

Minimum veri akışı incelemesi:

- Account/session/profile/friendship
- Anonymous ve friend messaging ayrımı
- Media upload/view/expiry ve moderation exception
- Report/block/ban/support ve sensitive attachment
- Push token/payload/delivery log ile Firebase
- Support email delivery ile Brevo
- IP/legal acceptance/geo resolution provider zinciri
- Canonical country ve Wave 08'deki gelecekteki queue code tüketimi
- Behavior/performance/release telemetry
- DiceBear gibi client-side dış asset isteği
- Render/Neon ve backup storage
- Ads/`app-ads.txt` yalnız reklam gerçekten açılırsa

Kurallar:

- “Anonim” yalnız kullanıcılar arası görünmezliği anlatır; servis account/session/IP/moderation verisini işliyorsa beyan bunu gizlemez.
- Kodda dependency bulunması ile production'da etkin veri paylaşımı ayrılır; enablement canlı config/panel ile doğrulanır.
- Processor region, DPA/terms veya store cevabı agent tarafından tahmin edilmez; yetkili owner kanıtı gerekir.
- Data Safety ekranı veya yasal metin agent tarafından otomatik yayınlanmaz. Taslak diff, etkilenmiş claim ve insan onayı üretilir.
- Reklam etkin değilse gereksiz consent/ads SDK mimarisi eklenmez; reklam açılırsa privacy ve Data Safety aynı değişiklik kapısında güncellenir.
- Üçüncü taraf silme/retention sınırı ayrı gösterilir; local row silindi diye dış sistemde gönderilmiş email/push/log yok olmuş sayılmaz.
- Claim ile registry policy uyuşmazlığı release blocker'dır; sessizce doküman veya kod tarafı doğru varsayılmaz.

### 5.5 Hesap silme state machine'i

Canonical state'ler:

```text
requested → reviewing → approved → processing → completed
                   └──────────────→ rejected
processing → failed_retryable → processing
```

State kuralları:

- Kullanıcı request'i güçlü mevcut auth, parola re-auth ve kesin confirmation ile açar; API stable `requestId`, `status=requested`, `requestedAt` ve “talep alındı” sonucu döndürür.
- Aynı kullanıcı için yalnız bir open request vardır. Aynı idempotency key/request retry aynı kaydı döndürür.
- Request transaction'ı user'ı `pending_deletion` yapar, bütün session'ları revoke eder, push tokenlarını delivery dışına alır ve Wave 05 user-scoped runtime termination komutu üretir.
- Runtime ack; aktif socket, queue, pending offer, anon room ve presence lease'in kapandığını kanıtlar. Bir instance erişilemiyorsa request kaybolmaz; lease expiry/worker retry tamamlar.
- `requested/reviewing` hesap yeni login, queue, message, media, push registration veya profile mutation yapamaz.
- Admin yalnız Wave 02 yetki/re-auth standardıyla review/approve/reject yapar; UI hedef, kapsam, policy version ve öngörülen delete/anonymize/retain özetini gösterir.
- `approved` destructive işlemi başlamadan önce son geri dönüş kapısıdır. `processing` başladıktan sonra reject/reactivate endpoint'i çalışmaz.
- Worker request row'unu `FOR UPDATE SKIP LOCKED` veya eşdeğer tek-owner mekanizmasıyla sahiplenir; aynı request iki worker tarafından uygulanmaz.
- Her data class işlemi ayrı step/cursor/count/result taşır; partial failure `completed` yazamaz.
- External processor işlemi destekleniyorsa ayrı step; desteklenmiyorsa limitation/retention kaydıdır. DB transaction external API başarısını varsaymaz.
- `completed` yalnız runtime, DB, orphan, retained evidence ve erasure journal doğrulamaları geçtiğinde yazılır.
- Kullanıcıya “hesap silindi” ancak backend completed receipt ile söylenir; request alınması completion değildir.

Policy-driven veri işlemi:

- **Delete:** aktif auth/session/profile, canonical country, presence lease, friendship/block, kullanıcıya ait push token ve policy'nin sil dediği conversation/message/media kayıtları.
- **Anonymize:** tutulması onaylanmış aggregate analytics, support/moderation/legal/audit kayıtlarındaki doğrudan username/email/IP/device/token ve raw user linkage.
- **Retain:** yalnız açık amaç, süre, owner, erişim rolü ve legal-hold/operasyon gerekçesi olan minimum evidence.
- Gerçek kararlar registry'den okunur; bu örnek sınıflandırma onaylı policy yerine hard-code edilmez.

Referential ve privacy kuralları:

- FK cascade'e kör güvenilmez; FK'siz user id, JSONB payload, username snapshot, email/IP, object key ve log correlation ayrıca taranır.
- Conversation'ın diğer kullanıcıya ait kalıcı message/history etkisi policy'de açık olmalıdır; bir hesabı silmek diğer kullanıcının verisini kanıtsız toplu silmez.
- Moderation/report evidence tutuluyorsa subject, reporter ve içerik linkage minimum pseudonymous case reference'a dönüşür.
- `account_deletion_requests` completion sonrası raw username snapshot ve doğrudan user id'yi süresiz tutmaz; minimal receipt policy'sine dönüşür.
- Immutable audit yeni kayıtlarda raw user id/username içermeyen request/case ref kullanır. Tarihsel audit için gerekiyorsa tek seferlik, açık onaylı ve auditlenen pseudonymization migrationı tasarlanır; trigger gizlice devre dışı bırakılmaz.
- Support contact email, IP, user-agent, description ve media her biri ayrı policy action'ı alır; `user_id=NULL` tek başına anonimleştirme değildir.
- Analytics/performance row'u aggregate olsa bile metadata/JSONB içinde subject identifier taranır.
- Orphan scan hem FK hem semantic linkage listesi üzerinden çalışır.

### 5.6 Erasure journal ve backup restore koruması

- Her completed request için raw username/email içermeyen `erasureId`, keyed pseudonymous `subjectRef`, key version, completedAt, policyVersion ve step checksum kaydı tutulur.
- `subjectRef`, restore edilen user UUID'sinin kontrollü secret/HMAC ile yeniden eşlenmesine izin verir; secret repo/log/backup içine yazılmaz.
- Erasure journal routine product backup'tan bağımsız, encrypted ve erişimi kısıtlı güncel kontrol artifact'ına düzenli export edilir.
- Journal retention da registry satırına ve açık owner/gerekçeye sahiptir; süresiz ve sahipsiz tutulmaz.
- Restore rehearsal eski backup'ı izole hedefe alır, en güncel erasure artifact'ını doğrular, tamamlanmış silmeleri/pseudonymization'ı replay eder ve ancak sonra functional smoke yapar.
- Cutover öncesi subject match, orphan, session, push, canonical country ve runtime başlangıç kontrolleri tamamlanır.
- Erasure artifact eksik, signature/hash geçersiz veya policy version uyumsuzsa restore production trafiğine açılamaz.
- Replay idempotenttir; aynı journal ikinci kez veri bozmadan sıfır ek etkiyle tamamlanır.
- Backup fiziksel silme süresi dolunca artifact ve checksum catalog kaydı policy'ye göre kaldırılır; destructive storage işlemi ayrıca açık yetki ister.

### 5.7 Support ve deletion operasyon sözleşmesi

Support için iki bağımsız durum korunur:

- `recordStatus`: received, triaged, in_progress, resolved, archived
- `deliveryStatus`: not_requested, pending, sent, failed, unknown

Kurallar:

- API success, PostgreSQL kaydının kabul edildiğini söyler; Brevo `sent` dışında email teslim edildi demez.
- Client-generated bounded `submissionId` aynı retry'da duplicate row/media üretmez.
- Benzer kayıtlar privacy-safe fingerprint ile “muhtemel duplicate grup” olarak ilişkilendirilebilir; otomatik tek case'e merge edilmez.
- Owner, internal note, state transition, user response ve timestamps server-side audit taşır.
- Contact email, IP, device/network diagnostic ve media varsayılan listede maskeli/kapalıdır; reveal/download rol + reason + audit ister.
- Media MIME/size/content kontrolü, at-rest erişim sınırı ve retention class taşır.
- Support kaydı account deletion geldiğinde registry'ye göre silinir veya minimum case evidence'a anonimleştirilir; username/email/IP yalnız `user_id=NULL` yapılarak bırakılmaz.
- Destructive delete/archive/attachment purge hedef sayısı ve retained consequence gösterir; admin re-auth/confirmation olmadan çalışmaz.
- Deletion request listesi request age, state, owner, last step, retry ve policy version gösterir; raw kullanıcı verisi varsayılan özet değildir.
- Reject reason zorunlu ve kullanıcıya aktarılabilir/özel admin notu ayrıdır.

### 5.8 Fallback ve hata davranışı

| Durum | Güvenli sonuç | Yasak davranış |
|---|---|---|
| Policy class eksik | Enforcement fail-closed, release blocker | Varsayılan süre uydurmak |
| Dry-run ve execute sayısı beklenmedik fark | Job durur, drift raporu | Toplu silmeye devam etmek |
| Legal hold belirsiz/expired | Owner review; normal policy açıkça belirlenir | Süresiz saklama |
| Country provider timeout | Mevcut eligible kayıt policy süresince korunur, sonra stale | Hemen unavailable/başka ülke yapmak |
| Free-text ülke normalize edilemiyor | unavailable/disputed | Fuzzy guess veya queue key |
| Client country code gönderiyor | Ignore/reject; server record kullan | Client değerini otorite yapmak |
| Deletion runtime ack eksik | Request pending/processing ve retry | Completed göstermek |
| Deletion step partial failure | `failed_retryable`, cursor/count korunur | Baştan kör tekrar veya completed |
| Retained evidence gerekçesiz | Completion/release bloke | “Audit” diyerek süresiz tutmak |
| Erasure journal restore'da yok | Cutover bloke | Eski silinmiş hesapları açmak |
| Brevo başarısız | DB case received + delivery failed | Support kaydını başarısız/yok saymak |
| Duplicate submit | Aynı submission result veya grup adayı | Duplicate media/email göndermek |
| Processor bölgesi bilinmiyor | Claim açık verification-needed | Bölge uydurmak |
| Privacy claim kodla çelişiyor | Release blocker + owner review | Sessizce bir tarafı doğru saymak |

### 5.9 Güvenlik, privacy ve telemetry sınırı

- Retention/deletion loglarında username, email, IP, token, message/support body, raw media veya country source payload bulunmaz.
- Counts çok küçük cohort'ta admin/analytics disclosure riski yaratıyorsa threshold/masking uygulanır.
- Country metric yalnız aggregate code/status/reason kullanır; tam IP, GPS, city, userId veya provider raw response taşımaz.
- Deletion/support admin endpointleri Wave 02 role, rate-limit, CSRF/re-auth ve audit sözleşmesini tüketir.
- Erasure HMAC secret ve encryption key versioned secret manager'da tutulur; repo, DB dump veya response'a girmez.
- Policy/config değişikliği actor, reason, before/after, effectiveAt ve version audit'i taşır.
- Retention worker metricleri run/class/result/count/duration/error-code gibi bounded label kullanır; subject id label olmaz.
- Country resolution metricleri provider/status/reason/policy version bazında aggregate olur.
- Deletion evidence access “kim, neden, ne zaman” audit'i olmadan mümkün değildir.
- Test fixture'ları sentetik kullanıcı/IP/email/media kullanır; production export test verisi yapılmaz.
## 6. Uygulama paketleri

### Paket 06A — Schema inventory ve policy registry

**Plan ref:** `B-DATA-001`.

1. Wave 05 sonrası gerçek DB schema, FK, index, trigger, JSONB, process-memory, log, file, backup ve dış processor envanterini read-only çıkar.
2. Her alanı stable `dataClassKey` ile machine-readable registry'ye ve insan matrisine bağla.
3. Product/technical/privacy/legal owner, retention clock/duration/action, deletion ve backup alanlarını doldur.
4. Süre/istisna gibi hukuki kararları yetkili owner'a çıkar; agent default üretmesin.
5. Registry-schema coverage validator ve privacy-claim referans kontrolünü ekle.
6. Retention runner'ı dry-run, lock, batch, cursor, timeout, retry, audit ve metric sınırlarıyla kur.
7. Sentetik/local DB'de delete/anonymize/aggregate ve partial failure testlerini tamamla.

**Çıkış:** Bütün veri sınıfları ownersız veya `TBD` kalmadan sürümlü policy'ye bağlı; production execute kapalı.

### Paket 06B — Canonical country kaynağı

**Plan ref:** `B-DATA-002`.

1. ISO allowlist/catalog ve controlled source/status/confidence transition'larını test-first oluştur.
2. `user_match_country` additive migrationını Wave 04 runner üzerinden ekle.
3. Server-side resolver'ı raw IP taşımayan minimum provenance ve bounded provider davranışıyla kur.
4. Legacy legal geo candidate dry-run/backfill aracını strict alias, conflict ve freshness policy'siyle yaz.
5. Backfill'i sentetik/staging fixture'da idempotency, newer-record guard ve aggregate parity ile doğrula.
6. Authenticated own-country read contractı ve capability alanını ekle; mutation/başka ülke seçme yüzeyi açma.
7. Account switch, stale/unavailable, VPN/seyahat refresh ve deletion testlerini ekle.
8. Wave 08'e kadar COUNTRY queue/selector/fallback'i feature-off tut.

**Çıkış:** Canonical ülke legal snapshot'tan ayrılmış, ISO/policy doğrulamalı ve privacy-safe.

### Paket 06C — Privacy/Data Safety uyum kanıtı

**Plan ref:** `C-COMP-002`.

1. Uygulamanın gerçek code/config/network data-flow haritasını registry stable key'leriyle çıkar.
2. Render/Neon/Firebase/Brevo/geo provider/DiceBear ve varsa diğer processor enablement, field, purpose ve region kanıtını doğrula.
3. Mevcut Privacy, Terms, store Data Safety ve ürün anonimlik ifadelerini claim key'lerle eşleştir.
4. Collected/derived/shared/optional/retention/deletion/user-control farklarını görünür yap.
5. Claim-policy-code drift validator ve release blocker raporunu kur.
6. Gerekli yasal/store metin değişikliklerini taslak diff olarak hazırla; publish etme.
7. Yetkili product/privacy/legal review ve onay kaydını evidence alanına bağla.

**Çıkış:** Her beyan gerçek veri akışına geri izlenebilir; belirsiz region/owner yayınlanmış gerçek sayılmaz.

### Paket 06D — Hesap silme orchestrator'ı

**Plan ref:** `B-DATA-003`.

1. Request/status/step/idempotency/policy-version schema migrationlarını additive ve rollback-safe ekle.
2. Request endpointini stable request receipt ve Wave 05 runtime termination ile bağla.
3. Yeni login/write/push/queue engelini bütün auth/socket/API yollarında server-side uygula.
4. Admin review/approve/reject sınırını re-auth, impact preview ve processing-point-of-no-return ile sürümle.
5. Policy-driven deletion worker'ı per-class step/cursor/count/retry ile oluştur.
6. FK'siz kolon, JSONB, snapshot, support, audit, analytics ve external processor işlemlerini açık step yap.
7. Retained evidence pseudonymization ve minimum completion receipt'i uygula.
8. Runtime/DB/orphan/retained-evidence verification geçmeden completed yazma.
9. Duplicate request/worker/retry ve mid-step crash testlerini tamamla.

**Çıkış:** Hesap silme deterministik, idempotent ve tablo/operasyon kanıtıyla tamamlanıyor.

### Paket 06E — Erasure restore ve trust operasyonu

**Plan ref:** `C-TRUST-002`.

1. Protected erasure journal, subjectRef/key-version ve bağımsız encrypted export akışını kur.
2. Wave 04 restore rehearsal/runbook'una erasure verification/replay zorunlu kapısını ekle.
3. Support `recordStatus` ile Brevo `deliveryStatus` alanlarını ayır ve mevcut kayıtları güvenli migrate et.
4. Submission idempotency, duplicate grouping, owner/note/user-response ve state-transition audit'i ekle.
5. Sensitive media reveal/download/purge ile deletion request actionlarını role/re-auth/reason/impact preview'a bağla.
6. Support/deletion admin özetini minimum masked veri ve progressive evidence ile güncelle.
7. Rejected/reactivate ve processing sonrası yasak transition'ları otomatik test et.
8. İzole restore targetında eski backup + güncel erasure journal replay'i kanıtla.

**Çıkış:** Support/deletion kaydı kaybolmuyor, yanlış tamamlanmıyor ve restore silinmiş hesabı geri açmıyor.

### Paket 06F — Entegrasyon, staging QA ve kapanış

**Plan refs:** Wave 06'nın beş stable ID'si.

1. Schema-policy coverage, retention, country, privacy mapping, deletion ve support focused testlerini çalıştır.
2. Sentetik tam user graph'i üzerinde delete/anonymize/retain ve orphan sonuçlarını karşılaştır.
3. Staging dry-run candidate count ve ardından açık test onayıyla küçük sentetik execute rehearsal yap.
4. Eski backup restore + erasure replay + post-restore critical verification kanıtını al.
5. Web/Android deletion request metni ve admin review akışını manuel doğrula.
6. Full syntax/lint/build/encoding/test kapılarını çalıştır.
7. İnsan privacy/legal review kanıtı olmadan C-COMP-002'yi kapatma.
8. Kullanıcı QA onayı gelmeden canonical checkbox/durum kapatma.
9. Wave 07 uygulamasını başlatma.

**Çıkış:** Wave 06 kanıtlı kapanışa hazır; retention/deletion production execute edilmedi ve ardıl wave başlamadı.

## 7. Dosya ve servis etki sınırı

Bu liste planlanan etki yüzeyidir; Wave başlatıldığında repo yeniden doğrulanmadan dosya değişikliği yapılmaz.

### Backend ve DB olası etki

- Wave 04'te doğrulanan migration runner/dizini — policy, country, deletion operation ve journal additive migrationları
- `chatapp-backend/db.js` — legacy schema kaynağı olarak okunur; yeni ad-hoc `ensureTables()` DDL burada yığılmaz
- `chatapp-backend/routes/profile.js` — deletion request receipt/state ve own-country read contractı
- `chatapp-backend/index.js` — yalnız orchestrated runtime termination entegrasyonu; domain logic burada yığılmaz
- Wave 05 connection/presence service'i — user-scoped socket/queue/room/lease cleanup
- Ayrıştırılacak retention policy/runner ve country resolver/service modülleri
- Ayrıştırılacak deletion orchestrator/worker/journal modülleri
- `chatapp-backend/routes/support.js` ve `utils/brevoSupport.js` — submission/workflow/delivery ayrımı
- `chatapp-backend/admin.js` — versioned admin API, authorization/impact/transition sınırı
- `chatapp-backend/admin.html` — yalnız mevcut admin mimarisi gerçekten hâlâ consumer ise trust UI; Plan C progressive disclosure standardı
- Config/env validator ve Wave 04 operasyon runbook'u
- Focused backend unit/PostgreSQL integration/runtime tests

### Frontend olası etki

- `chatapp-frontend/src/api.js` — versioned deletion receipt/status ve own-country read modeli
- `chatapp-frontend/src/screens/HomeScreen.jsx` — request ile completion metnini ayırmak
- `chatapp-frontend/src/App.jsx` — yalnız logout/runtime orchestration; yeni data policy logic'i eklenmez
- `chatapp-frontend/src/i18n/messages.tr.js` ve `messages.en.js`
- Wave 06'da country selector/queue UI eklenmez; country capability yalnız sonraki consumer için kapalı veri olabilir
- Focused API/state/component testleri

### Dokümantasyon ve kanıt etkisi

- Sürümlü data-class/retention registry ve insan okunur matrisi
- Privacy/Data Safety claim-to-code evidence matrisi
- Processor/region/config envanteri
- Account deletion runbook, step/action ve restore-erasure kanıtı
- Support/deletion admin operasyon rehberi
- Wave 06 test/QA sonuç kaydı
- Canonical Plan B/C checkbox ve Master kayıtları yalnız gerçek kapanışta
- Wave Map/README yalnız kanıtlı durum değişikliğinde

### Harici ve canlı yüzey

- Neon/PostgreSQL schema ve data
- Render runtime/config/scheduler
- Backup storage ve erasure artifact storage
- Firebase push token/delivery yüzeyi
- Brevo support email yüzeyi
- Geo provider requestleri
- Privacy/store Data Safety yayın yüzeyleri

Bunların hiçbiri plan dosyasının varlığıyla değiştirilemez veya sorgulanamaz; read-only production inceleme dahi hassas veri kapsamına göre ayrıca sınırlandırılır.

## 8. Açık kapsam dışı

- Wave 07 `B-MM-001` search lifecycle ve `A-MATCH-001` QA-014 UI
- Wave 08 `B-MM-002`, `A-MATCH-003`, `C-ANL-002`, `A-HOME-001`
- Global/Country queue partition, scope switch, fallback event, selector veya cohort dashboard
- Wave 09 pending-match karar protokolü ve QA-003 yeniden tasarımı
- Wave 10 message idempotency/outbox genişletmesi
- Wave 11 media/moderation/chat-header feature genişletmesi
- System message ve Release Health schema/feature uygulaması; yalnız gelecek registry coverage kapısı
- Yeni reklam/consent SDK'sı veya reklam feature'ı
- Kullanıcının manuel başka ülke seçmesi, GPS/şehir/adres toplama veya ülkeyi KYC iddiasına dönüştürme
- Production geo backfill, production retention execute veya gerçek kullanıcı hesabı silme
- Canlı DB migrationı, backup silme/restore, Render/Neon config, restart/redeploy veya store publish
- Hukuki süre/dayanak/processor-region bilgisini agent tahminiyle doldurma
- Bütün admin panelini yeniden tasarlama veya bağımsız QA-009/QA-013 uygulaması
- Android sync/version/signing/bundle/store işlemleri
- Wave 07 uygulaması

## 9. Otomatik doğrulama planı

### 9.1 Registry ve schema coverage

- `information_schema`, migration files, JSONB field allowlist, process-memory registry, logs ve external processors data-class registry ile karşılaştırılır.
- Yeni kullanıcı/cihaz/message/media/IP alanı stable class olmadan CI validation'dan geçmez.
- Her class owner, duration, trigger, expiry action, deletion action, admin access, backup ve policy version taşır.
- `TBD`, boş duration, ownersız hold veya bilinmeyen processor region release blocker üretir.
- Privacy claim'deki her class registry'de; registry'deki user-impact class privacy matrix'te görünürdür.
- Anonymous ve friend message policy'lerinin farklı olduğu fixture ile doğrulanır.

### 9.2 Retention runner test matrisi

| Senaryo | Beklenen kanıt |
|---|---|
| Default invocation | Yalnız dry-run; hiçbir row değişmez |
| Aynı cutoff iki dry-run | Deterministic candidate count |
| Aynı execute tekrar | İkinci çalışmada veri bozulmaz/ek etki yok |
| İki worker yarışı | Tek advisory-lock owner |
| Batch ortasında DB error | Partial failure + güvenli cursor; success yok |
| Legal hold aktif | Yalnız geçerli hold dışlanır ve count açıklanır |
| Hold süresi dolmuş | Normal policy adayı olur |
| Policy version drift | Execute durur; yeniden preview ister |
| Beklenmeyen target count | Stop threshold çalışır |
| Delete/anonymize sonrası | Remaining-expired ve orphan doğrulaması |
| Backup retention farkı | Açık warning/owner/onay; sessiz uyum yok |

### 9.3 Canonical country test matrisi

- ISO alpha-2 allowlist geçerli/geçersiz/büyük-küçük harf ve retired/unknown code fixture'ları.
- Strict alias katalogunda TR/Türkiye/Turkey gibi açık mapping; typo/fuzzy değer unavailable.
- `unresolved/none/local/private` source hiçbir zaman eligible olmaz.
- Provider timeout/rate-limit mevcut eligible kaydı anında ezmez; TTL sonunda stale olur.
- Conflicting candidate disputed/unavailable; son veya çoğunluk tahmini yapılmaz.
- Newer canonical record backfill tarafından ezilmez.
- Backfill ikinci kez ek/duplicate değişiklik üretmez.
- Client-sent arbitrary code ignore/reject edilir.
- Response code/display/status/updated/policy version contractı TR/EN'de tutarlı.
- Raw IP/GPS/city queue-ready response, log veya behavior telemetry'de bulunmaz.
- Account deletion canonical country row'unu policy'ye göre kaldırır.
- Düşük cohort aggregate çıktısı privacy threshold'u altında maskelenir.

### 9.4 Privacy/Data Safety validation

- Code/config/network fixture'ı processor inventory ile karşılaştırılır.
- Disabled dependency “aktif paylaşım” diye; aktif processor “yalnız dependency” diye yanlış sınıflanmaz.
- Firebase, Brevo, geo provider, DiceBear, Render/Neon ve backup için gönderilen field/purpose/region evidence zorunludur.
- Anonymous claim account/IP/report/support gerçeklerini gizlemiyorsa pass olur.
- Reklam disabled durumda consent SDK gereksiz eklenmez; enabled fixture privacy/Data Safety beraber update ister.
- User deletion claim gerçek deletion step sonuçlarıyla karşılaştırılır.
- Human review/onay yoksa legal/store publish gate fail olur.

### 9.5 Hesap silme ve orphan test matrisi

- İlk request doğru receipt ve `pending_deletion`; duplicate aynı open request sonucunu döndürür.
- Yanlış parola/confirmation request açmaz.
- Request bütün session, active socket, queue, offer, room, presence ve push delivery eligibility'yi kapatır.
- Pending account REST/WS/login/write yollarında server-side reddedilir.
- Reject yalnız pre-processing state'te ve reason ile çalışır; yeni login açıkça gerekir.
- Approve iki worker yarışında tek processing owner üretir.
- Her policy class için delete/anonymize/retain fixture sonucu ve before/after count doğrulanır.
- Mid-step crash retry aynı step'i veri bozmadan tamamlar.
- FK'siz ID, JSONB, username/email/IP/device/token/object key ve log reference orphan scanner'da kapsanır.
- Retained moderation/support/audit evidence minimum pseudonymous ref ve açık reason/expiry taşır.
- `user_id=NULL` kalan raw snapshot anonim sayılmaz ve testi kırar.
- Runtime/DB/external/journal validation bitmeden completed yazılmaz.
- Completed request ikinci kez işlendiğinde no-op/aynı receipt döner.
- Processing başladıktan sonra reactivate/reject engellenir.

### 9.6 Restore-erasure ve support testleri

- Güncel journal export hash/signature/key-version doğrulaması.
- Eski sentetik backup restore edildiğinde completed subject replay ile yeniden silinir/anonimleştirilir.
- Aynı journal ikinci replay'de veri bozulmaz.
- Journal eksik/bozuk/policy drift durumunda cutover bloke olur.
- Support aynı `submissionId` retry'ında tek DB case, tek media set ve tek delivery attempt policy'si üretir.
- DB accepted + Brevo failed iki ayrı status olarak kalır.
- Duplicate fingerprint yalnız group suggestion üretir, otomatik merge etmez.
- Yetkisiz sensitive media reveal/download/purge reddedilir ve başarılı erişim auditlenir.
- Account deletion support contact/diagnostic/media alanlarına registry action'ını uygular.
- Admin destructive action re-auth, reason ve impact preview olmadan çalışmaz.

### 9.7 Mevcut komut ve kalite kapıları

```powershell
npm.cmd run check:text-encoding
npm.cmd --prefix chatapp-frontend run lint
npm.cmd --prefix chatapp-frontend run build
node --check chatapp-backend/db.js
node --check chatapp-backend/index.js
node --check chatapp-backend/admin.js
node --check chatapp-backend/routes/profile.js
node --check chatapp-backend/routes/support.js
```

- Root `npm test` bugün bilerek başarısız placeholder'dır; başarı kanıtı olarak kullanılmaz.
- Backend/frontend test runner ve Wave 03–05'te oluşmuş komutlar başlangıçta yeniden okunur.
- Yeni backend service/worker/migration validator dosyalarının tamamına syntax/focused test uygulanır.
- PostgreSQL integration testleri yalnız ayrı sentetik test DB'sinde çalışır; canlı `DATABASE_URL` guard ile reddedilir.
- Migration up/down veya forward-fix, empty/current schema ve transaction failure testleri Wave 04 kurallarını tüketir.
- Full stdout/exit code/duration ve fixture DB kimliği kapanış kanıtında saklanır.

## 10. Manuel ve staging QA planı

### 10.1 Policy ve privacy incelemesi

- Data-class matrisi product, technical, privacy/legal owner ile satır satır gözden geçirilir.
- Her claim için kod/DB/config/provider kanıtına gidilir; yalnız doküman metnine güvenilmez.
- Anonymous/friend data farkı, IP/geo, support/media, push ve analytics kullanıcı gözüyle açıklanabilir olmalıdır.
- Processor enablement/region ve deletion limitation gerçek panel/config üzerinden doğrulanır; secret kopyalanmaz.
- Privacy/Data Safety diff'i yayın öncesi yetkili insan tarafından onaylanır.

### 10.2 Canonical country staging QA

1. Sentetik yeni, returning, country-eligible, stale, unavailable, disputed ve private-IP kullanıcıları oluştur.
2. Resolver/backfill sonucunu source record ve ISO catalog ile karşılaştır.
3. Kullanıcıya yalnız kendi code/display/status bilgisinin döndüğünü doğrula.
4. Client request body ile başka country code zorla; backend otoritesinin değişmediğini doğrula.
5. Provider kesintisinde eligible → stale zaman davranışını test clock ile kanıtla.
6. Account switch/logout'ta previous country cache sızıntısı olmadığını kontrol et.
7. Wave 08 capability kapalıyken selector veya COUNTRY queue'nun görünmediğini doğrula.

### 10.3 Hesap silme staging QA

1. Sessions, iki WebSocket, queue/room, friendship, messages/media, report/ban, support, push, legal/geo, analytics ve audit içeren sentetik user graph'i kur.
2. Web/Android mevcut build'den deletion request aç; UI yalnız “talep alındı” demeli ve session kapanmalı.
3. İkinci requestin duplicate oluşturmadığını doğrula.
4. Admin review'da masked impact/delete-anonymize-retain özeti, owner ve re-auth kapısını kontrol et.
5. Approve sırasında runtime state'in kapandığını ve kullanıcı yeni işlem yapamadığını iki-client ile doğrula.
6. Worker step/result/count/orphan/journal kanıtlarını registry ile karşılaştır.
7. Partial failure yaratıp retry'ın aynı operation'ı tamamladığını doğrula.
8. Completed öncesi kullanıcıya silindi mesajı çıkmadığını; sonrası minimum receipt bulunduğunu kontrol et.
9. Processing sonrası reactivate/reject'in kapalı olduğunu doğrula.

### 10.4 Support ve restore QA

- Aynı support submitini timeout/retry ile gönder; tek case/media/delivery sonucu oluşmalı.
- Brevo fail fixture'ında case received, delivery failed görünmeli.
- Owner/note/state/user-response akışını ve unauthorized media erişimini kontrol et.
- Deletion requestin support alanlarını policy'ye göre delete/anonymize/retain ettiğini doğrula.
- Eski backup'ı izole targeta restore et; güncel erasure journal olmadan cutover gate'i geçmemeli.
- Journal replay sonrası silinmiş subject, session, country, push ve orphan sonuçlarını doğrula.
- Production hesabı, gerçek support medyası veya canlı backup üzerinde test yapma.

### 10.5 Accessibility ve responsive

- Web/Android deletion request ile admin review ekranlarında keyboard, focus, screen reader ve 200% text kontrolü.
- Masked/reveal/impact/confirmation state'leri yalnız renkle anlatılmaz.
- Dar mobilde confirmation ve status metni kesilmez; destructive ana aksiyon yanlışlıkla birincil normal CTA gibi görünmez.
- TR/EN request/processing/completed/rejected/error metinleri teknik kod dökmeden doğru anlamı taşır.
## 11. Kanıt ve kabul eşlemesi

| Plan ref | Gerekli kanıt | Kapanış şartı |
|---|---|---|
| B-DATA-001 | Schema/data-class coverage, owner/duration/action, retention dry-run/execute fixture, backup ve admin access matrisi | Altı canonical kabul kriteri kanıtlı |
| B-DATA-002 | ISO model, source/status/freshness, strict backfill, own-country API, active-state/deletion ve privacy sonuçları | Sekiz canonical kabul kriteri kanıtlı |
| C-COMP-002 | Claim-code-policy mapping, processor/region evidence, ads gate, user deletion ve human review kaydı | Yedi canonical kabul kriteri kanıtlı |
| B-DATA-003 | Runtime revoke, policy step results, orphan/retained evidence, completion receipt ve idempotency sonuçları | Altı canonical kabul kriteri kanıtlı |
| C-TRUST-002 | Support DB/delivery ayrımı, duplicate/media, admin workflow, deletion evidence ve destructive re-auth | Altı canonical kabul kriteri kanıtlı |

Checkbox yalnız canonical kriter gerçek code/schema, otomatik test, staging rehearsal, gerekli insan review ve kullanıcı QA onayıyla kapandığında işaretlenir. Taslak retention matrisi, yalnız migration veya yalnız UI ekran görüntüsü stable ID'yi kapatmaz.

## 12. Riskler ve rollback

| Risk | Koruma | Rollback/durma davranışı |
|---|---|---|
| Retention süresi yanlış veri siler | Owner-approved version + dry-run + target threshold | Execute durur; veri değişmeden policy düzelt |
| Registry schema alanını kaçırır | information_schema/JSON/log/processor coverage CI | Release'i bloke et |
| Job iki instance'ta yarışır | Advisory lock + run id + cursor | İkinci runner no-op; partial run fail |
| Legal hold süresiz veri biriktirir | Reason/owner/expiry allowlist | Hold creation'ı reddet veya review'e al |
| Backup silinmiş hesabı geri getirir | Erasure journal + pre-cutover replay | Restore cutover'ını bloke et |
| Journal secret/subject açığa çıkar | HMAC key version + restricted encrypted artifact | Export/replay'i durdur, credential incident sürecini uygula |
| Legacy ülke yanlış normalize olur | Strict alias, conflict state, dry-run | Backfill'i iptal et; canonical row yazma |
| Provider failure eligible ülkeyi ezer | Freshness state machine | Mevcut policy-eligible değeri TTL sonuna kadar koru |
| Country KYC gibi sunulur | Explicit policy wording ve own-country response | Capability'yi kapat, metni düzelt |
| Client başka ülke enjekte eder | Server-only resolver/allowlist | Request'i ignore/reject; audit metric |
| Country UI erkenden açılır | Wave 08 capability/feature flag | Capability tüketimini kapat |
| Request session siler ama socket açık kalır | Wave 05 user-scoped runtime termination + expiry | Account write'larını server-side bloke et, cleanup retry |
| Deletion partial olup completed görünür | Step ledger + post-check gate | `failed_retryable`; completion yok |
| FK cascade başka kullanıcının verisini siler | Sentetik graph, impact preview, transaction counts | Production approval'u durdur; schema/policy düzelt |
| Retained evidence raw kimlik taşır | Column/JSON/snapshot scanner | Completion'ı bloke et; pseudonymize |
| Immutable audit erasure ile çakışır | Yeni minimum case ref + açık tarihsel migration kararı | Trigger'ı gizlice kapatma; owner review |
| Processing sonrası reactivation olur | State transition constraint/lock | Endpoint reddeder; operation devam/incident review |
| Support retry duplicate email/media üretir | submissionId + unique/idempotent delivery step | Duplicate delivery'yi durdur, tek case'e bağla |
| Processor bölgesi yanlış beyan edilir | Canlı panel/config + human evidence | Claim publish bloke |
| Dirty repo kullanıcı işini örter | Üç Git bağlamı snapshot ve küçük paketler | Yalnız Wave 06 farkını geri al |

## 13. Rollout ve canlı destructive sınır

Önerilen rollout sırası:

1. Registry, validators ve sentetik fixture'lar davranış değiştirmeden eklenir.
2. Additive schema migrationları local/izole test DB'sinde uygulanır.
3. Canonical country resolver read-only/shadow mode'da aggregate reason count üretir; client capability kapalıdır.
4. Retention runner yalnız dry-run ve sentetik staging execute ile doğrulanır.
5. Deletion request/runtime revoke yeni state machine'e compatibility flag ile bağlanır.
6. Deletion worker yalnız sentetik staging hesaplarda açılır; admin impact/re-auth ve journal export doğrulanır.
7. Privacy/Data Safety diff'i insan review alır; otomatik publish edilmez.
8. Restore-erasure rehearsal Wave 04 izole targetında tamamlanır.
9. Production rollout her feature/job için ayrı flag, metric ve rollback kapısıyla yapılır.

Bu belgenin hazırlanması aşağıdaki işlemlere yetki vermez; her biri exact target ve impact doğrulandıktan sonra ayrıca açık kullanıcı onayı ister:

- Production DB'de schema/data/PII/geo/deletion read query'si veya export
- Production migration/backfill/retention execute/account deletion/anonymization
- Gerçek kullanıcı session/socket/push/country/support/audit state değişikliği
- Backup oluşturma, indirme, restore, erasure replay veya artifact silme
- Render/Neon env, DB, scheduler, restart veya redeploy
- Firebase/Brevo/geo provider üzerinde data request/delete/config değişikliği
- Privacy, Terms, Data Safety veya store metni yayınlama
- HMAC/encryption key oluşturma/rotation veya secret erişimi

Canlı destructive rollback fiziksel silinen veriyi geri getirmeye dayanmaz. Koruma sırası dry-run, onaylı policy, güncel backup/erasure planı, küçük bounded batch, post-check ve stop threshold'dur. Şüphede job fail-closed durur.

## 14. Başlangıç kapısı

Bu kutular plan hazırlanırken işaretlenmez; yalnız Wave 06 gerçekten başlatılırken güncel kanıtla kapatılır:

- [ ] Wave 01–05 QA kapanışları ve kullanıcı onayı doğrulandı.
- [ ] Kullanıcı açıkça “Wave 06'yı başlat” talimatı verdi.
- [ ] Root, backend ve frontend Git status/remote/branch/commit snapshot'ı alındı.
- [ ] Wave 04 migration/backup/restore/runbook kapıları güncel repoda doğrulandı.
- [ ] Wave 05 runtime cleanup/presence lease kapıları güncel repoda doğrulandı.
- [ ] Gerçek schema/FK/JSON/log/process-memory/backup/processor envanteri read-only çıkarıldı.
- [ ] Privacy/legal/product/technical owner listesi ve karar yetkisi belirlendi.
- [ ] Retention süre/action/hold/backup kararlarının hiçbiri agent varsayımına bırakılmadı.
- [ ] Gerçek processor enablement/region/config doğrulama yöntemi belirlendi.
- [ ] Canonical country source/status/freshness ve legacy backfill policy'si owner tarafından onaylandı.
- [ ] Deletion state machine, point-of-no-return, retained evidence ve user messaging kararı kilitlendi.
- [ ] Sentetik staging DB/user graph ve izole restore hedefi hazırlandı.
- [ ] Production query/migration/backfill/execute/delete/publish işlemleri ayrı onay kapısına bağlandı.
- [ ] Wave 07 ve Wave 08 kapsamlarına taşma olmadığı doğrulandı.

## 15. Sonuç alanı

Wave 06 yürütülürse kapanış kaydı en az şunları içerir:

- Başlangıç/bitiş zamanı, Plan refs ve gerçek değişen dosyalar
- Üç Git bağlamının önce/sonra status/commit farkı
- Data-class registry versionı, schema coverage ve owner approval kaydı
- Her retention policy için dry-run/fixture execute/count/orphan/hold sonuçları
- Canonical country migration, ISO resolver, backfill aggregate/parity ve own-country contract kanıtı
- Privacy/Data Safety claim-code-policy-processor matrisi ve insan review sonucu
- Deletion state/step/idempotency/runtime revoke/delete-anonymize-retain/orphan kanıtı
- Minimum completed receipt ve processing/reject/reactivate transition sonuçları
- Support record/delivery/duplicate/media/owner/audit sonuçları
- Erasure journal export/hash ve eski backup staging replay sonucu
- Syntax/lint/build/encoding/focused/full test komutları ve exit code'ları
- Varsa ayrıca onaylanmış production işlemin exact target/impact/result/rollback kaydı
- Canonical checkbox ve durum değişiklikleri ile kullanıcı QA onayı
- Wave 07'nin başlatılmadığına dair açık durma kaydı

## 16. Durma kuralı

Wave 05 QA kapanışı ve kullanıcının açık Wave 06 başlatma talimatı birlikte gelene kadar:

- Wave 06 için kod, test, dependency, migration, data scan, backfill, retention, deletion, backup, config veya deploy değişikliği yapılmaz.
- Render/Neon/Firebase/Brevo/geo provider/store veya canlı kullanıcı verisi üzerinde hiçbir state değişikliği yapılmaz.
- Wave 06 `Aktif` işaretlenmez; bu belge yalnız `Hazır — aktif değil` durumunda kalır.
- Wave 07 uygulanmaz; hazırlanmış plan aktif edilmez.
