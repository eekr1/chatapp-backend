# TalkX Wave 12 Plan — Legal Reaccept, Session Recovery ve Hesap Yüzeyleri

> Bu belge yalnız Wave 12 için hazırlanmış uygulama planıdır.
> Canonical uygulama sırası Plan C `C-LEGAL-001` → Plan B `B-AUTH-002` → Plan A `A-AUTH-002` → Plan A `A-HOME-002` şeklindedir.
> Wave 06'nın `B-DATA-003/C-TRUST-002` hesap silme, destek ve retention sözleşmeleri bu Wave'de client yüzeylerinin doğruluk bağıdır; yeniden tasarlanmaz.
> Plan hazırdır. Wave 12 aktif değildir, Wave 01–11 kapanmamıştır ve uygulama başlamamıştır. Hazırlanmış Wave 13 Sistem inbox planı bu belge içinde aktif edilmez veya uygulanmaz.

## 1. Durum ve yürütme sınırı

- **Wave:** 12
- **Wave adı:** Legal reaccept, session recovery ve hesap yüzeyleri
- **Plan katılımı:** Plan C + Plan B + Plan A
- **Canonical sıra:** `C-LEGAL-001 → B-AUTH-002 → A-AUTH-002 → A-HOME-002`
- **Devreden sağlayıcılar:** Wave 04 `B-DB-001`; Wave 06 `B-DATA-001/B-DATA-003/C-COMP-002/C-TRUST-002`; Wave 03 auth/client foundation
- **Plan durumu:** Hazır
- **Wave durumu:** Bekliyor
- **Uygulama durumu:** Başlamadı
- **Uygulama yetkisi:** Verilmedi
- **Giriş kapısı:** Wave 11 **AUTO-VERIFIED / COMMITTED** ve kullanıcıdan açık “Wave 12'yi başlat” talimatı
- **Mevcut blokaj:** Wave 11 henüz committed değil; Wave 12 uygulanamaz
- **Önceki wave:** Wave 11 — planı hazır, aktif değil
- **Sonraki wave:** Wave 13 — planı hazır, aktif değil ve başlatılmadı

Bu dosyanın hazırlanması Wave 12 aktivasyonu, kod/test/dependency değişikliği, migration, production legal publish, reaccept zorlaması, gerçek hesap silme/destek işlemi, session invalidation, canlı veri sorgusu, deploy veya Wave 13 uygulaması için yetki değildir.

## 1.1 Sale Release override — KÜÇÜLTÜLMÜŞ

- **Satış öncesi uygulanır:** Session-expired/recovery UX, account settings, deletion/support akışı ve gerekli legal acceptance/version davranışı.
- **Post-acquisition Roadmap / Deferred:** Gelişmiş legal publishing/workflow sistemi, CMS benzeri legal yönetim ve satış öncesi gerekmeyen hesap özellikleri.
- **Canlı sınır:** Production legal publish veya gerçek kullanıcı hesabı silme ayrıca açık yetki ister.
- **Kapanış:** Focused auth/account/legal otomatik testleri ve build geçer, tek Wave 12 commit'i alınır ve **DUR**. Manuel/legal human review Checkpoint B/Wave 19'a gider.

## 2. Canonical referanslar ve otorite

1. `C-LEGAL-001` — QA-013 güvenli, sürümlü yasal yayın merkezi
2. `B-AUTH-002` — published legal sürüm ve atomik/idempotent kabul sözleşmesi
3. `A-AUTH-002` — legal reaccept ile auth/reconnect/session recovery ayrımı
4. `A-HOME-002` — ayarlar, destek, izin ve hesap silme kullanıcı yüzeyleri
5. Master `QA-013` — yayın özeti, tek belge editörü, TR/EN, preview, draft, diff, impact, publish, history, rollback ve erişilebilirlik
6. Wave 04 `B-DB-001` — sürümlü migration, transaction ve backup/restore kapısı
7. Wave 06 `B-DATA-001/B-DATA-003/C-COMP-002/C-TRUST-002` — retention, deletion, support ve legal acceptance veri amacı
8. Wave 03 auth foundation — güvenli hata dili, olmayan recovery vaadini vermeme ve session sona ermesi semantiği
9. `A-I18N-001/A-A11Y-001/A-MOB-001` — ortak TR/EN, erişilebilirlik ve Web/Android eşliği

Çelişki çözümü:

- Canlı yasal içerik yalnız published snapshot'tır; draft kaydı public API'yi veya required version değerlerini değiştirmez.
- Admin preview ile kullanıcının gördüğü `LegalScreen` aynı sanitize/render sözleşmesini tüketir.
- Reaccept gereksinimini client tahmin etmez; backend published release ile kullanıcının kabul kaydını karşılaştırır.
- Legal status bilinmiyorsa bu durum “kabul tamam” sayılmaz; geçerli session silinmeden güvenli recovery sunulur.
- Terms/Privacy maddi değişikliğinde version/reaccept politikası owner kararıdır. Agent hukuki sınıf, sürüm veya içerik uydurmaz.
- Child Safety'nin ayrıca kullanıcı kabulü gerektirip gerektirmediği policy owner tarafından kilitlenmeden kabul modeline sessizce eklenmez.
- Hesap silmenin tamamlanması ile silme talebinin alınması aynı sonuç değildir. Client backend state'inden ileri bir sonuç göstermez.
- Wave 13 Sistem inbox, Wave 14 analytics ve genel admin kabuk yeniden tasarımı bu Wave'e çekilmez.

## 3. Wave sonucu

Wave 12 sonunda:

- Yasal içerik tek mutable JSON yerine draft ve immutable published snapshot geçmişiyle yönetilecek.
- Admin varsayılanında üç belgenin yayın/taslak/eksik/uyarı durumu ve ana risk beş saniyede anlaşılacak.
- Bir seferde yalnız seçilen belge düzenlenecek; TR/EN, gerçek son kullanıcı önizlemesi, dirty state ve alan bazlı validation bulunacak.
- “Taslağı kaydet” canlı içeriğe dokunmayacak; “Yayınla” diff, değişiklik sınıfı, gerekçe, reaccept etkisi, re-auth ve açık onay isteyecek.
- Eşzamanlı editör stale revision ile yeni yayını ezemeyecek.
- Her yayın content hash, revision, admin, gerekçe, önceki yayın bağı ve audit ile atomik snapshot oluşturacak.
- Rollback geçmişi overwrite etmeyecek; eski snapshot'tan yeni ve denetlenebilir bir yayın oluşturacak.
- Public API, admin preview, kayıt kabul metni, `LegalScreen` ve reaccept yüzeyi aynı published release kimliğini gösterecek.
- Backend required/accepted state'i belge ve sürüm bazında açık taşıyacak; aynı kabul retry'si duplicate anlam üretmeyecek.
- Yayın ile kabul yarışında acceptance yalnız gördüğü güncel release/sürüme bağlanacak; stale kabul başarı sayılmayacak.
- 401 session sonu, 428 legal reaccept, offline/timeout, 5xx ve pending-deletion birbirinden ayrılacak.
- Legal status alınamadığında kullanıcı sessizce korunan akışa geçirilmeyecek veya geçerli session'dan gereksiz çıkarılmayacak.
- Reaccept ekranı gerçek TR/EN published içeriği ve sonraki adımı gösterecek; başarısız kabul başarılı görünmeyecek.
- Ayarlar, destek, izin ve hesap silme yüzeyleri Wave 06 backend sonuçlarını dürüst, accessible ve Web/Android eşdeğer biçimde sunacak.
- Hesap silme normal ayar gibi görünmeyecek; `request received`, `pending`, `completed/rejected` sonuçları birbirine karışmayacak.
- Wave 13 başlamayacak.

## 4. Doğrulanmış başlangıç fotoğrafı

### 4.1 Yasal içerik ve admin

- `app_settings` içindeki `legal_content_v1` bugün footer, Terms, Privacy ve Child Safety TR/EN içeriğini tek JSON kaydında tutuyor.
- `PUT /admin/legal` bütün payload'ı doğrulayıp aynı canlı kaydı upsert ile anında değiştiriyor.
- Mevcut admin ekranı altı uzun textarea ve çok sayıda alanı tek formda açıyor; draft, publish approval, diff, history, rollback ve optimistic concurrency yok.
- Mevcut `LEGAL_UPDATE` audit'i version ve updatedAt taşıyor; belge/dil/alan diff'i, previous hash, gerekçe ve immutable publish kimliği yok.
- Placeholder kontrolü admin uyarısı olabilir; backend publish block'u olduğu kanıtlanmış değil.
- `/api/legal` aynı mutable kaydı public olarak dönüyor; published/draft ayrımı veya release identity yok.

### 4.2 Acceptance ve reaccept

- `legal_acceptances` kullanıcı, Terms/Privacy version, acceptedAt, IP, UA ve Wave 06 geo snapshot alanlarını taşıyor.
- `calculateLegalStatus` son acceptance satırını current settings version'larıyla karşılaştırıp `requiresReaccept` üretiyor.
- `POST /api/me/legal-accept` submitted version'ları current required değerlerle eşitler, sonra yeni acceptance satırı ekler.
- Aynı kabul retry'sinin unique/idempotent constraint'i görünmüyor; duplicate satır ve belirsiz request sonucu riski var.
- Status ile accept arasındaki yayın yarışı yalnız version string eşitliğiyle ele alınıyor; release revision/hash bağı yok.
- Friends, profile, push ve support gibi korunan yüzeyler 428 `LEGAL_REACCEPT_REQUIRED` üretebiliyor; middleware uygulaması dağınık doğrulanmalı.
- Geo/IP/UA kabul anı kanıtıdır; canonical matchmaking country değildir.

### 4.3 Client ve session recovery

- `refreshLegalStatus` hata aldığında `false` dönebiliyor; çağıran akış bunu “reaccept gerekmiyor” gibi yorumlayıp friends yüklemeye devam edebilir.
- `checkAuth` geniş catch içinde token'ı kaldırıyor; network/5xx ile gerçek 401 ayrımı yapılmadan geçerli session kaybedilebilir.
- Reaccept modalı required Terms/Privacy version metni, iki link, logout ve accept aksiyonu sunuyor; actual published release/content identity ve recovery durumları sınırlı.
- Accept response doğrulanmadan client local accepted timestamp oluşturuyor; ardından status/release reconciliation yok.
- Web ve Android aynı React yüzeyini tüketse de offline, process recreation, deep-link, hardware back ve stale bundle davranışları ayrıca kanıtlanmalı.

### 4.4 Ayarlar, destek ve hesap silme

- `HomeScreen` içinde profil, şifre, dil, izin, destek ve hesap silme yüzeyleri birlikte bulunuyor.
- Destek formu subject, açıklama, opsiyonel email/media ve auto metadata topluyor; Wave 06 C-TRUST-002 idempotency/retention sonucu client ile yeniden doğrulanmalı.
- Hesap silme isteği current password ve confirmation text ister; backend kullanıcıyı `pending_deletion` yapıp session'ları transaction içinde siliyor.
- Tekrarlanan açık deletion request'i yeni kayıt yerine mevcut talebi kullanabiliyor; client sonucu “hesap tamamen silindi” olarak anlatmamalı.
- İzin onboarding'i atlanabiliyor; reddedilen izin ana uygulamayı kilitlememeli.
- Legal ve hesap silme deep-link/geri dönüş davranışı Web/Android'de henüz uçtan uca kanıtlı değil.

### 4.5 Repo ve canlı sınır

- Root/backend/frontend geniş ve kullanıcıya ait değişiklikler taşıyabilir; uygulama başında üç Git bağlamı ayrı snapshot edilir.
- Plan aşamasında production legal content, acceptance, IP/UA/geo, session, support veya deletion request verisi okunmaz/export edilmez.
- Migration, publish, rollback, session invalidation, gerçek hesap silme ve support mutation ayrıca exact-target/impact onayı ister.

## 5. Legal domain modeli

### 5.1 Ayrık varlıklar

Minimum kavramsal ayrım:

- `legal_document`: `privacy | terms | child_safety`; belge kimliği ve policy sahipliği
- `legal_draft`: document, locale, title/content, baseRevision, editor, updatedAt; public değildir
- `legal_publication`: immutable publish olayı, releaseId/revision, actor, reason, changeClass, previousPublicationId, publishedAt
- `legal_publication_content`: publication + document + locale + title/content + contentHash
- `legal_release_manifest`: current published document/revision/version haritası ve public checksum
- `legal_acceptance`: user + required document versions/release identity + acceptedAt + kanıt snapshot'ları
- `legal_footer_settings`: seyrek değişen link/etiketler; belge draft'ından ayrıdır ancak yayın/validation/audit kapısı taşır

Tablo isimleri uygulama keşfinde değişebilir; anlamlar bir mutable blob içinde tekrar birleştirilmez. Existing `legal_content_v1` compatibility/read modeli additive migration boyunca korunabilir.

### 5.2 Belge, sürüm ve release ayrımı

- `documentVersion`: kabul semantiği olan Terms/Privacy policy version'ı
- `contentRevision`: yazım/format dahil her published snapshot'ın monoton revision'ı
- `releaseId`: aynı atomik yayında kullanıcıya sunulan manifest kimliği
- `contentHash`: tam normalize edilmiş published title/body'nin bütünlük kanıtı
- `changeClass`: yazım/format, açıklama veya maddi hukuki değişiklik; yetkili admin seçer ve policy doğrular

Version string tek başına content identity değildir. Aynı version ile izinli non-material düzeltme varsa yeni contentRevision/publication oluşur; gerekçe ve audit korunur. Maddi değişiklikte aynı version'a yayın policy izin vermiyorsa backend block eder.

### 5.3 State modeli

Draft:

- `clean → editing → dirty → saving → saved`
- `saving → validation_error | conflict | save_failed`
- `saved → preview_ready → publish_review`

Publish:

- `publish_review → impact_loading → confirmation_ready → publishing`
- `publishing → published | conflict | verification_failed | publish_failed`

Client legal gate:

- `unknown → checking`
- `checking → accepted | reaccept_required | offline | recoverable_error | unauthenticated | account_restricted`
- `reaccept_required → loading_content → ready → accepting`
- `accepting → accepted | version_conflict | failed`

Unknown/error hiçbir zaman accepted'a otomatik dönüşmez. State, requestId/releaseId/revision ile stale response'lardan korunur.

## 6. Draft ve editör sözleşmesi

### 6.1 Yayın özeti

Varsayılan admin ekranı editör değil sakin yayın özetidir:

- Gizlilik Politikası, Kullanım Şartları, Çocuk Güvenliği ve Footer/Linkler kartları
- Published/Taslak/Eksik/Uyarı durumu yalnız renkle değil text/icon ile
- Current documentVersion/contentRevision, son yayın zamanı ve actor
- TR/EN tamlığı, unpublished draft ve validation riski
- Bekleyen reaccept etkisi yalnız hesaplanmışsa source/time ile
- `Düzenle`, `Geçmiş`, `Kanıtı gör` progressive disclosure aksiyonları

Ham JSON, audit payload veya tüm uzun içerikler ilk görünümde açılmaz.

### 6.2 Tek belge editörü

- Aynı anda yalnız bir document/footer alanı düzenlenir.
- TR/EN masaüstünde kontrollü karşılaştırma, dar ekranda accessible tabs kullanır.
- Title, body, version ve status bağlamı görünür; footer alanları belge editörüne karışmaz.
- Field-level required/limit/URL/placeholder/sanitize hataları alan yanında gösterilir.
- Karakter sayacı canonical backend limitinden gelir; client limiti tek otorite değildir.
- Uzun metin okunabilir ölçü, search ve kontrollü fullscreen edit sunabilir; altı bağımsız iç scroll üretmez.
- Dirty state route/tab/browser leave öncesi açık confirmation verir.
- Keyboard shortcut varsa yalnız draft save yapar; canlı publish tetiklemez.

### 6.3 Draft persistence ve concurrency

- Save payload document, locale content map, baseRevision ve commandId taşır.
- Draft save yalnız draft store'u değiştirir; current publication/reaccept etkilenmez.
- Aynı commandId retry aynı draft revision sonucunu döndürür.
- Stale baseRevision `409 LEGAL_DRAFT_CONFLICT` ve current revision özeti döndürür; silent last-write-wins yoktur.
- Autosave uygulanırsa explicit state, debounce, conflict ve failure görünür; kullanıcıya kaydedildi yalanı söylenmez.
- Bir belgenin save hatası diğer belge/footer draft'ını kaybettirmez.

## 7. İçerik formatı, validation ve preview

### 7.1 Tek render sözleşmesi

Düz metin, Markdown veya güvenli rich text seçeneklerinden biri mevcut içerik ve bakım riskiyle owner tarafından kilitlenir. Admin preview, public `/api/legal`, `LegalScreen`, kayıt kabulü ve reaccept aynı parser/sanitizer/version paketini tüketir.

- Script, event handler, iframe ve aktif HTML çalışmaz.
- `javascript:` ve izin verilmeyen link protocol/host davranışı reddedilir.
- External link target/rel ve uygulama içi route ayrımı açık olur.
- Headings, paragraphs, lists, links ve uzun kesintisiz text aynı görünür.
- Sanitizer versiyonu yayın snapshot'ında izlenebilir; renderer değişimi regresyon QA ister.

### 7.2 Publish-blocking validation

- Privacy, Terms ve Child Safety için gerekli TR/EN title/body
- Footer TR/EN labels/tagline ve izinli URL
- Backend canonical length limitleri; mevcut 30 bin karakter sınırı dahil
- Placeholder/template token taraması
- Güvensiz markup/URL
- Normalize sonrası boş veya yalnız whitespace içerik
- Duplicate/geriye giden/geçersiz version policy
- Maddi değişiklik + unutulmuş version/reaccept çelişkisi
- Preview/render failure

TR/EN anlamsal eşdeğerlik otomatik “hukuken doğru” diye onaylanmaz. Otomasyon yalnız uyarı/kanıt üretir; gerekli legal/content owner kararı kaydedilir.

### 7.3 Son kullanıcı önizlemesi

- Document + locale + desktop/mobile viewport seçimi
- Gerçek `LegalScreen` component/render sözleşmesi
- Published ile draft farkı açık label
- Footer link ve görünen etiket birlikte test
- 320 px, large text, zoom, keyboard ve screen reader
- Preview production recipient, acceptance veya public publish üretmez

## 8. Diff, etki hesabı ve yayın onayı

### 8.1 Diff ve değişiklik sınıfı

Publish review şunları gösterir:

- belge ve diller
- title/body/version/footer alan bazlı added/removed/changed özeti
- current publication → candidate draft revision
- normalized content hash değişimi
- admin changeClass ve zorunlu bounded gerekçe
- owner/reviewer gereksinimi

Diff hassas olmayan admin içeriğidir fakat audit ve erişim sınırı taşır. HTML injection üretmeden render edilir; çok uzun diff progressive disclosure kullanır.

### 8.2 Reaccept etki hesabı

Backend candidate manifest için:

- current ve proposed Terms/Privacy versions
- hangi değişikliğin reaccept tetikleyeceği
- etkilenen hesap sayısı tahmini
- query source/version, calculatedAt ve veri gecikmesi
- etkilenen protected flow listesi
- Child Safety/notification politikasının açık sonucu

Sayı yaklaşık ise “kesin” gösterilmez. Estimate sorgusu publish transaction'ının garantisi değildir; confirmation anında revision değişirse yeniden hesaplanır.

### 8.3 Destructive confirmation

Publish öncesi:

- admin re-auth/yetki
- candidate revision'ın hâlâ current olması
- belge/dil/version ve etki özeti
- geri alınamayan kullanıcı acceptance geçmişi uyarısı
- rollback'in yeni yayın oluşturacağı bilgisi
- actor, reason ve commandId

Loading sırasında duplicate publish engellenir. Preview veya draft-save permission'ı publish permission'ı değildir.

## 9. Atomik publish, public okuma ve rollback

### 9.1 Publish transaction

Tek transaction veya eşdeğer atomik sınır:

1. Current publication/manifest row lock veya compare-and-set ile doğrulanır.
2. Draft revision ve validation sonucu yeniden kontrol edilir.
3. Immutable publication ve locale content snapshot'ları yazılır.
4. Required version/reaccept manifesti yazılır.
5. Current published pointer değiştirilir.
6. Audit actor/reason/diff hash/previous link ile yazılır.
7. Idempotency command sonucu kaydedilir.
8. Commit sonrası cache invalidation/public verification tetiklenir.

DB commit olmadan public pointer değişmez. Audit yazılamıyorsa publish başarı sayılmaz. Cache verification hatası DB publish'i geri alınmış gibi anlatılmaz; `published_verification_pending/failed` sonucu ve güvenli aksiyon döner.

### 9.2 Public API sözleşmesi

Public response en az:

- releaseId/contentRevision/updatedAt
- published documentVersion haritası
- locale document title/body veya sürümlü content map
- footer labels/allowlisted links
- cache validator (`ETag`/checksum) ve açık cache policy
- safe fallback/unsupported locale sonucu

Draft asla public response'a karışmaz. Eski client contract'ı migration sırasında compatibility adapter ile beslenebilir; adapter yalnız current published manifestten üretir. DB/read error default metni “güncel published içerik” gibi sessizce sunmaz.

### 9.3 History ve rollback

- History publicationId, versions, hashes, actor, reason, time ve previous link taşır.
- Yetkili admin o tarihte sunulan exact TR/EN snapshot'ı görebilir.
- Karşılaştırma iki immutable publication arasında yapılır.
- Rollback seçilen snapshot'tan yeni draft/candidate üretir; eski satırı current yaparak geçmişi silmez.
- Rollback normal validation, impact, re-auth, approval ve atomic publish kapılarından geçer.
- Daha eski Terms/Privacy version'a dönüşün acceptance semantiği policy kararı olmadan yayınlanmaz.

## 10. B-AUTH-002 — Acceptance backend sözleşmesi

### 10.1 Status response

Authenticated legal status en az:

- current `releaseId` ve server revision
- required Terms/Privacy documentVersion değerleri
- accepted versions, acceptedAt ve bağlı publication/release identity
- `requiresReaccept`
- reason: missing acceptance, terms changed, privacy changed, multiple
- display locale ve published content refs
- `checkedAt`

Client version farkını kendi hesaplamaz. Child Safety acceptance kapsamı owner kararı açık değilse required map'e eklenmez.

### 10.2 Atomik ve idempotent kabul

Accept command:

- authenticated user/session
- expected releaseId/revision
- exact required version map
- commandId/idempotency key
- kullanıcı aksiyonu ve locale

Server transaction'da current published manifesti yeniden okur. Expected release/version stale ise acceptance yazmadan `LEGAL_VERSION_MISMATCH` ve yeni required state döndürür. Aynı user + aynı requirement set/command retry aynı acceptance sonucunu verir; duplicate semantic event/audit üretmez.

Acceptance record yayın snapshot'ına geri izlenebilir olmalıdır. IP/UA/geo yalnız Wave 06 veri amacı, retention ve erişim politikasıyla tutulur; tam değer normal response/log/analytics'e çıkmaz.

### 10.3 Protected flow gate

Ortak middleware/policy şu ayrımı korur:

- valid session + accepted current release → devam
- valid session + reaccept required → 428 stable code + required state
- invalid/expired/revoked session → 401; 428 değildir
- pending deletion/inactive/ban → kendi stable account code'u
- legal config/read failure → recoverable service error; accepted varsayılmaz

Profile, friends, push, support ve WebSocket protected event kapsamı envanterlenir. Endpointler farklı shape veya sessiz bypass üretmez. Public legal fetch ve logout reaccept gate arkasında kalmaz.
### 10.4 Yayın-kabul yarışları

| Yarış | Otorite | Sonuç |
|---|---|---|
| Status alındı, sonra yeni publish oldu | Current manifest | Eski accept reddedilir; yeni release gösterilir |
| Accept commit oldu, sonra publish oldu | Commit anındaki release | Yeni publish policy'ye göre tekrar reaccept üretir |
| İki cihaz aynı accept'i gönderdi | Unique requirement identity | Tek semantic acceptance, aynı başarılı sonuç |
| Response kayboldu, client retry yaptı | commandId/requirement fingerprint | Mevcut acceptance replay edilir |
| Rollback daha eski metni aday yaptı | Yeni publication policy | Eski acceptance sessizce geçerli sayılmaz |
| Status service hata verdi | Unknown/recoverable | Protected flow açılmaz, session silinmez |

## 11. A-AUTH-002 — Reaccept ve session recovery UX

### 11.1 Client auth/legal state sınırı

Client tek boolean yerine en az şu gerçeği taşır:

- auth: `unknown | unauthenticated | authenticated | expired | restricted`
- legal: `unknown | checking | required | accepting | accepted | unavailable | conflict`
- connectivity: `online | offline | reconnecting`
- published release identity ve request revision

Bu state'ler birbirine dönüştürülmez. Network hatası logout değildir; 428 token expiry değildir; modalı kapatmak acceptance değildir.

### 11.2 Boot ve login akışı

1. Token yoksa unauthenticated Auth ekranı.
2. Token varsa session/profile doğrulaması.
3. 401 ise local session state güvenle temizlenir ve login'e dönülür.
4. Auth başarılıysa legal status current server release ile kontrol edilir.
5. Accepted ise Home/protected hydration başlar.
6. Required ise reaccept gate açılır; protected fetchler başlatılmaz veya 428 loop'a sokulmaz.
7. Offline/5xx ise recovery yüzeyi açılır; token korunur, güvenli retry sunulur.
8. Pending deletion/restricted ise kendi hesap sonucu gösterilir; reaccept ekranına yanlış düşmez.

Friends/profile/push isteklerinden rastgele gelen 428 tek merkezi legal state'e normalize edilir. Aynı modal veya accept request'i tekrar tekrar üretilmez.

### 11.3 Reaccept yüzeyi

Mevcut TalkX glass/neon temasını bozmayan odaklı modal/full-screen gate:

- Başlık: sözleşmelerin güncellendiği ve neden tekrar onay gerektiği
- Terms/Privacy hangi version/revision ile değişti
- TR/EN gerçek published içerik veya aynı release'e bağlı accessible document view
- Değişiklik özeti yalnız backend yayın verisi sağlıyorsa; client uydurmaz
- Primary `Kabul et`, secondary `Çıkış yap`
- Content loading, unavailable, offline, stale release, accepting, success ve error durumları
- Long text için içerik içinde kontrollü okuma; aksiyonlar içeriği kapatmayan sticky bölgede
- Focus trap, initial focus, Escape/back policy, screen reader title/description ve 44 px hedefler

Kabul CTA'sı current published belge yüklenmeden veya required identity eksikken aktif olmaz. Link açıp geri dönmek kabul değildir.

### 11.4 Accept sonucu ve recovery

- Submit sırasında tek commandId kullanılır; double click disabled.
- Başarı response'undaki accepted release/version değerleri state'e yazılır; client kendi timestamp'ını canonical kanıt diye üretmez.
- Ardından status reconciliation aynı accepted sonucu doğrular veya server response zaten authoritative status taşır.
- Version conflict yeni içeriği yükler, kullanıcıya “metin güncellendi” der ve yeniden açık seçim ister.
- Network timeout sonucu unknown ise status sorgulanır; kör ikinci acceptance gönderilmez.
- Başarı sonrası kullanıcı önceki güvenli hedefe döner; stale protected request kontrollü bir kez yeniden denenir.
- Kabul başarısızsa modal kapanmaz, toast tek kanıt değildir ve logout zorlanmaz.

### 11.5 Web/Android session recovery

- Browser refresh ve Android process recreation current status'u serverdan tekrar alır.
- Offline launch cached content varsa açıkça “son indirilen kopya” der; yeni kabul göndermeye yetmez.
- Android hardware back reaccept gate'i bypass etmez; açık document view'dan gate'e döner.
- Deep-link protected hedefe geldiyse auth/legal kapıları tamamlandıktan sonra bir kez devam eder.
- Background/foreground stale release'i yeniden doğrular; loop veya content flicker üretmez.
- Multi-device: bir cihazın kabulü diğer cihazda next status/reconnect ile accepted olur; local tahmin yok.

## 12. A-HOME-002 — Ayarlar ve hesap yüzeyleri

### 12.1 Bilgi mimarisi

Home/Ayarlar içinde:

- Profil ve görünür ad
- Güvenlik/şifre ve session sonucu
- Dil
- Bildirim/medya izin durumu
- Destek
- Legal documents/current accepted versions
- Ayrı `Tehlikeli alan` içinde hesap silme

Hesap silme normal toggle veya profil alanıyla aynı görsel ağırlıkta sunulmaz. Dar ekranda modal/sheet safe-area, keyboard resize ve scroll ile erişilebilir kalır.

### 12.2 Destek yüzeyi

Wave 06 `C-TRUST-002` sonucu tüketilir:

- Subject, açıklama, opsiyonel reply email ve media limitleri backend capability ile uyumlu
- Client minimum/maximum validation yalnız erken feedback; server otorite
- File type/size/count ve privacy/auto metadata açık
- `received`, `queued`, `delivery_failed`, `duplicate`, `validation_error` ayrımı
- API kaydı başarısı email/Brevo teslim başarısı gibi anlatılmaz
- Aynı submit retry commandId ile duplicate report üretmez
- Loading sırasında double submit yok; error state form içeriğini sessizce kaybetmez
- Hassas media preview/object URL temizliği ve permission denied sonucu Wave 11 ile uyumlu
- Modal focus, close, Escape/back ve unsaved description confirmation

Wave 12 support backend mimarisini yeniden açmaz; Wave 06 kanıtı eksikse A-HOME-002 kapanmaz.

### 12.3 İzin yüzeyi

- Notification/camera/gallery durumları ayrı ve server özelliğiyle ilişkili anlatılır.
- Denied, limited, unavailable, askable ve granted state'leri platform capability'den gelir.
- “Şimdi değil” uygulamayı kilitlemez.
- Ayarlara git CTA'sı yalnız native bridge destekliyorsa sunulur.
- Permission verilmesi upload/push başarısı gibi gösterilmez.
- Web/Android farklı sistem ekranları aynı user-facing sonuç semantiğine normalize edilir.

### 12.4 Hesap silme talebi

Akış:

1. Tehlikeli alan açıklaması hesap silme talebi ile hemen hard-delete farkını anlatır.
2. Etkilenecek session ve erişim sonucu; retained/anonymized kanıt için privacy açıklaması gösterilir.
3. Current password/re-auth ve exact confirmation text backend capability'den gelir.
4. Hedef kullanıcı yalnız current self; client user id göndererek hedef seçmez.
5. Submit commandId ile idempotenttir; retry ikinci açık request üretmez.
6. Backend `request_received/pending_deletion` dönerse client yalnız bunu gösterir.
7. Server session'ları kapattıktan sonra local token, socket, queue, active chat, outbox, push/local sensitive cache güvenli sırayla temizlenir.
8. `completed`, `rejected`, `reactivated` yalnız doğrulanmış backend/admin state ile anlatılır.

Browser confirm prompt tek erişilebilirlik/kanıt katmanı değildir. Confirmation modalı title, consequence, password, exact text, loading, field error ve persistent result taşır.

### 12.5 Client state temizliği

Deletion request başarı sonrası:

- WebSocket kapatılır; reconnect timer yeniden auth denemez.
- Match queue/pending offer/chat/friend state ve memory outbox temizlenir.
- Session token ve kullanıcıya bağlı local cache silinir.
- Push token server deregistration sonucu mevcutsa kaydedilir; başarısız ağ çağrısı hard-block yaratmaz, server-side deletion policy devam eder.
- Başka kullanıcının aynı cihazda login'i önceki user state'ini görmez.
- Legal informational routes ve support/deletion sonucu için policy-approved signed-out erişim korunur.

Tamamlanmamış request “tüm veriler silindi” toast'ı üretmez.

## 13. Hata ve sonuç sözleşmesi

### 13.1 Legal/admin kodları

- `LEGAL_DRAFT_VALIDATION_FAILED`
- `LEGAL_DRAFT_CONFLICT`
- `LEGAL_PREVIEW_FAILED`
- `LEGAL_PUBLISH_REAUTH_REQUIRED`
- `LEGAL_PUBLISH_IMPACT_STALE`
- `LEGAL_PUBLISH_CONFLICT`
- `LEGAL_PUBLISH_FAILED`
- `LEGAL_PUBLIC_VERIFICATION_FAILED`
- `LEGAL_ROLLBACK_POLICY_REQUIRED`

### 13.2 Auth/client kodları

- `LEGAL_REACCEPT_REQUIRED`
- `LEGAL_VERSION_MISMATCH`
- `LEGAL_STATUS_UNAVAILABLE`
- `LEGAL_ACCEPT_IN_PROGRESS`
- `SESSION_EXPIRED`
- `SESSION_REVOKED`
- `ACCOUNT_PENDING_DELETION`
- `ACCOUNT_INACTIVE`
- `DELETE_REQUEST_ALREADY_PENDING`
- `SUPPORT_DUPLICATE`

İsimler uygulamadaki stable error registry ile kesinleştirilir. Her sonuç `code`, user-safe message key, retryable, requestId/commandId ve gerekiyorsa current release/account state taşır. Client raw backend message'i doğrudan göstermeden TR/EN eyleme dönük metne çevirir.

### 13.3 HTTP ve retry semantiği

- 400/422: field validation; otomatik retry yok
- 401: session invalid/expired; auth recovery
- 403: yetki/account restriction; legal reaccept diye gösterilmez
- 409: stale revision/idempotency conflict; current state fetch
- 428: valid session fakat legal reaccept gerekli
- 429: rate limit; bounded retry-after
- 5xx/network: sonucu bilinmiyor olabilir; status/reconciliation

Write endpointlerinde kör retry yerine commandId ve status/read-back kullanılır.

## 14. Güvenlik, privacy ve audit

### 14.1 Admin ve publish güvenliği

- Admin read/edit/publish/history/rollback yetkileri ayrılabilir.
- Publish ve rollback re-auth, CSRF koruması, target/impact summary ve audit ister.
- Draft veya diff içinde script/HTML execution yoktur.
- Public link allowlist ve SSRF/open redirect riski doğrulanır.
- Concurrent edit/publish CAS ile korunur.
- Audit başarısızsa destructive publish tamamlanmaz.
- Rate limit büyük preview/diff/impact sorgularını korur.

### 14.2 Acceptance privacy

- IP/UA/geo normal admin özetinde veya telemetry'de açık değildir.
- Geo acceptance-time historical snapshot'tır; Global/Kendi Ülkem eşleşme ülkesi değildir.
- Data purpose, retention, erasure/pseudonymization ve access Wave 06 registry'dedir.
- Acceptance body, password, session token ve legal full text structured log'a yazılmaz.
- Published content hash bütünlük kanıtıdır; kullanıcı fingerprint'i değildir.

### 14.3 Audit olayları

- draft created/updated/conflict
- preview generated/failed
- publish review/confirmed/succeeded/verification failed
- rollback candidate/published
- acceptance succeeded/replayed/conflicted
- account deletion requested/already pending
- support submitted/duplicate/result

Audit actor, target, reason, time, commandId ve before/after identity taşır; password/token/full IP/full UA/support body/legal body kopyası taşımaz. Immutable legal snapshot gerektiğinde body'nin canonical kaynağıdır.

## 15. Cache, dağıtım ve eski client uyumu

- Public legal response release-aware `ETag` veya checksum ile cache edilebilir; draft cache'e girmez.
- Publish sonrası cache invalidation failure ayrı verification state üretir.
- Reaccept status cache'i user-specific ve `no-store` olmalıdır.
- Service worker/WebView cache eski release'i current diye göstermemeli; offline kopya açık etiketli olmalıdır.
- Eski client yalnız version map bekliyorsa additive adapter current manifestten aynı alanları üretir.
- Yeni required alan eski client'ı 428 loop'a sokacaksa min-supported-release/compatibility kararı publish öncesi impact'te görünür.
- Backend/frontend deploy sırası additive şema → dual-read → new write → client rollout → legacy cleanup biçimindedir.
- Legacy `legal_content_v1` kaldırma bu Wave içinde ancak kullanım sıfır ve rollback kanıtı varsa; aksi hâlde deprecation kaydıyla kalır.

## 16. Dosya ve servis etki haritası

Uygulama başlangıcında güncel keşifle daraltılacak beklenen yüzey:

- `chatapp-backend/db.js` — sürümlü legal draft/publication/manifest/acceptance idempotency migration'ı
- `chatapp-backend/utils/legalContent.js` — normalize, validation, renderer contract ve compatibility
- `chatapp-backend/utils/legalAcceptance.js` — release-aware status/acceptance hesabı
- `chatapp-backend/admin.js` — draft/preview/impact/publish/history/rollback API, re-auth ve audit
- `chatapp-backend/admin.html` veya ayrıştırılmış legal admin componentleri — QA-013 bilgi mimarisi
- `chatapp-backend/routes/profile.js` — status/accept, deletion request ve account state
- `chatapp-backend/routes/auth.js` — registration acceptance ve session result
- `chatapp-backend/index.js` — public legal endpoint ve ortak middleware wiring
- `chatapp-backend/routes/friends.js`, `push.js`, `support.js` — ortak legal gate regresyonu
- Backend migration, unit, integration, concurrency ve API contract testleri
- `chatapp-frontend/src/App.jsx` — auth/legal/connectivity state machine ve gate
- `chatapp-frontend/src/api.js` — stable status/accept/deletion/support contractları
- `chatapp-frontend/src/screens/LegalScreen.jsx` — release-aware ortak published renderer
- `chatapp-frontend/src/components/Auth.jsx` — registration published version kabulü
- `chatapp-frontend/src/screens/HomeScreen.jsx` — settings/support/permission/deletion UX
- `chatapp-frontend/src/i18n/messages.tr.js` ve `messages.en.js`
- `chatapp-frontend/src/index.css` — mevcut temada responsive/a11y legal ve account yüzeyleri
- Web/Android E2E, deep-link, offline ve visual QA fixtures

Genel admin navigation/dashboard redesign veya auth mimarisinin Wave 12 dışı geniş refactor'ı yapılmaz.

## 17. Uygulama sırası

1. Wave 11 kapanışını, üç Git bağlamını ve gerçek legal/auth/account flow'unu doğrula.
2. Wave 04 migration ve Wave 06 retention/deletion/support sözleşmelerini kanıtla.
3. Legal content formatı, document/version/release identity, Child Safety acceptance politikası ve owner/yetki matrisini kilitle.
4. Additive draft/publication/manifest/audit/idempotency şemasını izole DB'de test-first kur.
5. Legacy `legal_content_v1` backfill, dual-read ve rollback stratejisini doğrula.
6. Draft save, field validation, preview ve optimistic concurrency API'lerini tamamla.
7. Diff, changeClass, impact estimate, re-auth ve atomic publish transaction'ını tamamla.
8. History/compare/rollback-as-new-publication ve public verification'ı tamamla.
9. Release-aware legal status, idempotent accept ve publish/accept race sözleşmesini tamamla.
10. Protected API/WS gate'lerini 401/403/428/5xx ayrımıyla merkezileştir.
11. Client auth/legal/connectivity state machine ve reaccept recovery yüzeyini tamamla.
12. `LegalScreen`, registration, reaccept ve admin preview renderer parity'sini tamamla.
13. A-HOME-002 settings/support/permission/deletion yüzeylerini Wave 06 contractlarına bağla.
14. Session/local state cleanup, deep-link ve multi-device reconciliation'ı tamamla.
15. Otomatik test, admin QA-013, Web/Android manual QA ve owner review'ları tamamla.
16. Stable ID/QA kanıtlarını kaydet ve Wave 13'ü başlatmadan dur.

## 18. Otomatik test planı

### 18.1 Migration ve legal model

- Empty DB, güncel şema snapshot'ı ve legacy `legal_content_v1` fixture migration'ı.
- Backfill published snapshot/hash/manifest parity.
- Migration forward, rollback, rerun/idempotency ve partial failure.
- Draft save public pointer/version'ı değiştirmiyor.
- Immutable publication update/delete koruması.
- Unique release revision, commandId ve acceptance requirement constraintleri.
- TR/EN Unicode, line endings ve deterministic content hash.
- Legacy adapter current published manifest ile aynı içeriği üretiyor.

### 18.2 Validation, preview ve editor

- Required/empty/whitespace/length/URL/placeholder field matrix.
- Script, unsafe HTML, `javascript:` URL ve sanitizer bypass fixtures.
- 30 bin karakter sınırı ve büyük diff performansı.
- TR/EN title/body/footer validation bağımsız field errors.
- Admin preview ile `LegalScreen` render snapshot parity.
- Stale baseRevision iki-editor conflict; silent overwrite yok.
- Draft save retry aynı result; başka document draft'ı kaybolmuyor.
- Dirty-state navigation ve keyboard draft-save; publish tetiklenmiyor.

### 18.3 Publish, history ve rollback

- Diff/changeClass/reason/owner/re-auth eksikse publish block.
- Material change + aynı version policy block/review.
- Estimate source/time ve stale impact conflict.
- İki eşzamanlı publish'te tek current manifest.
- Publication, current pointer, required map, audit ve command result atomik.
- Transaction/audit failure current public content'i değiştirmiyor.
- Response loss + same commandId publish replay.
- Public cache verification success/failure ayrımı.
- History exact snapshot, compare ve rollback yeni publication üretiyor.
- Daha eski required version rollback policy olmadan yayınlanmıyor.

### 18.4 Acceptance ve auth gate

- No acceptance, Terms-only mismatch, Privacy-only mismatch ve both mismatch.
- Same requirement retry tek semantic acceptance.
- İki cihaz eşzamanlı accept aynı sonucu alıyor.
- Status→publish→accept stale release reddi ve newest required response.
- Accept→publish sırası yeni reaccept'i doğru üretiyor.
- Missing/invalid version accepted görünmüyor.
- IP/UA/geo response/log redaction ve geo-country ayrımı.
- 401/403/428/429/5xx stable error matrix.
- Profile/friends/push/support/WS protected gate parity.
- Public legal ve logout reaccept arkasında kilitlenmiyor.

### 18.5 Client recovery

- No token, valid accepted session, required, expired, revoked ve pending deletion boot.
- Legal status network/5xx hatası token silmiyor veya protected UI açmıyor.
- Friends 428 merkezi gate'i bir kez açıyor; request/modal loop yok.
- Accept double click, timeout/read-back, replay, conflict ve success reconciliation.
- Success önceki safe deep-link'e yalnız bir kez dönüyor.
- Browser refresh/Android recreation/background/multi-device state.
- Cached old legal content current release gibi sunulmuyor.
- Focus trap, Escape/back, long content, large text, screen reader ve 320 px.

### 18.6 A-HOME-002

- Settings destructive hierarchy ve keyboard/focus.
- Support validation, permission, media limit, timeout ve same-command retry.
- Support API received ile mail delivery sonucu ayrımı.
- Permission denied/limited/unavailable/granted; app kilitlenmiyor.
- Delete wrong password/confirm, double submit, existing pending ve network timeout.
- Deletion request `pending` iken `completed` metni yok.
- Success socket/reconnect/queue/chat/outbox/token/cache cleanup.
- Aynı cihazda sonraki login önceki user state'ini görmüyor.
- Web/Android deep-link ve hardware back.
## 19. Manuel QA havuzu — Checkpoint B / Wave 19 (commit kapısı değil)

| Alan | Senaryo | Beklenen sonuç |
|---|---|---|
| Admin özet | 3 document + footer | Beş saniyede published/draft/eksik/risk anlaşılır |
| Editör | Privacy TR/EN | Yalnız seçili belge; field errors ve dirty state görünür |
| Preview | TR/EN desktop/mobile | Gerçek `LegalScreen` render'ı; draft etiketi açık |
| Draft | Save ve page leave | Public değişmez; unsaved içerik kaybolmaz |
| Conflict | İki admin aynı draft | İkinci stale save/publish ezmez; conflict çözümü açık |
| Diff | Uzun body/title/version | Added/removed/changed anlaşılır; injection yok |
| Impact | Terms/Privacy version değişimi | Source/time, affected count/flows ve risk görünür |
| Publish | Validation → re-auth → confirm | Tek atomik publication; duplicate yok |
| Verify | Public endpoint/cache failure | Kısmi sonuç başarı gibi anlatılmaz |
| History | İki publication compare | Exact TR/EN/version/hash/actor/reason bulunur |
| Rollback | Eski snapshot seçimi | Yeni denetlenebilir publish; history korunur |
| Registration | Publish öncesi/sonrası yeni hesap | Kabul doğru current release'e bağlı |
| Existing user | Accepted → new version | Korunan akıştan önce doğru reaccept gate |
| Race | Gate açıkken yeni publish | Stale kabul reddi; yeni içerik ve açık seçim |
| Retry | Accept response kaybı | Status reconciliation; duplicate acceptance yok |
| Offline | Boot/reaccept sırasında ağ yok | Session korunur; protected flow açılmaz; retry var |
| Expired session | Legal gate açıkken 401 | Login recovery; reaccept ile karışmaz |
| Multi-device | Bir cihaz kabul eder | Diğeri server status ile güncellenir |
| Deep-link | Legal/settings/delete protected link | Kapılar sonrası güvenli hedefe tek geçiş |
| Support | Success/mail failure/retry | Received/delivery ayrımı; duplicate yok |
| Permission | Denied/limited/granted | Uygulama kilitlenmez; doğru sonraki adım |
| Delete | Request/pending/retry | Tam silindi denmez; session/local state temiz |
| Accessibility | Keyboard/SR/large text/320 px | Editor, modal, tabs ve danger flow kullanılabilir |
| Platform | Web/Android/recreation/back | Aynı release ve sonuç semantiği |
| Regression | Match/friends/chat/push | Legal gate dışında mevcut davranış korunur |

## 20. Canonical kabul eşlemesi

### 20.1 C-LEGAL-001 — 8 kriter

- [ ] Master QA-013 kriterleri tamam.
- [ ] Draft kaydı canlı içeriği değiştirmiyor.
- [ ] Eksik TR/EN/placeholder yayınlanmıyor.
- [ ] Reaccept etki sayısı source/time taşıyor.
- [ ] Aynı anda editor çakışması sessiz overwrite değil.
- [ ] Publish transaction atomik.
- [ ] Rollback audit/history kaybetmiyor.
- [ ] Client doğru published version'ı görüyor.

### 20.2 B-AUTH-002 — 5 kriter

- [ ] Eksik belge sürümü kabul edilmiş görünmüyor.
- [ ] Aynı version retry duplicate anlam üretmiyor.
- [ ] Yayımla eşzamanlı kabul doğru version'a bağlanıyor.
- [ ] Client required state'i tahmin etmiyor.
- [ ] Geo snapshot matchmaking country alanı gibi kullanılmıyor.

### 20.3 A-AUTH-002 — 5 kriter

- [ ] Reaccept nedeni ve sonraki adım anlaşılır.
- [ ] Başarısız kabul başarılı görünmüyor.
- [ ] Aynı kabul tekrar tekrar gönderilmiyor.
- [ ] Web/Android aynı legal sürümü gösteriyor.
- [ ] C-LEGAL-001 yayın sözleşmesiyle çelişmiyor.

### 20.4 A-HOME-002 — 5 kriter

- [ ] Destructive hesap silme normal ayarla aynı ağırlıkta görünmüyor.
- [ ] Gönderim sonucu ve sonraki adım açık.
- [ ] Aynı destek kaydı retry ile duplicate olmuyor.
- [ ] İzin reddi uygulamayı kilitlemiyor.
- [ ] Tamamlanan hesap silme client state'ini temizliyor.

### 20.5 Master QA-013 — 10 kriter

| # | Canonical kabul | Wave 12 kanıtı |
|---:|---|---|
| 1 | Üç belgenin yayın/taslak/eksik durumu, version ve ana risk beş saniyede anlaşılır | Admin overview visual/manual QA |
| 2 | Tek belge odağı, TR/EN düzenleme ve gerçek son kullanıcı önizlemesi | Editor/renderer component + responsive QA |
| 3 | Unsaved değişiklik açık onaysız kaybolmaz | Dirty-state navigation tests |
| 4 | Save yalnız draft; public API diff/validation/impact/approval sonrası değişir | Draft/public integration tests |
| 5 | Terms/Privacy version değişimi doğru hesaplarda reaccept; same-version kararı auditli | Publish/status/acceptance matrix |
| 6 | Maddi içerik + unutulmuş version sessiz yayınlanmaz | Policy validation tests |
| 7 | TR/EN, placeholder, limit, URL ve unsafe content field-level görünür ve riskli publish block | Validation/security suite |
| 8 | Snapshot, diff, admin, reason, previous version korunur; rollback yeni publish'tir | DB/history/audit evidence |
| 9 | Public API, LegalScreen, footer, registration ve reaccept aynı publication/version'ı gösterir | Contract/render parity suite |
| 10 | Editor conflict, API/partial failure, mobile ve 30 bin karakter otomatik/manual QA'dan geçer | Concurrency/failure/performance/visual evidence |

Stable ID checkbox'ları yalnız kendi canonical kriterlerinin tamamı kanıtlandığında kapanır. Master QA-013 toplu kriteri, tablodaki on satırdan biri açıkken tamam sayılmaz.

## 21. Kapsam dışı ve successor guard

- Wave 13 TalkX Sistem inbox, campaign, recipient, read/push ve client sohbeti
- Wave 14 analytics/performance ve genel davranış panoları
- Genel admin navigation/dashboard/profile yeniden tasarımı
- Yeni identity provider, email recovery veya olmayan şifre kurtarma ürünü
- Hukuki metin yazarlığı, mevzuat yorumu veya agent tarafından changeClass kararı
- Child Safety'yi owner kararı olmadan zorunlu acceptance belgesine dönüştürme
- Rich-text editor dependency'sini kanıtsız ekleme
- Bütün session/token mimarisini yeniden yazma
- Wave 06 retention/deletion/support backend kararlarını yeniden açma
- Gerçek production legal publish/reaccept/rollback
- Gerçek kullanıcı hesabı silme, deletion approve/reject/reactivate
- Wave 13 uygulaması

## 22. Risk ve rollback

| Risk | Koruma | Rollback/durma |
|---|---|---|
| Draft canlı içeriği değiştirir | Ayrı store + public pointer test | Draft write kapat |
| Stale admin yeni yayını ezer | Revision CAS + 409 | Publish capability kapat |
| Unsafe content client'ta çalışır | Tek sanitizer/render contract | Affected publication block/roll-forward |
| Maddi değişiklik reaccept üretmez | changeClass/version policy | Publish durdur; owner review |
| Yanlış version bütün kullanıcıyı kilitler | Impact + canary + kill switch | Yeni audited corrective publish |
| Publish yarım kalır | Tek transaction + audit | Transaction rollback |
| DB publish olur cache eski kalır | Release verification/ETag | Cache bypass/invalidate; açık incident |
| Eski client 428 loop'a girer | Compatibility/min-release impact | Publish/requirement gate kapat |
| Acceptance race stale metni kabul eder | expected release + transaction | Accept kapat/status refresh |
| Retry duplicate acceptance üretir | Unique fingerprint + commandId | Dedupe/reconcile; write gate kapat |
| Network hatası kullanıcıyı logout eder | Error classification | Auth cleanup path kapat |
| Legal hata gate'i bypass eder | Fail-safe unknown state | Protected hydration durdur |
| Reaccept modal focus trap olur | A11y/back/deep-link tests | Full-screen simple fallback |
| Delete request tam silindi görünür | State-specific copy | CTA/result capability kapat |
| Delete sonrası reconnect canlanır | Ordered socket/timer/token cleanup | Global local-session purge |
| Support retry duplicate üretir | Wave 06 idempotency | Submit retry kapat/read-back |
| IP/UA/geo sızar | Redaction/access/retention | Detail access kapat/incident |
| Dirty repo işi örter | Üç Git snapshot'ı | Yalnız Wave 12 farkını geri al |

Published immutable history fiziksel rollback ile silinmez. Hatalı yayın düzeltmesi owner onaylı yeni publication'dır. Migration additive ve dual-read olduğu için uygulama rollback'i yeni tabloları destructive drop etmeye dayanmaz.

## 23. Rollout ve canlı destructive sınır

1. Legal/content/policy owner document formatı, changeClass, version/reaccept ve Child Safety kabul kararını imzalar.
2. Yeni şema izole DB'de migration/backfill/rollback/restore ile kanıtlanır.
3. Draft/preview/history read-only admin capability staging'de açılır.
4. Publish transaction önce synthetic legal content ve test admin ile capability-off doğrulanır.
5. Public API dual-read/compatibility ve release verification tamamlanır.
6. Acceptance status/accept idempotency ve protected gates staging test users ile doğrulanır.
7. Reaccept UX Web ve Android internal cohort'ta açılır.
8. A-HOME-002 support/permission/delete UI yalnız synthetic/test hesaplarda doğrulanır.
9. Draft save error, publish conflict/failure, 428 rate, acceptance conflict, logout ve deletion metrics izlenir.
10. QA-013 desktop/mobile/a11y ve long-content testi tamamlanır.
11. Stable ID sonuçları kullanıcı onayıyla değerlendirilir.

Production migration, current content backfill, live publish, reaccept requirement değişimi, cache/config, session invalidation, gerçek acceptance/deletion/support verisi, feature flag veya deploy ayrıca exact target/impact/onay ister. Plan belgesi bu yetkiyi vermez.

## 24. Başlangıç kapısı

- [ ] Wave 01–11 QA kapanışları ve kullanıcı onayı doğrulandı.
- [ ] Kullanıcı açıkça “Wave 12'yi başlat” dedi.
- [ ] Root/backend/frontend Git snapshot'ı alındı.
- [ ] Wave 04 migration/backup/restore runbook gerçek kodda doğrulandı.
- [ ] Wave 06 retention/deletion/support/account cleanup çekirdeği **AUTO-VERIFIED / COMMITTED**.
- [ ] Current legal/admin/auth/session/account/support data flow yeniden envanterlendi.
- [ ] Document formatı ve ortak sanitizer/renderer kararı owner tarafından onaylandı.
- [ ] Terms/Privacy changeClass, version ve reaccept politikası onaylandı.
- [ ] Child Safety acceptance/notification politikası açıkça kilitlendi.
- [ ] Legal admin read/edit/publish/history/rollback yetki ve re-auth matrisi onaylandı.
- [ ] Draft/publication/manifest/acceptance idempotency migration tasarımı review edildi.
- [ ] Legacy `legal_content_v1` backfill/dual-read/rollback yolu kanıtlandı.
- [ ] Impact estimate source/time ve compatibility/min-client politikası kilitlendi.
- [ ] Synthetic TR/EN/unsafe/30k/conflict/race fixtures hazırlandı.
- [ ] Web/Android offline/deep-link/recreation/a11y matrisi hazırlandı.
- [ ] Production publish, gerçek deletion veya session invalidation yapılmayacağı doğrulandı.
- [ ] Wave 13 kapsamına taşma olmadığı doğrulandı.

## 25. Sonuç alanı

- Başlangıç/bitiş, refs ve gerçek değişen dosyalar
- Üç Git bağlamının önce/sonra farkı
- Final document/version/release/draft/publication/acceptance sözleşmesi
- Migration/backfill/dual-read/rollback ve restore kanıtı
- Validation/sanitizer/renderer/preview parity sonuçları
- Draft save/dirty-state/two-editor conflict sonuçları
- Diff/changeClass/impact/re-auth/atomic publish kanıtı
- Public API/cache/ETag/verification ve old-client compatibility sonucu
- History/compare/rollback-as-new-publication kanıtı
- Required/accepted/status/accept idempotency ve race sonucu
- Protected flow 401/403/428/5xx/WS gate matrisi
- Client boot/reaccept/offline/session recovery/multi-device sonucu
- QA-013 admin desktop/mobile/30k/a11y evidence paketi
- A-HOME-002 settings/support/permission/deletion sonucu
- Deletion sonrası socket/timer/token/local state cleanup kanıtı
- Privacy/log/telemetry/IP/UA/geo redaction taraması
- Syntax/lint/build/encoding/focused/full test exit code'ları
- Stable ID checkbox için gerçek kanıt; manuel QA Checkpoint B / Wave 19 havuzunda
- Production destructive işlemlerin yapılmadığı kayıt
- Wave 13'ün başlatılmadığı açık durma kaydı

## 26. Durma kuralı

Wave 11 QA kapanışı ve kullanıcının açık Wave 12 başlatma talimatı birlikte gelene kadar:

- Wave 12 için kod, test, dependency, migration, legal/content data query, publish, acceptance, session, support, deletion, feature flag veya deploy değişikliği yapılmaz.
- Wave 12 `Aktif` işaretlenmez; belge yalnız `Hazır — aktif değil` kalır.
- Canonical `[ ]` maddeler kanıtsız kapatılmaz.
- Wave 06 veri/deletion/support sözleşmeleri kanıtsız varsayılmaz veya yeniden yazılmaz.
- Production legal publish, rollback, reaccept tetikleme ve gerçek hesap işlemi ayrıca açık yetki olmadan yapılmaz.
- Wave 13 uygulanmaz; hazırlanmış plan aktif edilmez.
