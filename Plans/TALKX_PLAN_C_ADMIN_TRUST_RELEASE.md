# TalkX Plan C — Admin, Trust & Release

> TalkX admin paneli, güven/moderasyon, global uyum, analitik, release ve operasyon işlerinin canonical uygulama planı.
> Kaynak envanter: `docs/TALKX_MASTER_BACKLOG.md`.
> Wave 01–18 Sale Release yürütmesi tamamlandı; Wave 19 başlamadı.

## 1. Belge rolü ve otorite

Bu belge TalkX'in güvenli biçimde yönetilmesi, ölçülmesi, yayınlanması ve işletilmesinin ana otoritesidir. Admin yüzeyleri ham veri deposu değil; problem, etki, tekrar, kanıt ve aksiyon sırasıyla çalışan karar araçlarıdır.

Master backlog ham bulgu ve QA kanıtını korur. Bu plan admin/trust/release alanlarını stable uygulama maddelerine dönüştürür. Wave'ler ayrıntıyı kopyalamaz; Plan C ID ve kabul kriterlerine yönlendirir.

Otorite sırası:

1. `TALKX_MASTER_BACKLOG.md` kilitli ürün kararları ve QA kanıtı
2. Bu belgedeki Plan C sözleşmeleri
3. Plan A kullanıcı yüzeyi ve Plan B veri/API sağlayıcı sözleşmeleri
4. `TALKX_WAVE_MAP.md` ve hazırlanmış `waves/TALKX_WAVE_NN.md` dosyaları; plan dosyasının varlığı aktivasyon değildir
5. Admin ekranı, audit, CI/release ve canlı operasyon kanıtı

Admin ihtiyacı kullanıcı ürün kimliğini sessizce değiştiremez. Canlı veya geri döndürülemez işlem yalnız açık scope, yetki, etki özeti ve audit ile yapılır.

## 2. Plan durumu ve sınırı

- **Plan durumu:** Hazır
- **Uygulama durumu:** Wave 01–18 Sale kapsamı yürütüldü; manuel/device/store QA Wave 19'a ertelendi
- **Wave Map durumu:** Hazır
- **Hazırlanmış Wave Planları:** Wave 01 — `waves/TALKX_WAVE_01.md`; Wave 02 — `waves/TALKX_WAVE_02.md`; Wave 03 — `waves/TALKX_WAVE_03.md`; Wave 04 — `waves/TALKX_WAVE_04.md`; Wave 05 — `waves/TALKX_WAVE_05.md`; Wave 06 — `waves/TALKX_WAVE_06.md`; Wave 07 — `waves/TALKX_WAVE_07.md`; Wave 08 — `waves/TALKX_WAVE_08.md`; Wave 09 — `waves/TALKX_WAVE_09.md`; Wave 10 — `waves/TALKX_WAVE_10.md`; Wave 11 — `waves/TALKX_WAVE_11.md`; Wave 12 — `waves/TALKX_WAVE_12.md`; Wave 13 — `waves/TALKX_WAVE_13.md`; Wave 14 — `waves/TALKX_WAVE_14.md`; Wave 15 — `waves/TALKX_WAVE_15.md`; Wave 16 — `waves/TALKX_WAVE_16.md`; Wave 17 — `waves/TALKX_WAVE_17.md`; Wave 18 — `waves/TALKX_WAVE_18.md`; Wave 19 — `waves/TALKX_WAVE_19.md` — Wave 01–18 kapalı, Wave 19 hazır fakat aktif değil
- **Uygulama wave'i:** Yok; Wave 18 kapandı, Wave 19 başlatılmadı
- **Birincil alan:** Admin / Trust & Safety / Moderasyon / Analytics / Legal / Release / Android dağıtım / Operasyon
- **Ana repo alanları:** `chatapp-backend/admin.js`, `chatapp-backend/admin.html`, canonical `chatapp-frontend/android/` ve ilgili canonical Plans/runbook belgeleri; workspace root `android/` ve `Plans/` kaynak değildir
- **Bağlı planlar:** Plan A — Product & Client Experience; Plan B — Platform, Realtime & Data

Bu plan:

- Global mağaza/yaş/uyum kararlarını,
- Admin bilgi mimarisini,
- Moderasyon ve güvenli admin aksiyonlarını,
- Bildirim/yasal/sistem mesajı yayınını,
- Performance/behavior/release görünürlüğünü,
- CI, deploy, backup ve Android release kapılarını,
- Manuel admin/release QA'yı

tanımlar.

Bu plan core WebSocket/DB iç uygulamasını veya kullanıcı ekranı kompozisyonunu sahiplenmez.

## 3. Bağlayıcı yönetim ve operasyon ilkeleri

- Admin ilk bakışta durum, etki ve en mantıklı aksiyonu görür.
- Ham JSON, tam IP, token, mesaj yığını veya binlerce event varsayılan ekran değildir.
- Her özet kaynak ve zaman penceresine geri izlenebilir.
- Veri yok, stale, partial ve düşük örnek ayrı durumdur.
- Destructive aksiyonlar hedef, etki, gerekçe, yeniden doğrulama ve audit gerektirir.
- Hassas veri varsayılan maskelidir; görme/kopyalama ayrı yetki ve gerekçe ister.
- Otomatik gruplama/özet deterministik ve geri alınabilir olmalıdır.
- Ürün 18+ olarak sessizce yeniden konumlandırılmaz.
- Mağaza veya bölge sorunu ürün kimliği değiştirilmeden ayrı çözülür.
- Global gönderim eksik dil varyantıyla yapılamaz.
- Push tek kalıcı kaynak değildir; ilgili ürün kaydı kendi otoritesinde kalır.
- Release kimliği olmadan performans/crash karşılaştırması güvenilir sayılmaz.
- Canlı DB, deploy, notification, legal publish ve toplu moderasyon salt doküman hazırlığıyla yetkilendirilmiş sayılmaz.
- Ayrı talimat olmadan sonraki plan maddesi veya wave uygulanmaz.

## 4. Stable ID ve wave referans kuralı

Plan C kimlik alanları:

- `C-COMP-*`: global erişim, yaş, privacy ve mağaza uyumu
- `C-TRUST-*`: moderasyon, rapor, destek ve güvenlik
- `C-ADMIN-*`: admin kabuğu ve görev ekranları
- `C-NOTIFY-*`: bildirim yönetimi
- `C-PERF-*`: performans
- `C-ANL-*`: davranış ve ürün analitiği
- `C-LEGAL-*`: yasal içerik
- `C-SYS-*`: TalkX Sistem kampanyaları
- `C-REL-*`: Release Health ve deploy görünürlüğü
- `C-CI-*`: kalite/release pipeline
- `C-MOB-*`: Android release
- `C-OPS-*`: canlı servis/runbook/backup
- `C-QA-*`: admin ve operasyon QA

Plan haritasındaki `Birincil bağımlılık` sütunu yalnız wave sıralamasında önce kapanması gereken ID'leri gösterir. `Çapraz plan sözleşmeleri` tablosundaki sağlayıcı/tüketici ilişkileri bağımlılık değildir; bağlı ID'ler aynı wave'de veya ardışık wave'lerde birlikte doğrulanabilir.

## 5. Plan haritası

| ID | Sonuç | Master/QA kaynağı | Birincil bağımlılık | Durum |
|---|---|---|---|---|
| C-COMP-001 | Global erişim, yaş ve mağaza uyumu | Master §6 | A-PRD-001 | [ ] |
| C-COMP-002 | Privacy/Data Safety ve retention uyumu | Master §5/§6/§10 | B-DATA-001 | [ ] |
| C-TRUST-001 | Moderasyon/rapor/engel kanıt zinciri | Master §8/§9/§14 | B-SEC-002, B-MSG-002 | [ ] |
| C-TRUST-002 | Destek ve hesap silme operasyonu | Master §9/§14 | B-DATA-003 | [ ] |
| C-ADMIN-001 | Admin auth, yetki ve ortak bilgi kabuğu | Master §9, QA-006 | B-SEC-001 | [ ] |
| C-ADMIN-002 | QA-004 Dashboard ve sistem sağlığı | QA-004 | B-API-002, C-PERF-001 | [ ] |
| C-ADMIN-003 | QA-005 aktivite özeti | QA-005 | B-ANL-001 | [ ] |
| C-ADMIN-004 | QA-007 profil listesi | QA-007 | C-ADMIN-001 | [ ] |
| C-ADMIN-005 | QA-008 profil detayı | QA-008 | B-DATA-001, C-TRUST-001 | [ ] |
| C-ADMIN-006 | QA-009 uygulama raporları | QA-009 | C-TRUST-002 | [ ] |
| C-NOTIFY-001 | QA-010 çok dilli bildirim merkezi | QA-010 | B-I18N-001 | [ ] |
| C-PERF-001 | QA-011 karar odaklı performans | QA-011 | B-ANL-002 | [ ] |
| C-ANL-001 | QA-012 davranış analitiği | QA-012 | B-ANL-001 | [ ] |
| C-ANL-002 | QA-017 scope ve country özeti | QA-017 | B-MM-002, B-DATA-002 | [ ] |
| C-LEGAL-001 | QA-013 güvenli yasal yayın merkezi | QA-013 | B-DB-001 | [ ] |
| C-SYS-001 | QA-015 Sistem mesajı kampanyaları | QA-015 | B-SYS-001, C-NOTIFY-001 | [ ] |
| C-REL-001 | QA-016 Release Health | QA-016 | B-OBS-002 | [ ] |
| C-CI-001 | Lint/test/build/audit/deploy kapıları | Master §11/§12 | A-QA-001, B-QA-001 | [ ] |
| C-MOB-001 | Android version/build/signing/release zinciri | Master §12/§15 | C-CI-001 | [ ] |
| C-OPS-001 | Canlı servis, config ve deploy runbook | Master §12 | B-API-002 | [ ] |
| C-OPS-002 | Backup/restore ve felaket kurtarma | Master §10/§12 | B-DB-001 | [ ] |
| C-QA-001 | Admin/manual/release kalite kapıları | Master §11/§14/§15 | C-CI-001 | [ ] |

## 6. C-COMP-001 — Global erişim, yaş ve mağaza uyumu

**Amaç:** Global dağıtım gerçeğini TalkX'i sessizce 18+ veya başka bir ürün kimliğine dönüştürmeden çözmek.

**Kapsam:**

- Google Play anonim/rastgele sohbet yaş mekanizması
- Hedef kitle ve content rating
- Ülke/bölge dağıtım seçenekleri
- CSAE/CSAM politika ve gerçek operasyon prosedürü
- Yetkili makam bildirim süreci
- Çocuk güvenliği irtibatı
- Terms/Privacy/Community Guidelines/Child Safety İngilizce inceleme
- Ülke/bölge uyum matrisi
- Web/Android/store açıklama uyumu

**Kapsam dışı:**

- Onaysız 18+ kararı
- Global ürünü tek ülkeye indirme
- Kanıt olmadan mağaza beyanı
- Hukuki tavsiye varmış gibi kesin sonuç

**Kabul kriterleri:**

- [ ] Play Console etkisi canlı panelde doğrulanmış.
- [ ] Ürün kimliğini değiştirmeyen seçenekler karşılaştırılmış.
- [ ] CSAE/CSAM prosedürü yalnız metin değil owner/escalation içeriyor.
- [ ] İrtibat ve bildirim kanalı doğrulanmış.
- [ ] Store/Data Safety/content rating cevapları kod ve veriyle uyumlu.
- [ ] TR/EN yasal metinler insan incelemesinden geçmiş.
- [ ] Bölgesel kısıt varsa kullanıcı ve operasyon etkisi açık.
- [x] A-PRD-001 ürün vaadiyle çelişki yok.

**Kanıt:** Play Console ekran kaydı, politika/version listesi, sorumlu/iletişim doğrulaması, uyum matrisi.

## 7. C-COMP-002 — Privacy, Data Safety ve retention uyumu

**Amaç:** Uygulama beyanlarını gerçek veri akışı ve saklama davranışıyla eşleştirmek.

**Kapsam:**

- Account/session/profile
- Anonymous/friend messages
- Media
- Report/support
- Push
- IP/geo
- Legal acceptance
- Behavior analytics
- System message
- Release Health
- Ads/`app-ads.txt` ve consent ancak reklam planı varsa
- Hesap silme
- Backup retention

**Kabul kriterleri:**

- [x] Her store/privacy beyanının kod/DB kaynağı var.
- [x] Anonimlik iddiası servis verisini gizlemiyor.
- [ ] B-DATA-001 retention matrisiyle çelişki yok.
- [x] Reklam açılmadan gereksiz consent mimarisi eklenmiyor.
- [ ] Reklam açılırsa privacy/Data Safety birlikte güncelleniyor.
- [ ] Üçüncü taraf servisler ve veri bölgesi kayıtlı.
- [x] Kullanıcı silme sonucu doğru anlatılıyor.

## 8. C-TRUST-001 — Moderasyon, rapor ve engel kanıt zinciri

**Amaç:** Rapor/engel/ban kararını yeterli fakat gereksiz hassas veri açmayan kanıtla yönetmek.

**Kapsam:**

- Anonim ve arkadaş sohbeti raporu
- Reported user/message/media bağlantısı
- Block
- Temp/permanent/shadow ban
- Otomatik ban eşiği
- Appeal/review ihtiyacı
- Moderator kanıtı
- Kanıt retention
- Yetki/audit
- Toplu işlem
- Kullanıcıya sonuç geri bildirimi

**Kabul kriterleri:**

- [ ] Moderator hangi olay/kullanıcı/mesajı incelediğini anlayabiliyor.
- [ ] Tam içerik ve IP varsayılan açık değil.
- [ ] Ban türü, süre, neden ve owner açık.
- [ ] Shadow ban davranışı normal ban gibi yanlış anlatılmıyor.
- [ ] Toplu/destructive işlem hedef ve etki özeti gösteriyor.
- [ ] Her değişiklik actor/gerekçe/zaman audit'i taşıyor.
- [ ] Hesap silme kanıt retention'ını sessizce bozmuyor.
- [ ] Client A-FRIEND-002 doğru sonucu gösteriyor.

## 9. C-TRUST-002 — Destek ve hesap silme operasyonu

**Amaç:** Support kaydı ve deletion request'i kaybolmadan, duplicate olmadan ve yetkili iş akışıyla yönetmek.

**Kapsam:**

- Destek metni/email/medya
- Rate/size/type limit
- Brevo/teslim durumu ile ürün kayıt durumunun ayrılması
- Admin durum/owner/not
- Kullanıcıya yanıt/sonuç
- Hesap silme talebi
- Review/complete/reject policy
- B-DATA-003 veri işlemi
- Audit ve retention

**Kabul kriterleri:**

- [x] Support API başarısı email teslimiyle karışmıyor.
- [x] Duplicate submit gruplanabilir.
- [ ] Hassas medya yetki altında.
- [x] Hesap silme sonucu backend doğrulaması olmadan tamamlandı görünmüyor.
- [ ] Retained/anonimized veri gerekçesi kayıtlı.
- [x] Admin destructive action yeniden doğrulama/onay kullanıyor.

## 10. C-ADMIN-001 — Admin auth, yetki ve ortak bilgi kabuğu

**Amaç:** QA-006 navigasyonunu güvenli, görev odaklı ve ortak admin standardına dönüştürmek.

**Kapsam:**

- Basic Auth yeterlilik kararı
- Brute-force/rate limit
- Rol/yetki matrisi
- CSRF/re-auth
- Session timeout
- Günlük görev odaklı navigasyon
- İlgili sayfa grupları
- Seyrek sistem/ileri alanlar
- Gerçek ikon sistemi
- Desktop/mobile navigation
- Ortak loading/empty/error/stale/no-data
- Hassas veri maskesi
- Destructive action standardı
- Audit viewer erişimi

**Kabul kriterleri:**

- [x] Yetkisiz admin endpointine UI gizlemesi dışında server engeli var.
- [x] Brute-force limiti production proxy arkasında doğru.
- [x] Kritik işlem yeniden doğrulama/policy ile korunuyor.
- [ ] Beş saniyede günlük görevler bulunuyor.
- [ ] Noktalama karakteri ikon olarak kullanılmıyor.
- [ ] Mobil navigasyon erişilebilir ve focus güvenli.
- [ ] Ortak durum bileşenleri teknik ham hata dökmüyor.

> **Wave 02 Sale Release kanıtı (2026-09-23):** Production disable-by-default korunurken timing-safe Basic Auth, remote-peer tabanlı ve bounded ayrı admin brute-force policy'si, canonical 401/429 envelope'u, her istekte yeniden doğrulama, no-store ve route bazlı server capability sınıflandırması eklendi. Gerçek Render zinciri staging manuel QA'ya; navigasyon/ikon/ortak görsel durum kriterleri ilgili admin dalgalarına ve Wave 19'a açık bırakıldı.

## 11. C-ADMIN-002 — QA-004 Dashboard

**Amaç:** Dashboard'u metrik duvarından güncel ve güvenilir sistem özetine dönüştürmek.

**Canonical kaynak:** Master QA-004.

**Kapsam:**

- Kullanıcı/aktiflik/anonim eşleşme ana metrikleri
- Sistem sağlığı
- Backend/DB/push/release kısa durum
- Veri zamanı/tazelik
- Loading/error/partial/no-data
- Önceki dönem
- Ana risk/aksiyon
- Detay sayfalarına yönlendirme
- Responsive/accessibility

**Kabul kriterleri:**

- [ ] Master QA-004 kabul kriterleri tamam.
- [ ] Dashboard araştırma detayını kopyalamıyor.
- [ ] Her sayı source/time window taşıyor.
- [ ] DB ve push sorunları aynı genel kırmızı kutuya gömülmüyor.
- [ ] Release Health C-REL-001 kısa kart olarak bağlanıyor.
- [ ] Düşük örnek/partial data başarı gibi görünmüyor.

## 12. C-ADMIN-003 — QA-005 aktivite özeti

**Amaç:** Saatlik ham tablo ve iç içe scroll yerine karar verdiren aktivite özeti oluşturmak.

**Canonical kaynak:** Master QA-005.

**Kapsam:**

- Aktivite trend grafiği
- Ana artış/düşüş
- Kısa, yerelleştirilmiş event akışı
- Gruplama
- Saatlik ham veri isteğe bağlı detay
- Tek ana scroll
- Filtre/time window
- Empty/stale/error

**Kabul kriterleri:**

- [ ] Master QA-005 kriterleri tamam.
- [ ] Ham saatlik tablo varsayılan görünüm değil.
- [ ] Grafik ile metrik aynı pencereyi kullanıyor.
- [ ] İç içe scroll yok.
- [ ] Eventler teknik isim değil anlaşılır sonuç.
- [ ] Ham kayda geri izleme mümkün.

## 13. C-ADMIN-004 — QA-007 profil listesi

**Amaç:** Profil tablosunu okunabilir, güvenli ve operasyonel hâle getirmek.

**Canonical kaynak:** Master QA-007.

**Kapsam:**

- Kolon bilgi önceliği
- Username/display name/platform
- Location city/country/source anlamı
- Last seen/created
- Satır/kolon takibi
- Uzun değer
- Filter/sort/pagination
- Hassas IP maskesi
- Tekil/toplu aksiyon
- Profil detayına geçiş

**Kabul kriterleri:**

- [ ] Master QA-007 kriterleri tamam.
- [ ] Tam IP varsayılan görünmüyor.
- [ ] Unresolved geo gerçek ülke gibi gösterilmiyor.
- [ ] Pagination/sort backend ile stable.
- [ ] Toplu ban liste taramasının içine gizlenmiyor.
- [ ] Dar ekranda kritik kolon ve aksiyon kaybolmuyor.

## 14. C-ADMIN-005 — QA-008 profil detayı

**Amaç:** Profil detayını özet, moderasyon, oturum/cihaz, legal/konum ve ilişki kanıtı olarak katmanlamak.

**Canonical kaynak:** Master QA-008.

**Kapsam:**

- Kimlik/hesap özeti
- Ban/report/block
- Session/device
- Legal acceptance
- Geo source/tazelik
- Friendship ve doğru tarih
- Messages/relationships sayıları
- Hassas alan reveal/copy
- Riskli aksiyonlar
- Audit

**Kabul kriterleri:**

- [ ] Master QA-008 kriterleri tamam.
- [ ] `expires_at` yanlış session bitişi olarak etiketlenmiyor.
- [ ] Friendship tarihi doğru tablodan.
- [ ] Location source/unresolved/stale açık.
- [ ] Hassas alan reveal auditli.
- [ ] Ban/unban/delete hedef-etki-onay taşıyor.
- [ ] Varsayılan görünüm ham JSON değil.

## 15. C-ADMIN-006 — QA-009 uygulama raporları

**Amaç:** Uygulama sorununu, etkisini, tekrarını, kanıtını ve aksiyonunu tek akışta göstermek.

**Canonical kaynak:** Master QA-009.

**Kapsam:**

- Ürün raporu lifecycle
- Brevo/email teslim durumundan ayrım
- Benzer kayıtları kanıtla gruplama
- Etkilenen kullanıcı/platform/release
- Owner/status/note
- Filtre/pagination
- Maskeli diagnostik
- Support media
- Archive/delete
- Audit

**Kabul kriterleri:**

- [ ] Master QA-009 kriterleri tamam.
- [ ] Email gönderildi ürün sorunu çözüldü demek değil.
- [ ] Yanlış grouping ayrılabilir.
- [ ] Ham diagnostik isteğe bağlı ve maskeli.
- [ ] Destructive delete yerine uygun archive/retention.
- [ ] Problem/etki/tekrar/aksiyon ilk görünümde.

## 16. C-NOTIFY-001 — QA-010 çok dilli bildirim merkezi

**Amaç:** Anlık, planlı ve run-now bildirimlerini TR/EN varyant, hedef ve teslimat özetiyle güvenli yönetmek.

**Canonical kaynak:** Master QA-010. Locale/delivery B-I18N-001.

**Kapsam:**

- TR/EN title/body
- Empty/whitespace validation
- Global ve segment hedefi
- Kullanıcı/device/locale sayımı
- English fallback
- WebSocket online ve push aktif ayrımı
- Test gönderimi
- Preview
- Schedule/timezone
- Run-now
- Duplicate engeli
- Gönderim öncesi onay özeti
- Dil/kanal bazlı sonuç
- Audit

**Kabul kriterleri:**

- [ ] Master QA-010 kriterleri tamam.
- [ ] Global iki dil tamamlanmadan gönderilemiyor.
- [ ] Test production globale sızmıyor.
- [ ] Recipient estimate source/time taşıyor.
- [ ] WS/push aynı kullanıcı double success gibi sayılmıyor.
- [ ] Schedule timezone/DST açık.
- [ ] Run-now aynı schedule'ı tekrar tetiklemiyor.
- [ ] Retry duplicate delivery üretmiyor.
- [ ] User locale fallback sayısı görünür.

## 17. C-PERF-001 — QA-011 performans özeti

**Amaç:** Ham veri tablosu yerine eşik, etki, güven ve aksiyon içeren performans görünümü oluşturmak.

**Canonical kaynak:** Master QA-011. Veri sağlayıcı B-ANL-002.

**Kapsam:**

- SLO/threshold
- Traffic/sample
- P50/P95/P99 gerektiği ölçüde
- Error rate
- Önceki dönem
- En çok etkilenen route
- DB/API/client ayrımı
- Stale/partial/no-data
- Güven etiketi
- Ham bucket detayı

**Kabul kriterleri:**

- [ ] Master QA-011 kriterleri tamam.
- [x] Eşik ve zaman penceresi görünür.
- [x] Az örnek kritik alarm değil.
- [x] P95 yoksa 0 gösterilmiyor.
- [x] Route etkisi trafik ve hata ile sıralı.
- [x] Özet ham kayda geri izlenebilir.
- [x] Release Health ile API latency aynı metrik yapılmıyor.

## 18. C-ANL-001 — QA-012 davranış analitiği

**Amaç:** Event hacmini değil kullanıcı yolculuğu sonucunu anlatmak.

**Canonical kaynak:** Master QA-012. Veri sözleşmesi B-ANL-001.

**Kapsam:**

- Registration/login
- Match search/queue/offer
- Accept/reject/timeout
- Chat start
- Message
- Friend request/accept
- System message/read/CTA
- Funnel/cohort
- Search/match/conversation birimleri
- Önceki dönem
- Düşük örnek
- Tek yolculuk hikayesi
- Platform/locale/release

**Kabul kriterleri:**

- [ ] Master QA-012 kriterleri tamam.
- [ ] Person/attempt/match/conversation ayrık.
- [ ] Sırasız event funnel'a sessizce eklenmiyor.
- [ ] İki participant bir match'i iki match yapmıyor.
- [ ] Düşük örnek güven işareti taşıyor.
- [ ] Ham event varsayılan tablo değil.
- [ ] Tam mesaj/prompt/PII analitikte yok.

## 19. C-ANL-002 — QA-017 scope ve country özeti

**Amaç:** Global/Country ürün kararını kullanıcı gizliliğini bozmadan ölçmek.

**Canonical kaynak:** Master QA-017 §16. Queue/data B-MM-002 ve B-DATA-002.

**Metrikler:**

- Selector seen/selected
- Requested/effective scope
- Scope change sonucu
- Country fallback shown/accepted/continued
- Median/P95 wait
- Offer
- Accept/reject/cancel
- Chat start
- Global/Country karşılaştırması
- Yeterli cohort/confidence

**Kurallar:**

- Tam IP/GPS/peer country yok.
- Serbest country string yok.
- Düşük hacimli ülke kırılımı maskeli/birleştirilmiş.
- Kartı görmeyen kullanıcı decline sayılmaz.
- Scope change ayrı search fakat aynı yolculuk bağı korunur.
- Az trafik `ülke modu başarısız` diye özetlenmez.

**Kabul kriterleri:**

- [ ] Master QA-017 analitik/gizlilik kriterleri tamam.
- [ ] Metric birimleri tanımlı.
- [ ] Source/time window/tazelik görünür.
- [ ] Minimum cohort eşiği deterministik.
- [ ] Global ve Country bekleme adil pencereyle kıyaslanıyor.
- [ ] Kullanıcı listesine gizli country tracking key açılmıyor.

## 20. C-LEGAL-001 — QA-013 yasal yayın merkezi

**Amaç:** Yasal metin ekranını soft editor ve güvenli, sürümlü yayın merkezi yapmak.

**Canonical kaynak:** Master QA-013. Veri/auth B-AUTH-002 ve B-DB-001.

**Kapsam:**

- Belge/dil seçimi
- Draft/save
- Preview
- Field validation
- Placeholder/URL/uzunluk
- Change summary
- Version/reaccept etki hesabı
- Publish confirmation
- Atomik publish
- Audit
- History
- Rollback/new version
- Concurrent editor
- Public API
- Web/Android preview
- Hassas/destructive ayrımı

**Kabul kriterleri:**

- [ ] Master QA-013 kriterleri tamam.
- [ ] Draft kaydı canlı içeriği değiştirmiyor.
- [ ] Eksik TR/EN/placeholder yayınlanmıyor.
- [ ] Reaccept etki sayısı source/time taşıyor.
- [ ] Aynı anda editor çakışması sessiz overwrite değil.
- [ ] Publish transaction atomik.
- [ ] Rollback audit/history kaybetmiyor.
- [ ] Client doğru published version'ı görüyor.

## 21. C-SYS-001 — QA-015 Sistem mesajı kampanyaları

**Amaç:** Adminin tek, seçili, segment veya global hedefe güvenli kalıcı TalkX Sistem mesajı göndermesini sağlamak.

**Canonical kaynak:** Master QA-015. Backend B-SYS-001; client A-SYS-001.

**Kapsam:**

- Tek kullanıcı
- Seçili kullanıcılar
- Ülke/dil/platform
- Son aktiflik/kayıt tarihi
- Herkes
- Hedef snapshot
- TR/EN/fallback
- Preview/test
- Recipient estimate
- Tek allowlist CTA
- Onay
- Batch/retry
- Delivery/read/push sonucu
- Audit/idempotency
- Campaign history

**Kabul kriterleri:**

- [ ] Master QA-015 admin kriterleri tamam.
- [ ] Kayıt ülkesi/son bilinen/IP tahmini source etiketi açık.
- [ ] Belirsiz geo kesin hedef gibi kullanılmıyor.
- [ ] Preview/test production recipient üretmiyor.
- [ ] Onay öncesi hedef/dil/kanal etkisi görünür.
- [ ] Campaign retry duplicate recipient değil.
- [ ] Kalıcı inbox sonucu push sonucundan ayrı.
- [ ] CTA allowlist ve permission açık.
- [ ] Gönderim sonrası temiz Jarvis özeti ve audit var.

## 22. C-REL-001 — QA-016 Release Health

**Amaç:** Web ve Android istemci hatalarını release, ekran ve etkiye göre güvenli karar özetine dönüştürmek.

**Canonical kaynak:** Master QA-016. Ingestion B-OBS-002; client instrumentation A planı.

**Kapsam:**

- Managed provider vs TalkX ingestion kararı
- Web ErrorBoundary/window/unhandled rejection/chunk
- Android native fatal ve destekleniyorsa ANR
- Release/build/deploy kimliği
- Source map/symbol
- PII redaction
- Fingerprint/grouping
- Occurrence/user/session
- Crash-free session
- Önceki release
- Sağlıklı/İzleniyor/Bozuldu/Kritik/Veri yok
- Issue list/detail/lifecycle
- Alert/dedupe/cooldown
- Recovery bağlantısı
- Retention/vendor/DPA/maliyet

**Kabul kriterleri:**

- [ ] Master QA-016 kriterleri tamam.
- [ ] Chat/token/form/IP eventte yok.
- [ ] Source map public değil ve doğru release'le.
- [ ] Düşük örnek kırmızı alarm değil.
- [ ] Telemetry kesintisi `0 hata` değil.
- [ ] Grouping override/audit mümkün.
- [ ] Fixed release ve regresyon izleniyor.
- [ ] Dashboard yalnız kısa kart; araştırma detay sayfasında.
- [ ] Kullanıcı recovery teknik stack göstermiyor.

## 23. C-CI-001 — CI ve release kalite kapıları

**Amaç:** Kırmızı lint/test/build/audit sonucuyla main deploy edilmesini engellemek.

**Kapsam:**

- Frontend lint
- Frontend production build
- Backend syntax/unit/integration
- DB migration test
- Critical E2E
- Dependency audit policy
- Text encoding/mojibake
- Android asset sync
- Version consistency
- Secret scan
- Artifact retention
- Branch protection/deploy trigger
- Flaky test doğrulama kuralı

**Kabul kriterleri:**

- [x] Hangi bulgunun blocker olduğu belgeli. — High/critical production audit, syntax/test/lint/build ve zero-test/live-target guard required-blocking.
- [x] Testler canlı DB'ye yazmıyor; Sale suite sentetik/in-memory çalışıyor ve `DATABASE_URL` varlığını reddediyor.
- [ ] Main deploy tüm zorunlu kapılardan sonra.
- [x] Flaky test otomatik yeşil sayılmıyor; workflow retry/`continue-on-error` kullanmıyor ve ilk geçişte flaky görülmedi.
- [ ] Artifact release kimliğiyle.
- [ ] Secret/log hassas veri kapısı var.
- [ ] Frontend 0.0.0 release olamıyor.
- [x] Mevcut audit bulguları sınıflanmış: frontend 0; backend 8 moderate `GHSA-w5hq-g745-h8pq`, breaking fix nedeniyle kabul edilmeden Wave 19/2026-10-25 review kapısında.

Wave 17 Sale Release override kanıtı 2026-09-25 tarihinde iki repoda `quality:all` ve basit SHA-pinned GitHub CI ile kaydedildi. Main branch protection/deploy read-back, geniş artifact/secret scan ve `0.0.0` release engeli kanıtsız kapatılmadı; sonuncusu Wave 18 version hizası kapsamındadır.

## 24. C-MOB-001 — Android release zinciri

**Amaç:** Capacitor Android build'inin doğru frontend asset, backend config ve release kimliğiyle tekrarlanabilir üretilmesi.

**Kapsam:**

- `versionName`/`versionCode`
- Ortak release version kaynağı
- Frontend build
- Capacitor sync
- Android asset hash
- Environment/backend URL
- Signing/keystore erişimi
- Debug/release ayrımı
- Manifest/permissions
- Data Safety/content rating
- Emulator/device smoke
- Play upload/rollout/rollback
- Release notes

**Kabul kriterleri:**

- [x] Web/Android/backend release kimliği ilişkilendirilebilir. — `talkx-1.0.6-8`, frontend `0cdc68303177bd076bc4c5832f26731b2e900f8e`, backend baseline `b5b3807356ca565315ce99b9eac4d566bd17ad80`.
- [x] Eski frontend asset'i yeni APK/AAB içine girmiyor. — Clean sync sonrası 18 dosyalık full-tree SHA-256 `860a50127d164c7a0a8f7d2ca5b2088f518df178f67af77d7f3c989c5f0221a9`; stale fixture negatif testi geçti.
- [x] Keystore/şifre repo/log'da değil. — Ephemeral internal RC PKCS12 temp alanda üretildi, password yalnız process env ile taşındı ve `finally` cleanup uygulandı.
- [x] Debug endpoint production release'te yok. — Localhost/emulator fallback kaldırıldı; production URL/source-map/staging taraması geçti.
- [x] Permission beyanı gerçek kullanım kadar. — Release merged manifest exact permission ve exported-component allowlistinden geçti; store/Data Safety insan incelemesi Wave 19'da.
- [ ] Back/push/media/match smoke cihazda.
- [x] Rollout ve rollback adımları belgeli. — Internal RC halt/forward-fix runbook'u eklendi; production rollout komutu yok.
- [x] C-COMP-001 mağaza kararları tamamlanmadan yanlış beyanla yayın yok. — Play upload/track/listing/rollout yapılmadı; `playUploadAuthorized=false`.

> **Wave 18 Sale kanıtı (2026-09-25):** `1.0.6`/versionCode 8 release manifesti, clean Vite build/Capacitor sync, Gradle/R8/lint release build, merged-manifest audit ve ephemeral internal imzalı AAB doğrulandı. Final artifact `f55badb5d4a9d8b122d03feb5e3905ec23c6f77745ec39791f19b84e0e01e5ae`, internal sertifika SHA-256 `AC:9A:A2:EB:79:E8:32:B0:1C:3C:EB:78:6E:F1:DF:4D:E3:16:9D:58:86:23:C3:1E:73:87:47:9C:C7:81:0A:75`. Bu ephemeral sertifika Play upload key değildir. Cihaz smoke ve store beyanları Wave 19'a ertelendi.

## 25. C-OPS-001 — Canlı servis, config ve deploy runbook

**Amaç:** Web, backend ve Android'in hangi commit/config/veri kaynağıyla çalıştığını kanıtlanabilir hâle getirmek.

**Kapsam:**

- Repo/remote/default branch
- Frontend/backend ayrı Git sahipliği
- Root dışı Android/docs dosyalarının sahipliği
- Environment variable envanteri
- Render backend deploy
- Static frontend routing
- CORS/origin
- Health/readiness
- Deploy commit/version
- Restart/redeploy
- Rollback
- Incident notu
- Domain/deep-link smoke

**Kabul kriterleri:**

- [x] Hangi dosyanın hangi repo/release'e ait olduğu açık.
- [x] Credential değeri docs/log'a yazılmıyor.
- [x] Config değişikliği deploy/restart gereksinimi belli.
- [ ] Health ve gerçek kullanıcı smoke birlikte.
- [ ] Rollback hedef commit/artifact belli.
- [x] Android ortak dosyaları sahipsiz root artefactı değil.
- [x] Runbook stale komut/endpoint taşımıyor.

## 26. C-OPS-002 — Backup, restore ve felaket kurtarma

**Amaç:** Neon PostgreSQL verisini doğrulanabilir backup/restore prosedürüyle korumak.

**Kapsam:**

- Source/target kimliği
- Custom/compressed dump
- Encryption
- Storage/access
- Retention
- Restore staging
- Role/extension/search_path
- Critical table/count
- Direct Neon endpoint
- Connection cutover
- Render restart
- Rollback
- Recovery time/point hedefi

**Kabul kriterleri:**

- [x] Dump okunabilir/listelenebilir.
- [ ] Backup şifresiz ve erişimsiz dağınık dosya değil.
- [x] Restore boş schema açmakla veri restore'u karıştırmıyor.
- [ ] Kritik user/message/friend/report/legal count doğrulanıyor.
- [ ] `current_schema()=public` doğrulanıyor.
- [x] Pooler/direct endpoint seçimi runbook'ta gerekçeli.
- [ ] Cutover sonrası backend restart ve smoke.
- [x] Canlı restore açık yetki olmadan yapılmıyor.

## 27. C-QA-001 — Admin, operasyon ve release QA

**Otomatik kapılar:**

- Admin endpoint auth/rate-limit
- API/schema
- Admin frontend smoke
- Data summary vs source
- Permission/audit
- Notification dry-run/test
- Legal draft/publish staging
- Analytics fixture/rollup
- Release Health controlled event
- CI pipeline
- Android build/sync

**Manuel kapılar:**

- Master §14 admin inceleme listesi
- Master §15 Android release maddeleri
- QA-004–013, QA-015–017 ilgili admin/operasyon matrisleri
- Desktop/mobile admin
- Mask/reveal/copy
- Destructive confirmation
- Low/no/stale/partial data
- Before/after ekran görüntüsü
- Staging ve gerektiğinde açık onaylı production smoke

**Kapanış kuralı:**

- [ ] Plan ID kabul kriterleri kanıtlı.
- [ ] Source/time window doğruluğu testli.
- [ ] Yetki/audit sonucu kayıtlı.
- [ ] Canlı destructive işlem yapılmadı veya açık onay/sonuç var.
- [ ] Web/backend/Android release kimliği kayıtlı.
- [ ] Sonraki wave başlatılmadı.

## 28. QA birincil sahiplik matrisi

| QA | Plan C rolü | Bağlı plan |
|---|---|---|
| QA-001 | Moderasyon/presence etkisi referans | A birincil, B sağlayıcı |
| QA-002 | Rapor aksiyonu sonucu | A birincil |
| QA-003 | Analitik/release regresyon referansı | A birincil, B sağlayıcı |
| QA-004 | Birincil sahip | B health/performance |
| QA-005 | Birincil sahip | B analytics |
| QA-006 | Birincil sahip | — |
| QA-007 | Birincil sahip | B geo/data |
| QA-008 | Birincil sahip | B session/data |
| QA-009 | Birincil sahip | B report/support |
| QA-010 | Birincil sahip | B locale/delivery |
| QA-011 | Birincil sahip | B performance data |
| QA-012 | Birincil sahip | B behavior data |
| QA-013 | Birincil sahip | B legal/version/DB |
| QA-014 | Admin analytics/release referansı | A birincil, B sağlayıcı |
| QA-015 | Admin/campaign birincil | A client, B inbox |
| QA-016 | Birincil sahip | A instrumentation, B ingestion |
| QA-017 | Analytics/privacy tüketicisi | B behavior birincil, A UI |

## 29. Çapraz plan sözleşmeleri

| Plan C tüketicisi/sağlayıcısı | Bağlı ID | Kural |
|---|---|---|
| C-COMP-001/002 | A-PRD-001, B-DATA-001 | Ürün vaadi ile gerçek veri/mağaza uyumu |
| C-TRUST-001/002 | A-FRIEND-002, B-MSG-002/B-DATA-003 | Client aksiyonu ve backend kanıtı |
| C-ADMIN-002 | B-API-002, C-PERF-001, C-REL-001 | Dashboard kısa özet tüketir |
| C-ADMIN-003 | B-ANL-001 | Aktivite özeti event sözleşmesine bağlı |
| C-ADMIN-004/005 | B-PRES-001, B-DATA-001/002 | Profil ve geo anlamı backend otoriteli |
| C-NOTIFY-001 | B-I18N-001 | Locale/recipient/delivery |
| C-PERF-001 | B-ANL-002 | Performance rollup |
| C-ANL-001 | B-ANL-001 | Davranış birimleri |
| C-ANL-002 | B-MM-002/B-DATA-002, A-MATCH-003 | Scope telemetry ve UI anlamı |
| C-LEGAL-001 | B-AUTH-002/B-DB-001, A-AUTH-002 | Publish/reaccept/client |
| C-SYS-001 | B-SYS-001, A-SYS-001 | Campaign/inbox/client |
| C-REL-001 | B-OBS-002, A client recovery | Ingestion/özet/kullanıcı recovery |
| C-CI-001 | A-QA-001, B-QA-001 | Ortak release kapısı |
| C-MOB-001 | A-MOB-001, B-API-002 | Client davranışı ve backend release |

## 30. Master backlog kaynak kapsama indeksi

Plan C'nin birincil aldığı kaynaklar:

- Master §6 — global erişim, yaş ve platform uyumu
- Master §9 — admin panel backlog
- Master §12 — repo, release ve operasyon
- Master §14 — manuel admin inceleme
- Master §15 — Android release/dağıtım maddeleri
- Master §11 — CI/release/admin/manual kalite maddeleri
- QA-004, QA-005, QA-006, QA-007, QA-008, QA-009
- QA-010, QA-011, QA-012, QA-013
- QA-015 admin/campaign
- QA-016 Release Health
- QA-017 analytics/privacy

Referans verip sahiplenmediği kaynaklar:

- Master §5, §7, §13 → Plan A
- Master §8, §10 → Plan B
- Master §15 kullanıcı akışı → Plan A
- Master §17 Fikir Parkı → master'da kalır

## 31. Risk ve onay kapıları

Aşağıdaki işler plan veya wave var diye otomatik yetkili değildir:

- Production notification/system campaign gönderimi
- Legal metin publish/rollback
- Ban/unban/bulk moderasyon
- Hesap silme tamamlama
- Production DB migration/restore
- Render environment değişikliği
- Deploy/rollback
- Play Console yayın/rollout
- Credential/secret erişimi
- Hassas IP/mesaj/medya reveal veya export

Her biri için hedef, kapsam, etki, geri dönüş, yetki ve audit ayrıca doğrulanır.

## 32. Plan C tamamlanma tanımı

Plan C bütünü ancak:

- Global/yaş/store/privacy kararları kanıtlanmış,
- Admin auth/yetki/audit ve destructive action korumaları tamam,
- QA-004–013 admin yüzeyleri Jarvis modelinde kapanmış,
- QA-015 campaign, QA-016 Release Health ve QA-017 scope analitiği tamam,
- CI/deploy/release/Android zinciri tekrarlanabilir,
- Backup/restore ve rollback runbook'u doğrulanmış,
- Admin özetleri Plan B kaynağına geri izlenebilir,
- Manuel admin/Android/release QA ve gerekli kullanıcı onayı tamam

olduğunda tamamlanır.

Planın hazır olması admin işlemi, canlı gönderim, deploy, migration, mağaza yayını veya wave başlangıcı değildir.
