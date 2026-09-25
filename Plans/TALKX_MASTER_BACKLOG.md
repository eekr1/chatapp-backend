# TalkX Master Review & Backlog

> TalkX icin tek ana inceleme ve yapilacaklar envanteri.
> Bu asamada kod degistirmiyoruz. Frontend, backend, admin paneli, mobil, canli servis ve operasyonu inceliyor; gordugumuz her seyi kaydediyoruz.

## Ana tema: Jarvis bilgi modeli

> TalkX backlog'unun ana tasarim ve bilgi sunum ilkesi: **veri yiginligi degil, temiz filtreden gecirilmis ve aksiyona donusen bilgi**.

Jarvis burada bir chatbot, yapay zeka zorunlulugu veya gosterisli animasyon demek degildir. Jarvis; frontend, admin, mobil ve operasyon yuzeylerinin bilgiyi ayiklayip dogru sirayla sunmasi demektir.

Her yuzey once su sorulari cevaplar:

1. Ne oluyor veya kullanici hangi durumda?
2. Onemli olan bilgi ne?
3. Bu bilgi ne kadar guncel ve guvenilir?
4. Sorun/degisiklik kimi ya da neyi etkiliyor?
5. Kullanici veya yonetici simdi ne yapabilir?
6. Iddiayi dogrulayan kanit nerede?

### Zorunlu bilgi hiyerarsisi

1. **Durum/Ozet:** Tek bakista anlasilan olgusal sonuc.
2. **Etki/Baglam:** Kimi, neyi, hangi zaman araligini veya hangi akisi etkiledigi.
3. **Aksiyon:** En mantikli sonraki adim ve varsa guvenli alternatifler.
4. **Kanit/Detay:** Ham teknik veri, kimlikler, loglar ve tam zamanlar; varsayilan gorunumu bogmadan istege bagli acilir.

### Tum backlog icin baglayici kurallar

- Ozet once, ham veri sonra gosterilir; fakat ham kanit kaybedilmez.
- Progressive disclosure kullanilir: temel bilgi varsayilan, sorusturma detayi istege baglidir.
- Her sayi, durum, uyari ve otomatik ozet kaynagina ve zaman penceresine geri izlenebilir olmalidir.
- Sistem emin degilse sonuc uydurmaz; `bilinmiyor`, `veri yetersiz` veya `guncel degil` durumunu acikca soyler.
- Tekrarlanan kayitlar kanita dayali olarak gruplanabilir; yanlis gruplama ayrilabilir ve ham kayitlara geri donulebilir olmalidir.
- Renk, ikon veya yapay zeka dili tek basina anlam tasimaz; metin ve kanitla desteklenir.
- Hassas veri varsayilan olarak maskelenir; gosterme/kopyalama ve riskli islemler yetki, gerekce ve audit kurallariyla korunur.
- Kritik veya geri donulemez aksiyonlar normal bilgi okuma akisindan ayrilir; hedef, etki ve sonuc onaydan once aciklanir.
- Kullanici yuzeyinde teknik sistem dili yerine mevcut durum, kalan sure, sonuc ve sonraki adim gosterilir.
- Admin yuzeyinde problem, etki, tekrar, kanit ve aksiyon sirasi kullanilir; dashboard analiz deposuna, detay ekrani ham JSON dokumune donusmez.
- Ilk surum deterministik kurallarla calisabilir; AI ancak gercek fayda, gizlilik, maliyet, yanlis ozet ve insan onayi tasarimi tamamlandiginda eklenir.
- Sadelestirme bilgi veya islev silmek degildir; ikincil bilgi dogru katmana tasinir ve erisilebilir kalir.

### Bir backlog maddesi ne zaman Jarvis uyumlu sayilir?

- Bes saniyelik bakista ana durum ve birincil aksiyon anlasilir.
- Varsayilan gorunum karar vermek icin yeterlidir ama gereksiz teknik ayrinti tasimaz.
- Detay acildiginda ozetin dayandigi kanit bulunabilir.
- Loading, bos, stale, kismi hata, bilinmeyen ve yetkisiz durumlari ayri ele alinmistir.
- Masaustu, mobil, klavye, ekran okuyucu, uzun metin ve buyuk yazi davranisi dogrulanmistir.
- Once/sonra ekran goruntusu ve veri/API karsilastirmasi ile ozetin dogru oldugu kanitlanmistir.

## 1. Kilitli urun kararlari

- TalkX global bir anonim sohbet urunudur.
- Rastgele birebir anonim eslesme cekirdek deneyimdir.
- Global anonim eslesme varsayilan kapsamdir. Kullanici isterse kendi ulkesini kesin eslesme kapsami olarak secebilir; sistem dusuk bulunabilirlikte Global'i yalniz onerir, kullanici onayi olmadan kapsami sessizce genisletmez.
- Ilk surumde eslesme kapsami yalniz `Global` ve sunucunun kullanici icin dogruladigi gercek ulke adindan olusur. Manuel ulke secimi, dil/yas/ilgi filtresi, canli havuz sayisi ve gelismis eslesme tercihleri bu karar kapsaminda degildir.
- TalkX'i 18+ urun olarak yeniden konumlandirma karari yoktur.
- Hesap sistemi; anonim eslesme, arkadas ekleme ve kalici arkadas sohbetini destekler.
- Magaza veya bolgesel uyum sorunlari urun kimligini sessizce degistirmeden ayrica cozulur.
- Bu envanter tamamlanmadan yeni ozellik gelistirmeye baslanmaz.
- Buradaki maddeler hemen uygulanmayacak; istedigimiz zaman oncelik sirasiyla ele alinacak.
- Tum mevcut ve yeni frontend, admin, mobil ve operasyon maddeleri `Ana tema: Jarvis bilgi modeli` kurallarina tabidir.

- TalkX hesap kaydinda e-posta toplanmaz ve sifre unutuldugunda hesap kurtarma sunulmaz. Kayit ekranindaki `Onemli Uyari` bu bilincli anonimlik kararini aciklar; bu politika degismedikce sifre sifirlama/kurtarma ozelligi backlog eksigi sayilmaz.
- TalkX icin ayri bir genel bildirim tercih merkezi veya pazarlama/operasyon bildirim siniflari kurulmaz. TalkX Sistem mesajlari normal mesaj bildirimi gibi davranir; push izni kapali olsa bile kalici Sistem sohbetinde gorunur.
- 2026-09-02 itibariyla ekran ve urun kesif backlogu yeterli kabul edilir. Yeni kanitsiz fikirlerle dosya buyutmek yerine sonraki asama mevcut maddeleri ayiklama, bagimliliklandirma, onceliklendirme ve uygulanabilir paketlere bolmedir.

## 2. Isaretler

- [ ] Acik madde.
- [x] Uygulanmis ve QA ile dogrulanmis madde.
- P0: Canli servis, guvenlik, veri kaybi veya dagitim engeli.
- P1: Cekirdek deneyim veya guvenilirlik.
- P2: Kalite, bakim, performans veya operasyon.
- P3: Sonraki donem fikri.
- MANUAL: Tarayici, cihaz veya panelde elle kontrol edilecek.
- VERIFIED: Kod, Git, build veya canli yanitla dogrulandi.
- JARVIS: Durum/ozet, etki/baglam, aksiyon ve kanit/detay hiyerarsisi uygulanacak.

## Plan belge yönlendirmesi

> 2026-09-25 itibarıyla üç kalıcı uygulama planı ile canonical Wave Map hazırdır. Wave 01–15 ve Wave 17 Sale Release kapsamları auto-verified/committed/manual-QA-deferred kapanışındadır. Wave 16 PAS kaydı DEFERRED / ROADMAP / COMMITTED olarak kapandı; Wave 18–19 başlatılmamıştır.

| Plan | Canonical dosya | Birincil sahiplik |
|---|---|---|
| Plan A — Product & Client Experience | [`TALKX_PLAN_A_PRODUCT_CLIENT.md`](TALKX_PLAN_A_PRODUCT_CLIENT.md) | Ürün, UI/UX, Web frontend, Android WebView kullanıcı akışları |
| Plan B — Platform, Realtime & Data | [`TALKX_PLAN_B_PLATFORM_REALTIME_DATA.md`](TALKX_PLAN_B_PLATFORM_REALTIME_DATA.md) | Backend, API, WebSocket, matchmaking, PostgreSQL ve veri yaşam döngüsü |
| Plan C — Admin, Trust & Release | [`TALKX_PLAN_C_ADMIN_TRUST_RELEASE.md`](TALKX_PLAN_C_ADMIN_TRUST_RELEASE.md) | Admin, moderasyon, global uyum, analitik, legal, release ve operasyon |
| Wave Map — Yürütme sırası | [`TALKX_WAVE_MAP.md`](TALKX_WAVE_MAP.md) | 19 wave'in sırası, stable ID sahipliği, durum ve giriş/çıkış sınırları |
| Wave planları — klasör ve sözleşme | [`waves/README.md`](waves/README.md) | 19 wave için dosya adı, hazırlık/aktivasyon ayrımı ve agent okuma sırası |
| Wave 01 Planı — Auto-verified / committed / manual QA deferred | [`waves/TALKX_WAVE_01.md`](waves/TALKX_WAVE_01.md) | Yalnız Wave 01 kapsamı, kanıt, checkpoint havuzu ve durma noktası |
| Wave 02 Planı — Auto-verified / committed / manual QA deferred | [`waves/TALKX_WAVE_02.md`](waves/TALKX_WAVE_02.md) | Platform/admin erişim temeli, otomatik kanıt ve checkpoint havuzu |
| Wave 03 Planı — Auto-verified / committed / manual QA deferred | [`waves/TALKX_WAVE_03.md`](waves/TALKX_WAVE_03.md) | Yalnız Wave 03 client foundation, accessibility/auth UX, otomatik kanıt ve checkpoint havuzu |
| Wave 04 Planı — Auto-verified / committed / manual QA deferred | [`waves/TALKX_WAVE_04.md`](waves/TALKX_WAVE_04.md) | Health, migration/runtime, performans sözleşmesi, runbook ve checkpoint kanıtı |
| Wave 05 Planı — Auto-verified / committed / manual QA deferred | [`waves/TALKX_WAVE_05.md`](waves/TALKX_WAVE_05.md) | Reconnect, active state, gerçek presence, client recovery ve Checkpoint A kanıtı |
| Wave 06 Planı — Auto-verified / committed / manual QA deferred | [`waves/TALKX_WAVE_06.md`](waves/TALKX_WAVE_06.md) | Veri registry, canonical ülke, fail-closed privacy/retention, hesap silme ve support operasyon kanıtı |
| Wave 07 Planı — Auto-verified, manual QA deferred | [`waves/TALKX_WAVE_07.md`](waves/TALKX_WAVE_07.md) | Yalnız Wave 07 QA-014 server-otoriteli arama yaşam döngüsü, UI/UX, kanıt planı ve durma noktası |
| Wave 08 Planı — Auto-verified / committed / manual QA deferred | [`waves/TALKX_WAVE_08.md`](waves/TALKX_WAVE_08.md) | Yalnız Wave 08 QA-017 Global/Kendi Ülkem queue, UI, analytics ve Home dilimi; kanıt planı ve durma noktası |
| Wave 09 Planı — Auto-verified / committed / manual QA deferred | [`waves/TALKX_WAVE_09.md`](waves/TALKX_WAVE_09.md) | Yalnız Wave 09 QA-003 pending-match protokolü, teklif/kabul UI'si, kanıt planı ve durma noktası |
| Wave 10 Planı — Auto-verified / committed / manual QA deferred | [`waves/TALKX_WAVE_10.md`](waves/TALKX_WAVE_10.md) | Yalnız Wave 10 kalıcı metin mesajı idempotency, outbox, retry ve ordering; medya handoff'u, kanıt planı ve durma noktası |
| Wave 11 Planı — Auto-verified / committed / manual QA deferred | [`waves/TALKX_WAVE_11.md`](waves/TALKX_WAVE_11.md) | Yalnız Wave 11 tek kullanımlık medya, moderasyon kanıtı, sohbet güven aksiyonları ve A-FRIEND-003 medya kapanışı; kanıt planı ve durma noktası |
| Wave 12 Planı — Auto-verified / committed / manual QA deferred | [`waves/TALKX_WAVE_12.md`](waves/TALKX_WAVE_12.md) | Yalnız Wave 12 QA-013 sürümlü legal yayın, reaccept/session recovery ve ayarlar-destek-hesap silme yüzeyleri; kanıt planı ve durma noktası |
| Wave 13 Planı — Auto-verified / committed / manual QA deferred | [`waves/TALKX_WAVE_13.md`](waves/TALKX_WAVE_13.md) | Yalnız Wave 13 QA-010/015 locale, çok dilli bildirim, kalıcı TalkX Sistem inbox ve güvenli kampanya teslimi; kanıt planı ve durma noktası |
| Wave 14 Planı — Auto-verified / committed / manual QA deferred | [`waves/TALKX_WAVE_14.md`](waves/TALKX_WAVE_14.md) | Yalnız Wave 14 B-ANL-001, C-ANL-001, C-ADMIN-002 ve C-ADMIN-003; ölçüm birimleri, ordered funnel, journey kanıtı, Dashboard ve aktivite özeti; Wave 16 Release Health için dürüst provider-pending sınırı |
| Wave 15 Planı — Auto-verified / committed / manual QA deferred | [waves/TALKX_WAVE_15.md](waves/TALKX_WAVE_15.md) | Yalnız Wave 15 C-ADMIN-004, C-ADMIN-005 ve C-ADMIN-006; güvenli profil listesi/detayı, doğru session-geo-relation anlamları, rapor lifecycle/grouping, hassas kanıt ve auditli operasyon aksiyonları |
| Wave 16 Planı — Deferred / Roadmap / committed | [`waves/TALKX_WAVE_16.md`](waves/TALKX_WAVE_16.md) | Wave 04 baseline yeterliliği doğrulandı; B-OBS-002 ve C-REL-001'in ingestion, redaction, grouping/rollup ve gelişmiş Release Health kapsamı Post-acquisition Roadmap'te açık korundu |
| Wave 17 Planı — Auto-verified / committed / manual QA deferred | [`waves/TALKX_WAVE_17.md`](waves/TALKX_WAVE_17.md) | Sale minimumu: frontend lint/build/test, backend syntax/core/critical test, live-target ve zero-test guard, high-severity audit ve iki repoda basit SHA-pinned GitHub CI; enterprise matris Roadmap'te açık |
| Wave 18 Planı — Hazır, aktif değil | [waves/TALKX_WAVE_18.md](waves/TALKX_WAVE_18.md) | Yalnız Wave 18 C-MOB-001 ve A-MOB-001; ortak release/version kaynağı, frontend/Capacitor/Gradle artifact zinciri, signing/manifest/store güvenliği ve Android WebView back/lifecycle/network/push/media eşliği |
| Wave 19 Planı — Hazır, aktif değil | [`waves/TALKX_WAVE_19.md`](waves/TALKX_WAVE_19.md) | Yalnız Wave 19 C-QA-001; bütünleşik admin/operasyon/release QA, release candidate freeze, evidence reconciliation, manuel matris, kullanıcı onayı ve terminal durma noktası |

Belge rolleri:

- Bu master backlog kilitli ürün kararlarını, başlangıç kanıtını, QA-001–017 kayıtlarını, manuel inceleme envanterini ve Fikir Parkı'nı korur.
- Plan A/B/C uygulama ayrıntısının, stable ID'lerin, bağımlılıkların ve kabul kriterlerinin canonical kaynağıdır.
- Çapraz özellikler kopyalanmaz; birincil plan sözleşmeyi sahiplenir, diğer planlar stable ID ile tüketir.
- `TALKX_WAVE_MAP.md` yalnız sıralama/durum ve Plan A/B/C katılımını taşır; ayrıntılı planlar `waves/TALKX_WAVE_NN.md` kalıbıyla saklanır. Hazırlanmış Wave 01–19 dosyaları yalnız kendi ID'lerinin uygulama sınırı ve kanıt kapısını taşır. Dosyanın varlığı aktivasyon yetkisi değildir.
- Bir wave mimariyi yeniden yazmaz; ilgili plan maddesine ve kabul kriterine yönlendirir.
- Yeni karar önce master/ilgili plana işlenmeden wave içinde uygulanmaz.
- Planların ve Wave Map'in hazır olması kod, migration, test, deploy veya ilk wave için başlangıç yetkisi değildir.

## 3. TalkX bugün nedir?

TalkX; hesap olusturan kullanicilari rastgele birebir anonim metin sohbetinde bulusturan, sohbet sonrasinda arkadas eklemeye ve kalici arkadas mesajlasmasina gecmeye izin veren global bir iletisim uygulamasidir.

Cekirdek dongu:

1. Kayit ol veya giris yap.
2. Guncel yasal metinleri kabul et.
3. Anonim eslesme kuyruguna gir.
4. Eslesmeyi kabul veya reddet.
5. Gecici anonim metin sohbeti yap.
6. Gerekirse raporla veya engelle.
7. Iletisimi arkadasliga tasi.
8. Arkadas modunda kalici mesaj ve kontrollu fotograf kullan.

Mevcut parcalar:

- Web frontend ve Render backend
- Neon PostgreSQL ana veritabani
- WebSocket eslesme ve mesajlasma
- Arkadaslik ve kalici direkt mesajlar
- Push bildirimleri
- Destek bildirimi ve medya ekleri
- Rapor, engel, ban ve moderasyon
- Admin paneli, analitik ve operasyon ekranlari
- Yasal metin ve yeniden kabul akisi
- Hesap silme talebi
- Capacitor Android uygulamasi

## 4. Baslangic durum kaniti

- VERIFIED: Backend ve frontend kendi Git depolarinda temiz ve uzak main ile ayniydi.
- VERIFIED: Canli web ve kontrol edilen yasal deep-linkler HTTP 200 dondu.
- VERIFIED: Canli backend /health ve /api/legal HTTP 200 dondu.
- VERIFIED: TalkX origin CORS kontrolunden gecti; yabanci origin'e izin verilmedi.
- VERIFIED: 19 backend JavaScript dosyasi syntax kontrolunden gecti.
- VERIFIED: Frontend production build basarili oldu.
- VERIFIED: Frontend lint 7 hata ve 9 uyari verdi.
- VERIFIED: Backend dependency audit 2 kritik dahil 24 bulgu verdi.
- VERIFIED: Frontend dependency audit 11 yuksek dahil 14 bulgu verdi.
- VERIFIED: Android web assetleri yerel frontend build'iyle eslesti.
- VERIFIED: Frontend surumu 0.0.0, Android surumu 1.0.5 idi.
- VERIFIED: Android ve ortak release dosyalari aktif backend/frontend Git depolarinin disinda kaldi.

## 5. Urun ve konumlandirma

- [ ] [P1] TalkX'in tek cumlelik global urun vaadini kesinlestir.
- [ ] [P1] Anonim ifadesinin kullanicilar arasi mi, servis duzeyinde mi oldugunu tum metinlerde acikla.
- [ ] [P1] Privacy-focused iddiasini gercek veri akislariyla karsilastir.
- [ ] [P1] Anonim sohbetten arkadasliga gecisi urunun ana farki olarak netlestir.
- [ ] [P1] Anonim ve arkadas modlarindaki veri saklama farkini kullaniciya acik goster.
- [ ] [P1] Global hedef dilleri ve ilk pazarlar daha sonra kararlastirilmak uzere kaydedilsin.
- [ ] [P2] Web, Android ve magaza aciklamalari tek urun tanimiyla uyumlu olsun.
- [ ] [P2] app-ads.txt dosyasinin mevcut veya gelecek reklam planiyla ilgisini netlestir.
- [ ] [P2] Reklam acilirsa privacy, consent ve Data Safety birlikte guncellensin.
- [ ] [P3] Yeni fikirler cekirdek backlog yerine fikir parkina yazilsin.

## 6. Global erisim, yas ve platform uyumu

> Urun 18+ olarak yeniden konumlandirilmayacak. Buradaki maddeler global dagitim gercegini urun kimligini bozmadan cozmek icindir.

- [ ] [P0] [MANUAL] Google Play anonim/rastgele sohbet yas kisitlama mekanizmasinin TalkX'e etkisini Play Console'da kesinlestir.
- [ ] [P0] Urun kimligini degistirmeden kullanilabilecek magaza, bolge, yas veya dagitim seceneklerini karsilastir.
- [ ] [P0] CSAE/CSAM icin politika metninin yaninda gercek inceleme ve yetkili makam bildirim proseduru tanimla.
- [ ] [P0] Cocuk guvenligi irtibat kisisi ve iletisim adresini dogrula.
- [ ] [P1] Uygulama ici rapor, engel ve destek mekanizmalarini magaza beyanlariyla karsilastir.
- [ ] [P1] Hedef kitle, Data Safety ve content rating cevaplarini kod ve veri akislariyla yeniden dogrula.
- [ ] [P1] Terms, Privacy, Community Guidelines ve Child Safety Ingilizcesini elle gozden gecir.
- [ ] [P2] Ulke ve bolge bazli uyum matrisi olustur.

## 7. Frontend teknik backlog

> JARVIS frontend kurali: Kullanici once mevcut durumu, sonucun anlamini ve birincil sonraki adimi gorur; hata kodu, baglanti ayrintisi ve teknik kanit ikincil detayda kalir.

- [x] [P1] Lint'teki 7 hata ve 9 uyariyi tek tek siniflandir ve temizle.
- [ ] [P1] Uygulama surumunu 0.0.0 yerine gercek release surumunden uret.
- [ ] [P1] App.jsx icindeki WebSocket, push, outbox, auth, legal ve navigasyonu test altinda kademeli ayir.
- [x] [P1] localStorage session token riskini degerlendir.
- [ ] [P1] Reconnect, outbox retry ve duplicate-message davranisini test et.
- [ ] [P1] Eslesme kabul, red ve timeout durumlarini test et.
- [x] [P1] Anonim ve arkadas chat state'lerinin birbirine karismadigini test et.
- [ ] [P1] Fotograf gonderme, acma ve expire akisini web/Android'de test et.
- [ ] [P1] Legal reaccept akisini eski ve yeni hesaplarla test et.
- [ ] [P1] Arkadas sohbeti presence sozlesmesini tamamla: `/friends/list` cevabinda `is_online` ile `last_seen_at` birlikte donsun; authenticated WebSocket baglanma, kopma ve yeniden baglanma yasam dongusu son gorulme zamanini guvenilir bicimde guncellesin; `activeFriend` verisi `ChatScreen` header'ina aktarilsin.
- [ ] [P1] Arkadas sohbeti header aksiyonlarini ortak bir UI standardina tasi: rapor ve cikis butonlari anlasilir ikon/etiket, tooltip/aria-label, tutarli hiyerarsi, yeterli tiklama alani, focus/hover/pressed durumlari ve mobil tasma davranisi kazansin.
- [ ] [P1] Anonim eslesme teklif/kabul ekranini QA-003 tasarim yonune gore yeniden tasarla: eslesme ani guclu bir kart hiyerarsisi, anlasilir geri sayim/progress, `Sohbete Basla` ana aksiyonu, `Gec` ikincil aksiyonu ve `Eslesmeyi iptal et` ucuncul aksiyonuyla sunulsun; mevcut kabul/red/iptal ve bekleme durumlari korunup responsive ve erisilebilir hale getirilsin.
- [x] [P1] Anonim eslesme arama ekranini QA-014 briefine gore yeniden tasarla: anahtar/radar yerine iki anonim parcacikli ambient animasyon, gercek queue/reconnect durum metinleri, durust gecen sure, eslesmeyi etkilemeyen sohbet havasi secimi, kullanici kontrollu buz kirici karti ve QA-003 kabul ekranina kesintisiz gecis sagla.
- [ ] [P1] QA-017'ye gore Global / kendi ulkem eslesme kapsam secimini mevcut anonim eslesme baslatma kartina ve QA-014 arama yuzeyine yedir: `Global` varsayilan olsun, gercek ulke adi gosterilsin, scope degisimi atomik yeniden arama olarak anlatilsin, ulke beklemesi Global'e yalniz kullanici onayli fallback sunsun ve QA-003 teklif hiyerarsisi degismeden kalsin.
- [ ] [P1] QA-015'e gore Arkadaslar ekranina dogrulanmis TalkX Sistem kaydi ve tek yonlu kalici sohbet ekle: sahte user/friendship olusturma; unread, gecmis/pagination, coklu cihaz read senkronu, guvenli CTA, WebSocket canli ekleme ve push'tan Sistem sohbetine yonlendirmeyi Web/Android'de tamamla.

- [x] [P2] Geri tusu, refresh ve deep-link davranislarini haritala.
- [x] [P2] React hook dependency uyarilarini gider.
- [ ] [P2] Kullanilmayan state ve importlari temizle.
- [ ] [P2] Accessibility lint ve klavye testi ekle.
- [ ] [P2] Tek JS chunk performansini olc.
- [ ] [P2] DiceBear avatar servisinin privacy etkisini degerlendir.
- [ ] [P2] Web/native environment ayarlarini standartlastir.
- [ ] [P2] Bos, loading, error, offline ve reconnect state'lerini standartlastir.
- [ ] [P3] Tasarim tokenlari, spacing, typography ve breakpoint standardi olustur.

## 8. Backend, API ve WebSocket backlog

> JARVIS backend kurali: API ham kaniti korurken ozet icin gerekli guvenilir durum, zaman, kaynak ve hata semantigini acik tasir; frontend sonuc tahmin etmek zorunda kalmaz.

- [ ] [P0] Token olmadan guest/legacy WebSocket fallback'e dusulmesini guvenli hale getir.
- [ ] [P0] WebSocket maxPayload siniri belirle.
- [ ] [P0] Anonim ve direkt mesajlar icin maksimum metin uzunlugu belirle.
- [ ] [P0] Tum WebSocket event payloadlarini schema ile dogrula.
- [ ] [P0] ws, multer, express-rate-limit ve internet yuzeyi bagimliliklarini kontrollu guncelle.
- [ ] [P0] Rate limit'in Render proxy arkasinda gercek kullaniciyi dogru ayirdigini test et.
- [ ] [P1] Origin, kullanici, cihaz ve baglanti bazli abuse limitleri ekle.
- [ ] [P1] Tek kullanimlik fotografin DB boyutu, timeout, silinme ve raporlama davranisini test et.
- [ ] [P1] Direkt mesaj idempotency ve client_msg_id kurallarini DB seviyesinde netlestir.
- [ ] [P1] Session suresi, tum cihazlardan cikis ve sifre degisiminde oturum iptali karari ver.
- [x] [P1] DB'yi de kontrol eden readiness endpoint'i ekle.
- [x] [P1] Health cevabinda deploy commit SHA ve uygulama surumu goster.
- [ ] [P1] Scheduler'in coklu instance'ta duplicate bildirim uretmesini engelle.
- [ ] [P1] Bildirim dagitim sozlesmesini QA-010'a gore yerellestir: anlik, planli ve `run-now` akislari TR/EN icerik haritasi kabul etsin; WS istemcilerini `client.lang`, push tokenlarini `profiles.locale` ile segmentlere ayirsin; bilinmeyen dilde Ingilizce fallback kullansin ve teslimat sonucunu dil bazinda raporlasin.
- [x] [P2] Performans ozet sozlesmesini QA-011'e gore guclendir: esik/SLO, ornek sayisi ve guven durumu, onceki donem farki, `veri yok` semantigi ve etki sirali route ozetini API'den acik tasiyarak adminin ham dakikalik kayitlardan sonuc tahmin etmesini engelle.
- [ ] [P2] Davranis analitigi sozlesmesini QA-012'ye gore yeniden kur: kisi, deneme, eslesme cifti ve sohbet birimlerini ayir; sirali/cohort funnel, onceki donem farki, dusuk ornek guveni ve match/conversation bazli olay hikayesini backend tarafinda acik uret.
- [ ] [P1] Yasal metin yayin sozlesmesini QA-013'e gore guvenli hale getir: taslak/onizleme/yayin ayrimi, alan bazli dogrulama, degisiklik ozeti, surum-reaccept etki hesabi, atomik yayin, audit ve geri alma destegi sagla.
- [x] [P1] Eslesme arama yasam dongusunu QA-014 icin aciklastir: queue onay zamani/search kimligi, iptal onayi, reconnect sonrasi kuyrukta kalma veya yeniden katilma semantigi ve match_offer gecisini frontend'in tahmin etmeyecegi bir event sozlesmesiyle tasir.
- [ ] [P1] QA-017 Global / kendi ulkem eslesme sozlesmesini kur: sunucu otoriteli `GLOBAL|COUNTRY` scope, canonical ISO ulke kodu, scope ve ulke tasiyan `searchId`, tek aktif kuyruk, atomik scope degisimi, ayni scope ile requeue/reconnect, stale event reddi ve kullanici onayli Global fallback eventlerini mevcut block/cooldown/match_offer kurallariyla birlestir.
- [ ] [P1] QA-015 Sistem mesaji altyapisini kur: campaign/recipient modeli, locale, hedef snapshot'i, kalici inbox API'si, read receipt, versiyonlu WebSocket, push dikkat katmani, idempotency, batch/backoff, yetki ve audit.
- [ ] [P1] QA-016 Release Health veri sozlesmesini kur: istemci hata alimi veya secilen gozlemleme saglayicisi adaptoru, schema dogrulama, idempotency, rate limit, PII temizleme, source-map/release esleme, fingerprint gruplama, etkilenen kullanici/session ve onceki release karsilastirmali rollup uretsin.

- [ ] [P2] index.js sorumluluklarini test altinda kademeli ayir.
- [ ] [P2] Tekrarlanan auth middleware'lerini merkezilestir.
- [ ] [P2] API hata kodlari icin tek sozlesme olustur.
- [ ] [P2] Structured logging ve hassas veri maskeleme standardi belirle.
- [ ] [P2] x-powered-by kapat ve guvenlik header katmani ekle.
- [ ] [P2] CORS ve native/no-origin kurallarini belgeleyip test et.

## 9. Admin panel backlog

> JARVIS admin kurali: Her ekran problem/durum, etki, tekrar, kanit ve aksiyon sirasi ile tasarlanir; ham tablo veya metadata varsayilan bilgi mimarisi olamaz.

- [ ] [P0] Admin endpointlerine brute-force/rate limit korumasi ekle.
- [ ] [P0] Basic Auth'un uzun vadeli yeterliligini degerlendir.
- [ ] [P0] Destructive islemlerde CSRF ve yeniden dogrulama ihtiyacini incele.
- [ ] [P1] Ban, shadow ban, unban ve toplu islemlerin audit kaydini test et.
- [ ] [P1] Hesap silmenin tum verileri beklenen kapsamda temizledigini test et.
- [ ] [P1] Raporlanan kullanici, mesaj ve fotograf icin moderator kanitini kontrol et.
- [ ] [P1] Support medya goruntuleme ve silme yetkilerini test et.
- [ ] [P1] Geo lookup hata, rate limit ve unresolved retry davranisini test et.
- [ ] [P1] Notification schedule timezone, duplicate ve run-now davranisini test et.
- [ ] [P2] Admin Dashboard ozet alanini QA-004 tasarim yonune gore yeniden tasarla: ana metrikleri, sistem sagligini ve push teslimat teshisini belirgin bolumlere ayir; canli veri/tazelik, hata ve loading durumlarini gercek veriyle goster; mevcut metrikleri kaybetmeden responsive ve erisilebilir bir gorsel sistem kur.
- [ ] [P2] Dashboard altindaki Kullanici Aktiviteleri ve Son Aktiviteler alanini QA-005 sadelik brief'ine gore yeniden tasarla: grafik ve karar verdiren ozet bilgileri koru; saatlik ham tabloyu istege bagli detaya tasi; ic ice scroll'u kaldir; aktivite akislarini kisa, yerellestirilmis, gruplanabilir ve kolay taranabilir hale getir.
- [ ] [P2] Admin sol navigasyonu QA-006 sadelik brief'ine gore yeniden duzenle: gunluk gorevleri one cikar, iliskili sayfalari gorev odakli gruplandir, seyrek kullanilan sistem/ileri seviye alanlarini ikincillestir, noktalama karakteri ikonlarini gercek bir ikon sistemiyle degistir ve masaustu/mobil navigasyonu erisilebilir hale getir.
- [ ] [P2] Admin Profiller listesini QA-007 okunabilirlik brief'ine gore yeniden tasarla: kolonlari bilgi onceligine gore birlestir/ayir, satir ve kolon takibini guclendir, uzun degerleri kontrollu goster, hassas IP bilgisini koru, filtre/siralama/pagination'i belirginlestir ve tehlikeli tekil/toplu aksiyonlari varsayilan gorunumden sakinlestir.
- [ ] [P1] Admin Profil Detayi yuzeyini QA-008'e gore bastan tasarla ve veri anlamlarini duzelt: profil ozeti, moderasyon, oturum/cihaz, yasal/konum ve iliskileri kademeli bolumlere ayir; `expires_at` degerini gercek session bitisi gibi gostermeyi birak; friendship tarihini dogru kaynaktan getir; hassas alanlari koru ve riskli admin aksiyonlarini audit/onay ile sun.
- [ ] [P1] Uygulama Raporlari liste ve detayini QA-009 Jarvis bilgi modeline gore yeniden tasarla: rapor yasam dongusu ile Brevo teslim durumunu ayir; benzer sorunlari kanita dayali grupla; sorun/etki/tekrar/aksiyon ozetini one al; ham diagnostik ve hassas veriyi acilir kanit katmanina tasi; filtre, pagination, durum yonetimi ve guvenli silme/arsivleme akisini tamamla.
- [ ] [P1] Bildirim Ayarlari ekranini QA-010'a gore cok dilli hale getir: anlik ve planli bildirimlerde Turkce/English baslik-metin alanlari, hedef/fallback ozeti, dil bazli alici tahmini, iki dil onizlemesi, test gonderimi ve dil bazli teslimat sonucu olmadan global gonderime izin verme.
- [ ] [P2] Performans ekranini QA-011 Jarvis modeline gore yeniden tasarla: sistem durumu, esiklere uzaklik, degisim, veri guveni ve etkili route'lari ilk gorunumde ozetle; ham dakika/route tablolarini acilir kanit katmanina tasi; `yavas istek` esigini ve yetersiz ornek durumunu acik goster.
- [ ] [P2] Davranis Analitigi ekranini QA-012 Jarvis modeline gore yeniden tasarla: ana kaybi/anomaliyi ve donusumu ozetle; saatlik tablo, event/platform dagilimi, kullanici tablosu ve raw olay akisini varsayilan gorunumden kaldirip filtrelenebilir kanit katmanina tasi; olaylari match/conversation hikayesi olarak grupla.
- [ ] [P1] Yasal Metinler ekranini QA-013'e gore soft ve kontrollu editor olarak yeniden tasarla: belge kartlariyla durum ozeti, tek belge odagi, TR/EN karsilastirma, son kullanici onizlemesi, dirty-state, diff, surum/reaccept etki uyarisi ve onayli yayin akisi olmadan canli kaydi degistirme.

- [ ] [P1] Sistem Mesajlari ekranini QA-015'e gore tasarla: tek/sectili kisi, ulke/dil/platform/aktiflik/kayit tarihi/herkes hedefleri; TR/EN; alici-dil-push onizlemesi; kendime test; son onay ve teslim/okunma Jarvis ozeti.
- [ ] [P1] Release Health ekranini QA-016 Jarvis modeline gore tasarla: aktif Web/Android surum sagligi, crash-free session, yeni/regresyon hatalari, etkilenen kullanici ve ekranlari etki sirasiyla ozetle; ham stack/device/breadcrumb kanitini maskeli acilir detayda tut; no-data ve dusuk ornek durumunu acik goster.
- [ ] [P2] admin.js ve tek parca admin.html dosyalarini kademeli ayir.
- [ ] [P2] Filtre, pagination, sorting ve bos state'leri standardize et.
- [ ] [P2] Dar ekran, klavye, focus, modal ve tablo scroll davranislarini test et.
- [ ] [P2] Kritik islemlerde sebep/not alanlarini guclendir.

## 10. Veritabani ve veri yasam dongusu

- [x] [P0] Tek buyuk ensureTables sorgusundan surumlu migration sistemine gecis plani yap.
- [x] [P0] Neon backup/restore runbook'unu yeniden dogrula.
- [ ] [P0] Backup sifreleme, saklama suresi ve erisim yetkisini belirle.
- [ ] [P1] Tum tablolar icin veri amaci, sahibi, saklama suresi ve silme matrisi olustur.
- [ ] [P1] Mesaj, report, support media, analytics, push log ve IP/geo retention karari ver.
- [ ] [P1] `notification_schedules` icin surumlu cok dilli icerik semasi/migration'i tasarla; TR/EN varyantlarini tek baslik-metin yerine dogrulanabilir locale haritasinda veya bagli tabloda sakla, mevcut tek dilli planlari otomatik global gondermeden once pasif/ceviri gerekli durumuna tasi.
- [ ] [P1] Yasal icerigi tek canli `app_settings` JSON kaydindan surumlu yayin gecmisine tasiyacak modeli QA-013'e gore tasarla; belge/dil, taslak-yayin, icerik hash'i, yayinlayan admin, gerekce, zaman, onceki surum ve geri alma baglantisini koru.

- [ ] [P1] QA-015 icin system_message_campaigns ve system_message_recipients migration'ini tasarla; locale, hedef snapshot'i, recipient unique/idempotency, teslim/read/CTA, audit, retention ve kullanici silmeyi netlestir.
- [ ] [P1] QA-016 istemci hata verisi sahipligi ve retention modelini kararlastir: self-hosted ise client_error_events/release_health_rollups benzeri surumlu sema; dis saglayici ise yerel ozet/kimlik baglantisi, silme, kaynak haritasi erisimi, bolge ve maliyet sinirlarini belgeleyip hassas veri toplamama kuralini koru.
- [ ] [P1] QA-017 icin hesap/profil seviyesinde canonical eslesme ulkesi modelini tasarla: ISO 3166-1 alpha-2 kodu, kaynak, guven/dogrulama durumu ve guncellenme zamani tutulacak; `legal_acceptances.location_country` tarihsel ve serbest metinli kabul snapshot'i oldugu icin dogrudan eslesme otoritesi yapilmayacak; tam IP/GPS eslesme kaydina kopyalanmayacak.
- [ ] [P1] Hesap silmede silinecek, anonimlestirilecek veya tutulacak veriyi kesinlestir.
- [ ] [P1] Legacy/anon tablolarda orphan veri kontrolu yap.
- [ ] [P1] Pool size, query timeout ve statement timeout belirle.
- [x] [P1] Neon direct endpoint ve search_path=public kuralini runbook'ta koru.
- [ ] [P2] Yavas sorgu ve buyuyen tablo analizi yap.
- [ ] [P2] Staging DB ve migration rollback proseduru kur.

## 11. Test ve kalite kapilari

> JARVIS kalite kapisi: Sadelik yalniz gorsel QA ile degil, ozetin dogrulugu ve ham kanita geri izlenebilirligiyle test edilir.

- [ ] [P0] Eski test_auth_flow.js dosyasini guncel legal kabul akisine gore yeniden tasarla.
- [ ] [P0] Testlerin canli DB'de veri olusturmasini engelleyen ayri test ortami kur.
- [ ] [P1] Backend unit test altyapisi kur.
- [ ] [P1] PostgreSQL integration testleri kur.
- [ ] [P1] Iki istemcili WebSocket/eslesme testleri kur.
- [ ] [P1] [JARVIS] Frontend ve admin icin bes saniyelik anlasilabilirlik testi tanimla: ana durum, etki ve birincil aksiyon ilk gorunumde bulunabilmeli.
- [ ] [P1] [JARVIS] UI ozetlerini API/DB kaynagiyla karsilastiran veri dogrulugu testleri ekle; stale, kismi hata ve bilinmeyen durumlari kapsa.
- [ ] [P1] [JARVIS] Progressive disclosure regresyonu ekle: ham kanit erisilebilir kalirken varsayilan gorunumde hassas/teknik veri acik olmamali.
- [ ] [P1] [JARVIS] Otomatik gruplama, oncelik veya ozet varsa geri izlenebilirlik, yanlis birlestirmeyi geri alma ve `veri yetersiz` davranisini test et.
- [ ] [P1] Bildirim yerellestirme test matrisi kur: TR/EN/null/gecersiz locale, ayni kullanicinin coklu cihazi, WS+push birlikte teslim, anlik/planli/run-now, fallback, duplicate engelleme, test gonderimi ve dil bazli log sayilari.
- [ ] [P2] Performans ozeti test matrisi kur: 0/az/yeterli ornek, esik alti-siniri-ustu, P95 degeri olmayan bucket, hata/spike, onceki donem farki, stale/kismi veri ve route etki siralamasini API/ham kanitla karsilastir.
- [ ] [P2] Davranis analitigi test matrisi kur: sirali ve siradan cikmis eventler, pencere sinirini asan yolculuk, duplicate/reconnect, tek eslesmenin iki katilimci eventi, dusuk ornek, platform/cohort filtresi, onceki donem ve match hikayesi sayilarini ham eventlerle karsilastir.
- [ ] [P1] Yasal yayin test matrisi kur: taslak/kaydet/yayin/geri alma, TR-EN eksigi, placeholder, URL/uzunluk, eszamanli editor, surum degisti-degismedi, reaccept etki sayisi, audit, public API ve web/Android son kullanici onizlemesini kapsa.
- [x] [P1] QA-014 eslesme arama test matrisi kur: hazirlaniyor/queued/uzayan arama/reconnect/offline/iptal/match_offer, sayac yasam dongusu, sohbet havasi ve soru tekrar kurali, secimin kabul-sohbete tasinmasi, reduced-motion ve 100dvh mobil yerlesimi kapsa.
- [ ] [P1] QA-015 test matrisi kur: tek/sectili/segment/herkes, TR-EN-fallback, online/offline, push hatasi, coklu cihaz, unread/read sync, reconnect/retry/duplicate, test gonderimi, CTA allowlist, yetki/audit/rate limit ve Web/Android.
- [ ] [P1] QA-016 Release Health test matrisi kur: Web ErrorBoundary/window/unhandled rejection/chunk, Android native crash ve sonraki acilis teslimi, offline/retry/duplicate, source map, release/build ayrimi, PII redaksiyonu, grouping, az ornek/no-data, baseline/regresyon, crash-free oran ve admin ozetinin ham kanitla dogrulugunu kapsa.
- [ ] [P1] QA-017 Global / kendi ulkem eslesme test matrisi kur: ilk ve donen kullanici varsayimi, ulke yok/gecersiz/stale, Global ve ayni ulke eslesmesi, farkli ulke izolasyonu, arama sirasinda atomik scope degisimi, reconnect/requeue, gecikmis event, fallback kabul/ret, QA-003'e gecis, TR/EN, Web/Android ve gizlilik sinirlarini kapsa.

- [ ] [P1] Frontend component testleri kur.
- [ ] [P1] Kritik web akislari icin E2E testleri kur.
- [ ] [P1] Lint, test, build ve dependency audit'i CI kapisi yap.
- [ ] [P1] Kirmizi kalite kapisiyla main deploy edilmesini engelle.
- [ ] [P2] Fixture, seed ve test temizleme standardi olustur.
- [ ] [P2] Flaky test tekrar dogrulama kurali belirle.
- [ ] [P2] Her release icin web/backend/admin/Android smoke checklist'i olustur.

## 12. Repo, release ve operasyon

- [ ] [P0] Android, Capacitor ve ortak release scriptlerini aktif bir Git reposuna al.
- [ ] [P1] Frontend reposunu web + Capacitor client kaynagi olarak standartlastir.
- [ ] [P1] Eski ust wrapper repo karisikligini arsivleme plani yap.
- [ ] [P1] Frontend 0.0.0, Android 1.0.5 ve backend surumlerini birlestir.
- [ ] [P1] Git tag, changelog, deploy SHA ve rollback standardi belirle.
- [ ] [P1] Render deploy ayarlari ve environment sahipligini belgeleyip dogrula.
- [ ] [P1] Canli frontend asset'i ile kaynak commit arasinda izlenebilirlik sagla.
- [ ] [P1] Secret rotation checklist'i olustur.
- [ ] [P2] Anlamli commit ve PR standardi belirle.
- [ ] [P2] Backend/frontend README'lerini gercek projeyi anlatacak sekilde yenile.
- [ ] [P2] Lokal, staging ve production ortamlarini ayir.
- [ ] [P2] Render, Neon, Firebase ve Brevo sahiplik envanteri olustur.

## 13. Manuel frontend inceleme listesi

> Her manuel turda bes saniyelik anlasilabilirlik, birincil aksiyon, teknik gurultu ve detay/kanit erisimi birlikte kontrol edilir.

### Public ve auth

- [ ] [MANUAL] Ana alan adi ilk acilis, loading ve hata davranisi.
- [ ] [MANUAL] Splash gecis suresi ve gorunumu.
- [ ] [MANUAL] Kayit: bos, kisa, gecersiz ve alinmis username.
- [ ] [MANUAL] Giris: hatali sifre, olmayan hesap, rate limit ve offline.
- [ ] [MANUAL] Terms, Privacy, Community, Child Safety ve Account Deletion deep-linkleri.
- [ ] [MANUAL] Turkce/English ve refresh sonrasi dilin korunmasi.
- [ ] [MANUAL] Mobil, tablet ve genis masaustu responsive kontrolu.
- [ ] [MANUAL] Klavye tab sirasi, focus, Enter ve Escape.

### Giris sonrasi

- [ ] [MANUAL] Profil ve gorunen isim.
- [ ] [MANUAL] Ayarlar: sifre, dil ve hesap silme.
- [ ] [MANUAL] Bildirim/medya izin onboarding'i.
- [ ] [MANUAL] Arkadaslar, istekler, engellenenler ve bos state'ler.
- [ ] [MANUAL] Destek formu: metin, email, medya ve limitler.

### Anonim eslesme

- [ ] [MANUAL] Kuyruga gir, cik ve tekrar gir.
- [ ] [MANUAL] Eslesme kabul, red ve timeout.
- [ ] [P1] [MANUAL] Eslesme teklifi ekranini QA-003 gorsel referansi ile karsilastir; kart hiyerarsisi, geri sayim/progress, `Sohbete Basla`, `Gec` ve `Eslesmeyi iptal et` aksiyonlarini masaustu ve mobilde dogrula.
- [ ] [P1] [MANUAL] Eslesme arama ekranini QA-014 kriterleriyle test et; iki parcacik animasyonu, gercek durum metinleri, sayac, sohbet havasi, soru degistirme/tekrar, aramayi durdurma, reconnect ve QA-003 ekranina gecisi web/Android ile dar-kisa telefonlarda dogrula.
- [ ] [P1] [MANUAL] QA-017 Global / kendi ulkem eslesmesini Web/Android'de dogrula: mevcut anonim eslesme karti ve QA-014 icindeki soft segmented control, gercek ulke adi, Global varsayimi, ulke yok durumu, scope degisimi, ayni scope ile reconnect/requeue, uzun beklemede onayli Global onerisi ve QA-003'un degismeyen hiyerarsisi.
- [ ] [P1] [MANUAL] QA-015 TalkX Sistem sohbetini Web/Android'de dogrula: dogrulanmis satir, tek yonlu gecmis, unread, tek/sectili/segment/herkes, TR/EN, offline kalicilik, push yonlendirme, coklu cihaz read ve CTA.
- [ ] [P1] [MANUAL] QA-016 Release Health'i staging Web/Android'de kontrollu hatalarla dogrula: kullanici recovery ekrani, event redaksiyonu, offline sonraki teslim, release ve ekran gruplama, etkilenen kullanici/session sayisi, yeni/regresyon durumu, no-data ve maskeli kanita gecis.

- [ ] [MANUAL] Iki taraf kabul ettiginde sohbet baslangici.
- [ ] [MANUAL] Normal, uzun, hizli ve emojili mesaj.
- [ ] [MANUAL] Typing gostergesi.
- [ ] [MANUAL] Peer ayrilma, next ve baglanti kopmasi.
- [ ] [MANUAL] Report ve block.
- [ ] [MANUAL] Anonim modda fotografin kapali olmasi.
- [ ] [MANUAL] Sohbetten arkadas eklemeye gecis.

### Arkadas sohbeti

- [ ] [MANUAL] History ve unread sayisi.
- [ ] [MANUAL] Offline/outbox, reconnect ve duplicate engelleme.
- [ ] [MANUAL] Fotograf sec, limit, gonder, ac, expire ve tekrar ac.
- [ ] [MANUAL] Arkadas silme ve block sonrasi erisim.
- [ ] [MANUAL] Push bildirimi ve dogru sohbete yonlenme.
- [ ] [P1] [MANUAL] Arkadas sohbeti header'inda gercek presence durumunu kontrol et: kullanici gercekten online ise Online, degilse guncel ve yerellestirilmis son gorulme bilgisi gosterilmeli.
- [ ] [P1] [MANUAL] Arkadas sohbeti header'indaki rapor bildirme ve cikis aksiyonlarini masaustu/mobilde gorsel hiyerarsi, anlasilabilirlik, erisilebilirlik ve tiklama alani bakimindan yeniden ele al.

## 14. Manuel admin panel inceleme listesi

> Her admin ekraninda `ne oldu, etkisi ne, ne yapmaliyim, kanit nerede` sorulari cevaplanmadan inceleme tamamlanmis sayilmaz.

- [ ] [MANUAL] Yanlis ve dogru admin kimlik bilgisi.
- [ ] [MANUAL] Dashboard metrikleri ve online sayisi.
- [ ] [P2] [MANUAL] Dashboard ozetini QA-004 gorsel referansiyla karsilastir; metrik hiyerarsisi, sistem sagligi, push teslimati, canli veri/tazelik, hata uyarilari ve mobil yerlesimi dogrula.
- [ ] [P2] [MANUAL] Dashboard altindaki Kullanici Aktiviteleri ve Son Aktiviteler alanini QA-005 sadelik kriterleriyle test et; varsayilan gorunumde bilgiye hizli ulasim, detay acma, ic scroll olmamasi, olay metinleri ve mobil yerlesimi dogrula.
- [ ] [P2] [MANUAL] Admin sol navigasyonu QA-006 sadelik kriterleriyle test et; menu sirasi/gruplari, aktif sayfa, ikonlar, rozetler, dar ekran drawer'i, klavye kullanimi ve seyrek kullanilan alanlara erisimi dogrula.
- [ ] [MANUAL] Profil listesi, filtre, siralama, pagination ve geo bilgisi.
- [ ] [P2] [MANUAL] Profiller tablosunu QA-007 kriterleriyle test et; kolon/satir takibi, uzun isim ve IP, filtre/siralama, secim/toplu islemler, tekil aksiyonlar, pagination, dar ekran ve hassas veri gorunurlugunu dogrula.
- [ ] [MANUAL] Profil detayinda arkadas, engel, rapor ve legal bilgi.
- [ ] [P1] [MANUAL] Profil Detayi yuzeyini QA-008 kriterleriyle test et; bilgi bolumleri, session/push semantigi, yasal/konum, rapor/ban/audit, arkadas/engel yonu, hassas alanlar, riskli aksiyonlar, kismi hata, uzun veri ve mobil modal/drawer davranisini dogrula.
- [ ] [MANUAL] Ban, shadow ban, unban ve audit.
- [ ] [MANUAL] Toplu kullanici islemleri.
- [ ] [MANUAL] Support report, detay, medya ve silme.
- [ ] [P1] [MANUAL] Uygulama Raporlari liste/detayini QA-009 Jarvis kriterleriyle test et; sorun ozeti, etki/tekrar, durum-Brevo ayrimi, gruplama, filtre/pagination, ham kanit, medya, hassas veri, arsiv/silme ve mobil modal/drawer davranisini dogrula.
- [ ] [MANUAL] Push health, diagnostics, log ve toplu bildirim.
- [ ] [MANUAL] Notification schedule tum islemleri.
- [ ] [P1] [MANUAL] QA-010 cok dilli bildirim akisini iki TR ve iki EN test hesabi/cihaziyla dogrula; anlik, planli ve Simdi Calistir gonderimlerinde her dilin dogru baslik-metni, fallback'i, onizlemesi ve teslimat ozetini kontrol et.
- [ ] [MANUAL] Performance ve slow requests.
- [ ] [P2] [MANUAL] Performans ekranini QA-011 Jarvis kriterleriyle test et; bes saniyede saglik/degisim/etki/aksiyonun bulunmasini, 1500 ms esiginin gorunurlugunu, az ornek ve `veri yok` ayrimini, grafik-kanit uyumunu, route siralamasini ve dar ekran davranisini dogrula.
- [ ] [P2] [MANUAL] Davranis Analitigi ekranini QA-012 Jarvis kriterleriyle test et; ana kayip/degisim/guven ozetini, ordered funnel'i, birimlerin acikligini, match hikayesine hizli erisimi, kanit tablolarini ve mobil/dar ekran davranisini dogrula.
- [ ] [MANUAL] Analytics overview, funnel, users ve events.
- [ ] [MANUAL] Hesap silme approve, reject ve reactivate.
- [ ] [MANUAL] Legal metin kaydi ve frontend'e yansimasi.
- [ ] [P1] [MANUAL] Yasal Metinler ekranini QA-013 kriterleriyle test et; belge odagi, TR/EN karsilastirma, onizleme, dirty-state, diff, surum/reaccept etki uyarisi, taslak-yayin-geri alma, audit ve mobil/dar ekran davranisini dogrula.
- [ ] [MANUAL] Dar ekran, tablo, modal, scroll ve klavye.
- [ ] [MANUAL] Backend restart ve session davranisi.

## 15. Manuel Android inceleme listesi

> Android yuzeyi ayni Jarvis hiyerarsisini dar ekran, izin, offline/reconnect ve background durumlarinda korumalidir.

- [ ] [MANUAL] Temiz kurulum ve ilk acilis.
- [ ] [MANUAL] Status bar, splash, klavye resize ve geri tusu.
- [ ] [MANUAL] Bildirim, kamera ve galeri izinleri.
- [ ] [MANUAL] Background/foreground WebSocket reconnect.
- [ ] [MANUAL] Ag degisimi, ucak modu ve zayif internet.
- [ ] [MANUAL] Push foreground/background/kapali uygulama.
- [ ] [MANUAL] Release surum ve asset dogrulamasi.
- [ ] [MANUAL] Legal ve hesap silme deep-linkleri.

## 16. Manuel bulgu gunlugu

> Her yeni bulgu yalniz gorsel sorunu degil, bilginin nasil suzulup hangi ozet/aksiyon/kanit sirasi ile sunulacagini da kaydeder.

Her bulgu su formatla eklenecek:

### QA-XXX - Kisa baslik

- Tarih:
- Alan: Frontend / Backend / Admin / Android / Canli servis
- Ortam:
- Adimlar:
- Beklenen:
- Gerceklesen:
- Kanit:
- Oncelik: P0 / P1 / P2 / P3
- Durum: Acik / Tekrar dogrulanacak / Kapali

### QA-001 - Arkadas sohbeti header'i gercek presence yerine Online gosteriyor

- Tarih: 2026-09-01
- Alan: Frontend / Backend / Canli servis
- Ortam: Canli web, arkadas sohbeti header'i
- Jarvis hedefi: Gercek ve guncel durumu tek satirda soyle; online degilse guvenilir son gorulmeyi goster, stale/bilinmeyen veriyi online diye sunma.
- Adimlar: Online olmayan bir arkadasla mevcut sohbeti ac; kullanici adi altindaki durum satirini kontrol et.
- Beklenen: Arkadas gercekten bagliysa yesil durum ile `Online` gosterilmeli. Bagli degilse son guvenilir aktivite zamanina gore yerellestirilmis bir `Son gorulme ...` bilgisi gosterilmeli. Sohbetin bitmesi, baglantinin gecici kopmasi ve gercek offline durumu birbirine karistirilmamali; durum sayfa yenilenmeden de guncellenebilmeli.
- Gerceklesen: Arkadas online olmasa bile header'da `Online` yaziyor. `ChatScreen` sohbet bitmedigi surece presence verisi okumadan `common.online` metnini sabit olarak gosteriyor.
- Teknik kapsam: `/friends/list` halihazirda `is_online` donduruyor fakat `last_seen_at` dondurmuyor. `ChatScreen` tarafina `is_online` veya `last_seen_at` aktarilmiyor. Authenticated kullanicilar icin WebSocket baglanma/kopma/reconnect akisi `last_seen_at` guncelligini garanti edecek sekilde netlestirilmeli.
- Kabul kriterleri:
  - Presence icin tek kaynak ve online/offline kurali belgelenmis olmali.
  - Arkadas verisi `is_online` ve `last_seen_at` alanlarini birlikte tasimali.
  - Authenticated WebSocket yasam dongusu son gorulme zamanini coklu cihaz ve ani kopma durumlarinda makul dogrulukla guncellemeli.
  - `activeFriend` presence verisi sohbet header'ina aktarilmali; online durum degisimi yeniden yukleme gerektirmeden yansimali.
  - Son gorulme metni TR/EN icin yerellestirilmeli; gecersiz veya bilinmeyen zaman icin guvenli bir fallback bulunmali.
  - Online, offline, stale veri, reconnect ve coklu cihaz senaryolari otomatik ve manuel olarak test edilmeli.
- Kanit: `codex-clipboard-e3c5b5b6-4fff-40c8-aab0-15a4639d39ac.png`; `chatapp-frontend/src/screens/ChatScreen.jsx`; `chatapp-frontend/src/App.jsx`; `chatapp-backend/routes/friends.js`
- Oncelik: P1
- Durum: Acik

### QA-002 - Rapor bildirme ve cikis butonlari gorsel olarak zayif

- Tarih: 2026-09-01
- Alan: Frontend / UX
- Ortam: Canli web, arkadas sohbeti header'i
- Jarvis hedefi: Kullanicinin iki aksiyonun anlamini ve sonucunu ilk bakista ayirmasini sagla; riskli aksiyonu acik etiket ve geri bildirimle koru.
- Adimlar: Bir arkadas sohbetini ac; header'in sag tarafindaki rapor ve cikis aksiyonlarini masaustu ile dar ekran genisliklerinde incele.
- Beklenen: Iki aksiyon da ne yaptigini ilk bakista anlatmali, sohbet basligi ile hizali ve ayni tasarim sistemine ait gorunmeli. Rapor aksiyonu hata rozeti gibi algilanmamali; cikis aksiyonu onemli fakat arayuzu gereksiz yere domine etmeyen acik bir hiyerarsiye sahip olmali.
- Gerceklesen: Rapor butonu yalnizca kucuk bir `!` isareti olarak gorunuyor; anlam ve tiklanabilirlik zayif. Cikis aksiyonu da rapor butonuyla birlikte kopuk, kucuk ve dengesiz gorunuyor.
- Kabul kriterleri:
  - Rapor aksiyonu taninabilir ikon ve/veya acik etiketle sunulmali; tooltip ve `aria-label` bulunmali.
  - Cikis aksiyonunun metni ve danger/secondary hiyerarsisi sohbet baglamina gore kesinlestirilmeli.
  - Her iki aksiyon icin en az 44x44 px dokunma alani, tutarli bosluk, hizalama ve ikon olcegi saglanmali.
  - Default, hover, focus-visible, pressed ve disabled durumlari tanimli olmali; klavye ile erisilebilmeli.
  - Dar ekranda kullanici adi veya durum metniyle cakismamali; gerekiyorsa kontrollu overflow/menu davranisi kullanilmali.
  - Raporlama ve sohbetten cikis onay/geri bildirim akislarinin mevcut davranisi korunmali ve manuel regresyon testi yapilmali.
  - Masaustu ve mobil ekran goruntusu QA'i ile gorsel tutarlilik dogrulanmali.
- Kanit: `codex-clipboard-e3c5b5b6-4fff-40c8-aab0-15a4639d39ac.png`; `chatapp-frontend/src/screens/ChatScreen.jsx`
- Oncelik: P1
- Durum: Acik
### QA-003 - Anonim eslesme kabul ekrani yeni tasarim yonune tasinmali

- Tarih: 2026-09-01
- Alan: Frontend / UX
- Ortam: Canli web, anonim eslesme sonrasi teklif/kabul ekrani
- Jarvis hedefi: Eslesme bulundu, kiminle, ne kadar sure kaldi ve Kabul/Gec/Iptal eylemlerinin farki tek bakista anlasilsin; protokol detayi gorunmesin.
- Adimlar: Anonim eslesmeye gir; bir eslesme bulundugunda kabul ekrani acilana kadar bekle; mevcut ekrani onaylanan tasarim yonuyle masaustu ve mobilde karsilastir.
- Beklenen: Eslesme ani urunun ana deneyimlerinden biri gibi guclu ve heyecan verici sunulmali. Onaylanan yon; merkezde belirgin neon/glass kart, eslesmeyi anlatan gorsel, net baslik-alt baslik, tek ve okunakli kullanici kimligi, zamana bagli progress, guclu ana CTA ve sakinlestirilmis ikincil/ucuncul aksiyon hiyerarsisidir.
- Gerceklesen: Mevcut ekran kucuk ve sade bir kart, tekrarlanan kullanici adi, yalnizca metin tabanli geri sayim ve birbirine yakin agirliktaki `RED`/`KABUL` butonlari kullaniyor. Kart ile disaridaki `IPTAL ET` butonu butunlesik bir deneyim olusturmuyor; eslesme ani yeterince belirgin ve rafine hissettirmiyor.
- Onaylanan tasarim yonu: `docs/assets/manual-qa/qa-003-approved-design-direction.png`. Bu gorsel piksel piksel kopyalama zorunlulugu degil; kompozisyon, hiyerarsi, neon pembe/cyan dil, geri sayim progress'i ve aksiyon seviyeleri icin ana referanstir.
- Davranis eslemesi:
  - `Sohbete Basla` mevcut `onAccept` davranisina baglanmali ve ana aksiyon olmali.
  - `Gec` mevcut `onReject` davranisina baglanmali; yalnizca bu eslesme teklifini reddetmeli.
  - `Eslesmeyi iptal et` mevcut `onCancel` davranisina baglanmali; eslesme/kuyruk surecini tamamen sonlandirmali.
  - Kullanici kabul ettikten sonra CTA tekrar tetiklenmemeli; `waitingPeer` durumu acikca gosterilmeli.
- Kabul kriterleri:
  - Baslik, aciklayici alt metin ve karsi taraf bilgisi tekrarsiz, dengeli ve TR/EN yerellestirmeye uygun olmali.
  - Geri sayim `autoAcceptAt` ile senkron bir progress gostergesi ve kalan saniye metniyle sunulmali; sifira gelme, gecikmis/stale teklif ve yeniden baglanma durumlari dogru ele alinmali.
  - Kullanilan avatar eslesmenin anonim niteligini bozmamali; gercek avatar verisi sozlesmede yoksa urun diline uygun jenerik bir gorsel kullanilmali.
  - Referanstaki yesil online noktasi ancak gercek ve guvenilir presence verisi varsa kullanilmali; dekoratif veya varsayilan `online` gostergesi eklenmemeli.
  - `peerAcceptedHint`, kullanicinin kabul edip karsi tarafi beklemesi, red, timeout, iptal, peer ayrilmasi ve baglanti kopmasi durumlarinin her biri ayri ve anlasilir geri bildirim vermeli.
  - Ana, ikincil ve ucuncul aksiyonlar renk, boyut ve konumla ayirt edilmeli; tum tiklama alanlari en az 44x44 px olmali.
  - Klavye focus sirasi, focus-visible, ekran okuyucu etiketleri, yeterli kontrast ve `prefers-reduced-motion` destegi bulunmali.
  - Kart 320 px civari dar mobil ekranlardan genis masaustune kadar tasmadan calismali; uzun kullanici adi ve uzun TR/EN metinleri test edilmeli.
  - Gorsel efektler dusuk seviye cihazlarda akici kalmali; agir bitmap zorunlu olmamali ve mevcut urun tokenlariyla uygulanabilmeli.
  - Kabul, red/gec, otomatik kabul, iptal, peer accepted ve timeout akislarinda fonksiyonel regresyon testi; masaustu/mobil ekran goruntusu QA'i yapilmali.
- Kanit:
  - Mevcut ekran: `docs/assets/manual-qa/qa-003-current-match-offer.png`
  - Onaylanan tasarim yonu: `docs/assets/manual-qa/qa-003-approved-design-direction.png`
  - Ilgili kod: `chatapp-frontend/src/screens/MatchScreen.jsx`, `chatapp-frontend/src/i18n/messages.tr.js`, `chatapp-frontend/src/i18n/messages.en.js`
- Oncelik: P1
- Durum: Acik
### QA-004 - Admin Dashboard ozet ve sistem sagligi alani yeniden tasarlanmali

- Tarih: 2026-09-01
- Alan: Admin / UX / Canli servis
- Ortam: Canli web admin paneli, Dashboard ust ozet alani
- Jarvis hedefi: Sistem normal mi, ne sorunlu, hangi zaman penceresi kullaniliyor ve ne incelenmeli sorularini ham metriklere dalmadan cevapla.
- Adimlar: Admin paneline gir; Dashboard sekmesindeki ozet kartlarini, API/push metriklerini ve Push Teshis alanini masaustu ile dar ekranlarda incele; mevcut ekran ile onaylanan tasarim yonunu karsilastir.
- Beklenen: Dashboard ilk bakista urunun genel durumunu okutabilmeli. Ana is metrikleri, sistem sagligi ve push teslimat teshisi ayri fakat ayni tasarim sistemine ait bolumlerde sunulmali; sayilarin anlami, zaman araligi, veri tazeligi ve sorun seviyeleri kolayca ayirt edilebilmeli.
- Gerceklesen: Dokuz kart tek bir akista farkli onem seviyeleriyle yan yana diziliyor; ikinci satir yarim kaliyor. Harf tabanli ikonlar, kucuk alt metinler ve alttaki yogun Push Teshis satiri gorsel hiyerarsiyi zayiflatiyor. Kritik, bilgilendirici ve saglik metrikleri birbirine karisiyor; alan calissa da ilk bakista rafine ve rahat okunur gorunmuyor.
- Onaylanan tasarim yonu: `docs/assets/manual-qa/qa-004-approved-dashboard-direction.png`. Bu gorsel piksel piksel kopyalama zorunlulugu degil; bolumleme, kart hiyerarsisi, ikon dili, bosluklar, canli veri kontrolu, sistem sagligi ve push teslimat sunumu icin ana referanstir.
- Bilgi mimarisi:
  - `Genel Bakis`: Toplam Kullanici, Anlik Online, Aktif Sohbet ve Kullanici Raporlari (24s) ana kartlari.
  - `Sistem Sagligi`: API P95 (60 dk), API Hata Orani (60 dk), Push (60 dk) ve Push Firebase durumu.
  - `Push Teslimati - Son 24 saat`: Beklenen proje, kimlik kaynagi, gonderim/hata, gecersiz token, cihaz tazeligi ve en sik hata.
  - Mevcut `Uygulama Raporlari (24s)` verisi yeni tasarimda sessizce kaldirilmamali; ana kartlarda veya uygun bir rapor/uyari alaninda gorunurlugu korunmali.
- Kabul kriterleri:
  - Mevcut veri baglari korunmali: `/admin/stats`, `/admin/push/health?minutes=60`, `/admin/push/diagnostics?hours=24` ve `/admin/performance/overview?hours=1` kaynaklarindaki metrikler yeni yapida dogru alanlara eslenmeli.
  - `Canli veriler` gostergesi veri tazeligi ve son basarili yenileme bilgisine dayanmalı; yenileme butonu loading, basari, kismi hata ve tam hata durumlarinda acik geri bildirim vermeli.
  - `Servisler aktif` gibi toplu saglik etiketi tanimli esiklerden turetilmeli. Yuksek P95, hata orani, Firebase kapali/init hatasi veya push teslimat sorunu varken kosulsuz yesil durum gosterilmemeli; normal, uyari, kritik ve bilinmiyor durumlari ayrilmali.
  - API P95 ve hata orani icin iyi/uyari/kritik esikleri urun operasyonuna gore belgelenmeli; renk tek basina anlam tasimamali.
  - Referanstaki mini trend/nokta gorselleri yalnizca gercek zaman serisi verisi varsa kullanilmali; dekoratif veri grafigi veya sahte trend uretilmemeli.
  - Push Firebase `ACIK/KAPALI`, aktif cihaz sayisi, proje kimligi, kimlik kaynagi, gonderim/hata ve gecersiz token sayilari eksiksiz korunmali.
  - En sik push hatasi bosken sakin bir `Hata yok` durumu; hata varken kod, adet ve uygun uyari seviyesiyle gosterilmeli. Uzun hata kodlari tasmamali ve gerekirse detay gorunumu acilabilmeli.
  - Sifir degeri, veri yok, yukleniyor, stale veri, yetki/endpoint hatasi ve kismi endpoint basarisizligi birbirinden ayirt edilmeli; basarisiz istek eski degeri fark edilmeden canliymis gibi birakmamali.
  - Kartlar ortak ikon, tipografi, spacing, radius, border ve durum rengi tokenlari kullanmali; anlamsiz `U/M/O/B` harf ikonlari yerini tutarli ve erisilebilir ikonlara birakmali.
  - 320 px civari dar ekran, tablet ve genis masaustunde kart sirasi ve bilgi onceligi korunmali; yatay tasma, kesilen metin veya okunamayacak kadar kucuk alt bilgi olmamali.
  - Klavye erisimi, focus-visible, ekran okuyucu etiketleri, yeterli kontrast ve en az 44x44 px etkilesim alanlari saglanmali.
  - Yeni tasarim masaustu ve mobil ekran goruntusu QA'i ile; metrik degerleri ise endpoint cevaplariyla karsilastirilarak manuel regresyon testinden gecmeli.
- Kanit:
  - Mevcut ekran: `docs/assets/manual-qa/qa-004-current-admin-dashboard.png`
  - Onaylanan tasarim yonu: `docs/assets/manual-qa/qa-004-approved-dashboard-direction.png`
  - Ilgili kod: `chatapp-backend/admin.html` (`#dashboard-cards`, `#dashboard-diag`, `loadStats`, `loadPushHealth`, `loadPushDiagnostics`, `loadPerformanceSummaryCard`)
- Oncelik: P2
- Durum: Acik
### QA-005 - Dashboard Kullanici Aktiviteleri ve Son Aktiviteler alani sadelestirilmeli

- Tarih: 2026-09-01
- Alan: Admin / UX / Analytics
- Ortam: Canli web admin paneli, Dashboard alt bolumu
- Jarvis hedefi: Trend ve dikkat isteyen olaylari ozetle; saatlik tablo ile ham olay akislarini bilincli detay eylemine tasi.
- Adimlar: Admin Dashboard'u ac; Kullanici Aktiviteleri kartindaki KPI'lari, grafigi ve saatlik tabloyu incele; ardindan Son Aktiviteler listesini tarayip belirli bir olayin ne oldugunu ve ne zaman gerceklestigini bulmaya calis.
- Beklenen: Dashboard bir analiz raporu gibi derine zorlamadan `ne oluyor, trend nasil, dikkat etmem gereken bir sey var mi?` sorularini saniyeler icinde cevaplamali. Grafik korunmali; ham zaman kirilimi ve teknik olay ayrintilari ancak kullanici istediginde acilmali.
- Gerceklesen: Kullanici Aktiviteleri alani ayni anda yedi KPI, grafik ve 24 satira kadar saatlik tablo gosteriyor. Tablo karti gereksiz yere uzatiyor ve ozet ile analiz detayini ayni seviyeye tasiyor. Son Aktiviteler alani 16 karta kadar kendi icinde dikey scroll kullaniyor; Turkce ve Ingilizce olay adlari, teknik metadata ve tekrar eden olaylar hizli taramayi zorlastiriyor.
- Tasarim brief'i: Yeni bir gorsel mockup zorunlu degildir. Ana ilke `ozet varsayilan, detay istege bagli` olmalidir. Mevcut ekran kanit olarak saklanmistir; uygulanacak tasarim sade, sakin, tek bakista okunur ve QA-004 ile ayni admin tasarim sistemine ait olmalidir.
- Kullanici Aktiviteleri bilgi mimarisi:
  - Son 24 saatin karar vermeye yarayan az sayida ana metrigi ustte ozetlenmeli; ikincil metrikler grafik secicisinde veya acilir detayda bulunmali.
  - Grafik ana gorsel olarak korunmali. Tekil Gelen, Match Deneme/Bulma, Kabul/Red ve Sohbet Baslangici serileri karisik bir yigin olmamali; kullanici hangi metriği gordugunu acikca anlayabilmeli ve gerekirse seri secimini degistirebilmeli.
  - Zaman araligi net yazilmali; noktaya gelindiginde tarih/saat ve deger tooltip ile okunabilmeli. Bos veri, tek nokta ve ani zirve durumlari yaniltici olcek uretmemeli.
  - Saatlik ham tablo varsayilan Dashboard akışından kaldirilmali. `Saatlik detayi gor` ile acilan kontrollu bolum, modal/drawer veya mevcut Analytics ekranina gecis kullanilabilir.
  - Detay tablo erisilebilir kalmali fakat Dashboard'u dikey olarak uzatmamalı; siralama, zaman araligi ve gerekirse CSV disari aktarma detay gorunumunde ele alinmali.
- Son Aktiviteler bilgi mimarisi:
  - Varsayilan listede en yeni ve anlamli sinirli sayida olay gosterilmeli; kalan kayitlara `Tum aktiviteleri gor` ile ulasilmali.
  - Her satir once `ne oldu`, sonra `kim`, `ne zaman` ve `platform` sorularini kisa bir hiyerarsiyle cevaplamali.
  - Olay adlari tek dilde ve tutarli olmali; `Sohbet Leave Action` gibi yarim cevrilmis dahili isimler kullaniciya gosterilmemeli.
  - Ham UUID, dahili event adi ve metadata varsayilan kartta yer kaplamamali; gerekli teknik bilgi satir genisletildiginde veya detay gorunumunde sunulmali.
  - Ayni kullanicinin kisa surede olusan tekrarli/ardisik olaylari gerekirse gruplanmali; gercekten dikkat isteyen olaylar normal aktiviteden gorsel olarak ayrilmali.
  - Zaman ilk bakista goreli (`5 dk once`) ve kolay okunur sunulabilir; kesin zaman tooltip veya detayda korunmali.
  - Dashboard icinde ikinci bir dikey scrollbar olmamali. Liste sayfayla birlikte akmali veya sinirli onizleme + `Tumunu gor` modeli kullanmali.
- Kabul kriterleri:
  - `/admin/analytics/timeseries` ve `/admin/analytics/recent` veri baglari korunmali; sadelestirme veri kaybi veya yanlis toplama uretmemeli.
  - Kabul orani hesabi, otomatik kabuller ve saatlik toplamlarda mevcut anlam korunmali; gosterilen her sayinin zaman penceresi acik olmali.
  - Varsayilan Dashboard alt bolumu grafik dahil tek masaustu ekraninda makul olcude taranabilmeli; ham saatlik tabloyu gormek icin bilincli bir detay eylemi gerekmeli.
  - Grafik secicileri ve detay eylemleri klavye ile kullanilabilmeli; focus-visible, ekran okuyucu etiketi, kontrast ve en az 44x44 px etkilesim alani saglanmali.
  - Recent event etiketleri merkezi bir TR/EN sozlukten gelmeli; bilinmeyen event icin teknik ama kontrollu bir fallback bulunmali.
  - Loading, bos liste, endpoint hatasi, kismi veri, uzun kullanici adi, eksik display name ve bozuk/eksik metadata durumlari tasarim icinde ele alinmali.
  - Mobilde bolumler tek kolona inmeli; grafik okunabilir kalmali, aktivite satirlari tasmamali ve ic ice scroll olusmamali.
  - Once/sonra masaustu ve mobil ekran goruntusu QA'i; grafik toplamlari, detay tablosu ve recent event sayilari icin endpoint karsilastirmali regresyon testi yapilmali.
- Kanit:
  - Mevcut ekran: `docs/assets/manual-qa/qa-005-current-dashboard-activity.png`
  - Tasarim yonu: Bu kayittaki `ozet varsayilan, detay istege bagli` sadelik brief'i
  - Ilgili kod: `chatapp-backend/admin.html` (`loadDashboardTab`, `renderDashboardMiniChart`, `.dashboard-kpi-grid`, `.table-scroll--trend`, `.dashboard-recent-list`)
- Oncelik: P2
- Durum: Acik
### QA-006 - Admin sol navigasyon daha sade ve gorev odakli olmali

- Tarih: 2026-09-01
- Alan: Admin / UX / Navigasyon
- Ortam: Canli web admin paneli, sol kenar navigasyonu
- Jarvis hedefi: Yonetici gorevini dusunerek hedefi bulsun; teknik modul adlari ve formalite ikonlari yerine gunluk is akisi gorunsun.
- Adimlar: Admin panelini ac; belirli bir kullaniciyi bulma, raporu inceleme, sistem durumunu kontrol etme ve yasal metinlere ulasma gibi temel gorevlerde sol menuden hedef sayfayi bulmaya calis; masaustu ve dar ekranda menu davranisini incele.
- Beklenen: Sol navigasyon panelin haritasi gibi calismali. Gunluk ve kritik gorevler ilk bakista bulunmali; seyrek kullanilan veya teknik sayfalar ana akisi kalabaliklastirmamali. Grup adlari, sayfa etiketleri ve ikonlar kendi basina anlamli olmali.
- Gerceklesen: On iki sayfa dort grupta ayni agirlikta listeleniyor. `D`, `#`, `!`, `@`, `?`, `*`, `%`, `~`, `+`, `-`, `=` ve `:` karakterleri gercek ikon gibi kullaniliyor fakat sayfanin amacini anlatmiyor. Fazla grup basligi, buyuk marka alani ve benzer agirlikteki satirlar menunun bir kismini formalite gibi hissettiriyor; gunluk aksiyonlarla ileri seviye/sistem ekranlari yeterince ayrismiyor.
- Tasarim brief'i: Yeni bir gorsel mockup zorunlu degildir. Ana ilke `az secenek gostermek degil, dogru secenegi dogru anda gostermek` olmalidir. Mevcut islevler once kullanim sikligi ve yonetici gorevleriyle haritalanmali; sayfalar kanitsiz bicimde silinmemeli.
- Onerilen bilgi mimarisi yonu:
  - `Genel Bakis`: Dashboard tek ve belirgin baslangic noktasi.
  - `Kullanicilar ve Moderasyon`: Profiller, Kullanici Raporlari, Uygulama Raporlari, Yasaklar/Golge ve Silme Talepleri gibi ayni gorev ailesindeki sayfalar.
  - `Operasyon`: Anlik Online, Bildirim Ayarlari ve gercek zamanli operasyon ihtiyaclari.
  - `Analiz ve Sistem`: Performans, Davranis Analitigi, Audit Log ve Yasal Metinler; gunluk ihtiyac degilse varsayilan olarak daha sakin, daraltilabilir bir grup.
  - Kesin gruplama uygulanmadan once sayfa kullanim sikligi ve gercek yonetici is akislariyla dogrulanmali; bu liste yon gosterir, zorunlu nihai etiket seti degildir.
- Kabul kriterleri:
  - Navigasyon en sik kullanilan 4-6 hedefi ilk bakista gostermeli; ikincil hedefler acilir grup veya `Daha Fazla/Sistem` alaniyla kolayca ulasilabilir kalmali.
  - `Dashboard` gibi dil karisikligi yaratan adlar panelin genel dil kararina gore `Genel Bakis` benzeri tutarli TR/EN etiketlere donusturulmeli; etiketler teknik tablo/route adlari olmamali.
  - Noktalama ve harf ikonlari kaldirilmali; tek bir SVG ikon ailesinden semantik, ayni olcu/stroke degerine sahip ikonlar kullanilmali. Ikon tek basina degil, gorunen metin ve ekran okuyucu etiketiyle desteklenmeli.
  - Aktif sayfa yalnızca mor arka planla degil; renk, ikon/metin vurgusu ve uygun `aria-current` ile anlasilmali. Hover, focus-visible, pressed ve disabled durumlari tanimli olmali.
  - Bekleyen Kullanici/Uygulama Raporlari ve Silme Talepleri gibi eylem gerektiren bolumlerde yalnizca gercek veriye dayanan, sakin sayisal rozetler kullanilabilmeli; her menuye dekoratif rozet eklenmemeli.
  - Grup basliklari azaltildiginda anlam kaybolmamali; acilir gruplar son durumunu ve icindeki aktif sayfayi dogru gostermeli, klavye ve ekran okuyucuyla acilip kapanabilmeli.
  - Sidebar'daki `Tum Verileri Yenile` ile topbar'daki `Yenile` ayni amaca hizmet ediyorsa yinelenen aksiyon kaldirilmali veya kapsam farklari etiketle netlestirilmeli.
  - Sayfa degisiminde aktif sekme korunmali; refresh/geri-ileri davranisi ve mumkunse dogrudan sayfa baglantisi tahmin edilebilir olmali.
  - Genis masaustunda sidebar olculu ve dengeli kalmali; 320 px civari dar ekranda erisilebilir drawer'a donusmeli. Drawer odak yonetimi, Escape ile kapatma, disariya tiklama ve arka plan scroll kilidi icermeli.
  - Marka alani menuden daha baskin olmamali; logo, `talkx` ve `Yonetim Paneli` yazisi daha kompakt hiyerarsiyle sunulmali.
  - Uzun etiketler, buyuk yazi/zoom, cok sayida rozet ve tum menu gruplarinin acik oldugu durumlarda tasma veya ulasilamayan hedef olusmamali.
  - Tum mevcut sekmeler yeniden tasarimdan sonra erisilebilir ve islevsel kalmali; her hedef icin tiklama, klavye, aktif durum, refresh ve mobil regresyon testi yapilmali.
- Kanit:
  - Mevcut ekran: `docs/assets/manual-qa/qa-006-current-admin-sidebar.png`
  - Tasarim yonu: Bu kayittaki gorev odakli ve kademeli navigasyon brief'i
  - Ilgili kod: `chatapp-backend/admin.html` (`.sidebar`, `.sidebar-brand`, `.nav-group`, `.nav-group-title`, `.sidebar .tab`, `.nav-icon`, `switchTab`)
- Oncelik: P2
- Durum: Acik
### QA-007 - Admin Profiller tablosu daha okunabilir ve sakin olmali

- Tarih: 2026-09-01
- Alan: Admin / UX / Profiller / Guvenlik
- Ortam: Canli web admin paneli, Profiller sekmesi
- Jarvis hedefi: Kullanici kimligi, durum ve son aktiviteyi hizla okut; ikincil/hassas alanlari ve riskli islemleri baglamsal detaya tasi.
- Adimlar: Profiller sekmesini ac; bir kullanicinin adini, gorunen adini, konumunu, son gorulmesini ve kayit zamanini satir boyunca takip et; ardindan arama, siralama, tekil yasaklama, coklu secim ve pagination akisini dene.
- Beklenen: Yonetici bir satira baktiginda kullaniciyi, durumunu ve gerekli ana bilgiyi hizla okuyabilmeli. Tablo satir/kolon iliskisini kaybettirmemeli; ikincil ve hassas veriler ana gorunumu bogmadan erisilebilir olmali. Normal inceleme ile tehlikeli moderasyon aksiyonlari gorsel olarak ayrilmalidir.
- Gerceklesen: Sekiz veri/aksiyon kolonu genis alana yayiliyor fakat kolon sinirlari zayif; satir boyunca gozu takip etmek zorlasiyor. `table-layout: fixed` ve genel `word-break` uzun kullanici adi ile IP/kaynak degerlerini ortadan boluyor. Sehir ve ulke, son gorulme ve kayit zamani ayri kolonlarda benzer agirlikta duruyor. Her satirdaki mavi `Detay` ve kirmizi `Yasakla` butonlari ile secim yokken gorunen dort toplu moderasyon aksiyonu ekrani surekli alarm halinde gosteriyor.
- Tasarim brief'i: Ana ilke `tabloyu daha cok cizgiyle doldurmak degil, satir ve kolon takibini zahmetsiz yapmak` olmalidir. Ince ayiricilar, dengeli bosluk, anlamli gruplama ve ilerlemeli detay birlikte kullanilmali; spreadsheet benzeri agir tam grid zorunlu degildir.
- Onerilen bilgi hiyerarsisi:
  - `Kullanici`: username, gorunen isim ve platform bilgisi tek, guclu bir kimlik hucresinde toparlanabilir; uzun degerler ortadan kirilmak yerine kontrollu kisaltma + tooltip/detay kullanmali.
  - `Konum`: sehir ve ulke tek hiyerarsik hucrede sunulabilir; geo kaynagi ve tam etiket detay gorunumunde kalabilir.
  - `Aktivite`: Son Gorulme ana deger, Kayit Tarihi ikincil deger olarak ayni hucrede veya secilebilir kolon yapisinda ele alinabilir.
  - `IP/Kaynak`: hassas ve teknik bilgi olarak varsayilan gorunumde maskeli/kisaltilmis sunulmali; tam deger yalnizca gerekli yetki ve bilincli bir gosterme/detay eylemiyle gorulmeli.
  - `Islemler`: Detay ana satir eylemi olabilir; Yasakla/Golge/Unban gibi riskli islemler uc nokta menusu veya detay ekraninda, acik ad ve onayla sunulmali.
- Kabul kriterleri:
  - Header ile veri kolonlari hem acik hem koyu satirlarda net izlenebilmeli; satir hover/focus, kontrollu zebra tonu ve kritik kolonlar arasinda ince ayirici kullanilmali.
  - Tam dikey grid uygulanirsa gorsel gurultu olusturmamali; padding, satir yuksekligi, font olculeri ve kontrast ortak admin tablo tokenlarina baglanmali.
  - Kullanici adi, gorunen isim, sehir/ulke, IP/kaynak ve tarih alanlari rastgele kelime ortasindan bolunmemeli. Truncation durumunda tam deger klavye ve dokunmayla da erisilebilir olmali; yalnizca mouse hover'a bagli kalmamali.
  - Siralanabilir kolonlarda `-` veya `v` karakteri yerine standart sort ikonu kullanilmali; aktif siralama, yon ve `aria-sort` acik olmali. Sunucu tarafli pagination/siralama sonucu korunmali.
  - Arama alani temizleme aksiyonu, sonuc sayisi ve aktif filtrelerle birlikte calismali. Platform, ulke, durum/ban, online/son gorulme gibi gercek yonetim ihtiyaclari icin filtreler degerlendirilmeli; her filtre varsayilan ekrani doldurmamali.
  - Toplu islem cubugu hic secim yokken tehlikeli butonlarla baskin olmamali; secim yapildiginda baglamsal olarak acilmali. Secili sayisi, tum sayfayi mi mevcut sayfayi mi kapsadigi ve pagination sonrasi secim davranisi acik olmalı.
  - Toplu 24s Ban, Kalici Ban, Golge Ban ve Unban eylemleri birbirinden ayirt edilmeli; hedef sayisi, etki, gerekce ve geri donus durumu onay adiminda gosterilmeli. Yanlis tiklama riski renk disinda metin ve yerlesimle de azaltilmali.
  - Tekil `Yasakla` butonu her satirda alarm rengiyle baskin olmamali; acildiginda mevcut yasak durumu, sure/tur, gerekce ve audit sonucu dogrulanmali.
  - Tam IP gibi hassas verilerin liste gorunumunde gorunmesi icin rol/yetki, maskeleme ve audit ihtiyaci belirlenmeli; kopyalama eylemi varsa bilerek tetiklenmeli. IP'nin geo kaynagi ile ayni metinde birlesmesi engellenmeli.
  - Pagination hem ust/alt baglamda kolay bulunmali; toplam kayit, gosterilen aralik, sayfa boyutu, onceki/sonraki ve loading durumu acik olmali. Yenileme sonrasinda makul arama/filtre/siralama durumu korunmali.
  - Loading skeleton, bos sonuc, endpoint hatasi, eksik geo, bilinmeyen platform, gecersiz tarih ve cok uzun deger durumlari icin belirgin fallback bulunmali.
  - Genis masaustunda kolonlar boslugu dengeli kullanmali; dar masaustunda kontrollu yatay scroll + sabit kimlik/aksiyon veya oncelikli kolon modeli kullanilmali. Mobilde sikistirilmis sekiz kolon yerine ozet satir/kart ve acilir detay degerlendirilmelidir.
  - Klavye ile satir/checkbox/aksiyon menusu kullanimi, focus-visible, toplu secim, ekran okuyucu baslik iliskileri ve en az 44x44 px etkilesim alanlari saglanmali.
  - Once/sonra masaustu ve mobil ekran goruntusu QA'i; arama, sort, pagination, detay, tekil ban ve tum toplu islemler icin fonksiyonel regresyon testi yapilmali.
- Kanit:
  - Mevcut ekran: `docs/assets/manual-qa/qa-007-current-admin-profiles.png`
  - Tasarim yonu: Bu kayittaki okunabilir, kademeli ve guvenli veri tablosu brief'i
  - Ilgili kod: `chatapp-backend/admin.html` (`table`, `th/td`, `.table-scroll`, `.bulk-toolbar`, `.profiles-pagination`, `renderProfileSortHeader`, `renderBulkToolbar`, `loadList`, `openProfileDetails`)
- Oncelik: P2
- Durum: Acik
### QA-008 - Admin Profil Detayi yuzeyi ve veri anlamlari bastan ele alinmali

- Tarih: 2026-09-01
- Alan: Admin / UX / Profiller / Moderasyon / Guvenlik
- Ortam: Canli web admin paneli, Profiller > Detay
- Jarvis hedefi: Kullanici kim, mevcut durumu/risk nedir, hangi kanit var ve hangi kontrollu aksiyon alinabilir sorularini bolumlu bir ozetle cevapla.
- Adimlar: Profiller listesinden bir kullanicinin `Detay` aksiyonunu ac; hesap, konum/yasal kabul, session, push cihazi, arkadas ve engel bilgilerini okumaya; ardindan gerekli yonetim aksiyonunu bulmaya calis.
- Beklenen: Profil detayi yoneticinin kullaniciyi tanimasini, risk/durumunu anlamasini ve bilincli aksiyon almasini saglayan temiz bir inceleme yuzeyi olmali. Bilgiler anlamli bolumlerde, dogru etiket ve kaynakla sunulmali; teknik ve hassas alanlar ana ozeti bogmamalidir.
- Gerceklesen: Genis modal icinde hesap, yasal/konum ve cihaz alanlari esit agirlikli kutulara yigiliyor; etiket ile deger arasinda gorsel ayrim olmadigi icin `Kullanicifloge93`, `Durumactive` gibi birlesik okunuyor. Session ve push cihazlari ham pipe (`|`) listeleri, arkadas/engel alanlari duz bullet listeleri olarak sunuluyor. Moderasyon ozeti, raporlar, mevcut ban/golge durumu ve audit baglami gorunmuyor; modal uzadikca taramak ve kapatmak zorlasiyor.
- Dogrulanan veri/etiket sorunlari:
  - `Son Sessionlar` listesindeki `Bitis`, backend'deki `sessions.expires_at` alanidir; gercek cikis, iptal veya son kullanim zamani degildir. `Sona erme/son kullanma tarihi` olarak dogru etiketlenmeli; aktif/expired/revoked bilgisi isteniyorsa veri sozlesmesi tamamlanmalidir.
  - Arkadas endpoint'i `friendships.created_at` yerine arkadas kullanicinin `users.created_at` degerini donduruyor; mevcut tarih friendship'in kurulma tarihi gibi sunulmamali.
  - `Kayit Onayi Zamani` aslinda secilen `legal_acceptances.accepted_at` kaydidir; hesap kaydi veya genel bir onay zamani gibi belirsiz etiketlenmemeli. Hangi metin/surumun kabul edildigi gerekiyorsa endpoint bunu acikca tasimalidir.
  - `Engellenen Kullanici` listesi yalnizca bu kullanicinin engelledigi kisileri donduruyor; yon `Bu kullanicinin engelledikleri` olarak acik yazilmali. Bu kullaniciyi engelleyenler gerekiyorsa ayri veri olarak sunulmalidir.
  - `/admin/user-reports/:userId` alinan/gonderilen rapor verisini sagliyor fakat mevcut Profil Detayi bu veriyi kullanmiyor.
- Onerilen bilgi mimarisi:
  - `Profil Ozeti`: username, gorunen ad, durum/ban/golge rozetleri, kullanici ID, kayit zamani, son gorulme ve son platform. Kimlik bilgisi modal boyunca sabit ve kolay kopyalanabilir olmali.
  - `Moderasyon`: alinan/gonderilen rapor sayilari ve son kayitlar, mevcut/gecmis ban-golge durumu, ilgili audit olaylari ve kontrollu moderasyon aksiyonlari.
  - `Oturumlar ve Cihazlar`: session ile push cihazlarini ayri alt alanlarda; cihaz kimligi, platform, olusturma, son aktivite, sona erme ve aktiflik anlamlari dogru etiketlerle.
  - `Yasal Kabul ve Konum`: kabul tarihi/surumu, kayit konumu ve geo kaynagi; IP varsayilan olarak maskeli.
  - `Iliskiler`: arkadaslar, bu kullanicinin engelledikleri ve gerekiyorsa bu kullaniciyi engelleyenler; sayi ozeti + aranabilir/sayfalanabilir detay.
  - Yuzey tek uzun ham modal yerine buyuk responsive drawer, tam sayfa detay veya sticky header'li sekmeli modal olarak tasarlanabilir; nihai desen mevcut admin tasarim sistemiyle birlikte secilmelidir.
- Kabul kriterleri:
  - Baslikta profil kimligi, gorunen ad ve durum net ayrilmali; raw `active` gibi backend degerleri yerellestirilmis, semantik rozetlere donusturulmeli.
  - Etiket ve degerler ayri tipografi/spacing ile sunulmali. Bos, bilinmeyen ve yuklenemeyen veri ayni `-` ile gecistirilmemeli; uygun fallback veya bolumsel hata mesaji bulunmali.
  - Bilgi bolumleri tabs/accordion/drawer gibi kademeli yapida olmali; ilk ekranda yalnizca karar verdiren ozet gorunmeli, teknik ayrintilar istege bagli acilmalidir.
  - `expires_at`, `created_at`, `last_seen_at`, `updated_at` ve gercek revocation/logout kavramlari birbirine karistirilmamali. Tum tarihler saat dilimi, kesin zaman ve gerekiyorsa goreli zamanla tutarli sunulmali.
  - Friendship endpoint'i gercek iliski `created_at/updated_at/status` alanlarini dondurmeli; iki tarafin yonu ve kullanici bilgisi karismamali. Uzun listeler pagination veya kontrollu yukleme kullanmali.
  - Session satirinda aktiflik yalnizca gelecekteki expiry'ye bakilarak kesin varsayilmamali; token iptali/son kullanim bilgisi yoksa UI bunu `bilinmiyor` olarak ifade etmeli veya backend sozlesmesi genisletilmelidir.
  - Push cihazi aktifligi, platformu ve son gorulmesi semantik rozetlerle sunulmali; session ile push token cihazi ayni sey gibi gosterilmemeli.
  - Tam IP ve device ID varsayilan gorunumde maskeli/kisaltilmis olmali. Goster/kopyala eylemleri yetki, gerekce ve audit ihtiyacina gore tasarlanmali; hassas degerler ekran goruntusunde gereksiz yere acik kalmamalidir.
  - Moderasyon bolumu mevcut rapor, ban/golge ve audit verilerini dogru sayilarla ozetlemeli. Eksik endpoint gerekiyorsa acik API sozlesmesi eklenmeli; farkli kaynaklardan gelen sayilar sessizce birlestirilmemeli.
  - Manuel Arkadas Ekle, Arkadas Sil ve Engeli Kaldir islemleri normal bilgi okuma akışından gorsel olarak ayrilmali. Hedef, etki, yon, gerekce ve audit kaydi onay adiminda acik olmali.
  - Ban/golge/unban gibi aksiyonlar profil baglaminda sunulacaksa mevcut durum ve beklenen sonuc gorunmeli; tehlikeli eylemler renk disinda metin, ikon, konum ve yeniden dogrulamayla korunmali.
  - Uc endpoint'ten biri (`profile-details`, `user-blocks`, `user-friends`) hata verdiginde tum modal kapanmamalı; basarili bolumler kalmali ve yalnizca sorunlu bolum tekrar denenebilmelidir. Rapor/moderasyon kaynaklari icin de bolumsel loading/error uygulanmali.
  - Modal/drawer acildiginda odak iceri alinmali; Escape, gorunen kapat butonu ve kontrollu dis tiklama davranisi bulunmali. Kapatma sonrasi odak `Detay` butonuna donmeli; arka plan scroll'u kilitlenmelidir.
  - 320 px civari mobil ekran, zoom/buyuk yazi, uzun username/device ID, cok sayida session/arkadas ve bos kayit durumlari tasmadan calismali.
  - Profil Detayi icin masaustu/mobil ekran goruntusu QA'i; veri alanlari icin endpoint karsilastirmasi; arkadas ekle/sil, engel kaldir ve moderasyon aksiyonlari icin audit dahil fonksiyonel regresyon testi yapilmali.
- Kanit:
  - Mevcut ekran: `docs/assets/manual-qa/qa-008-current-admin-profile-detail.png`
  - Tasarim yonu: Bu kayittaki kademeli profil, moderasyon ve guvenlik bilgi mimarisi brief'i
  - Ilgili kod: `chatapp-backend/admin.html` (`openProfileDetails`, `.modal`, `.modal-box`, `.grid`, `.item`, `.list-compact`); `chatapp-backend/admin.js` (`/profile-details/:userId`, `/user-blocks/:userId`, `/user-friends/:userId`, `/user-reports/:userId`)
- Oncelik: P1
- Durum: Acik
### QA-009 - Uygulama Raporlari Jarvis bilgi modeline gore sadelestirilmeli

- Tarih: 2026-09-02
- Alan: Admin / UX / Uygulama Raporlari / Operasyon / Guvenlik
- Ortam: Canli web admin paneli, Uygulama Raporlari listesi ve Rapor Detayi
- Jarvis hedefi: Sorun, etki, tekrar, operasyon durumu, kanit ve uygulanabilir aksiyonu one al; e-posta teslimi ile rapor cozumunu ayir.
- Adimlar: Uygulama Raporlari sekmesini ac; hangi sorunlarin tekrar ettigini, kac kullaniciyi etkiledigini ve hangisinin aksiyon gerektirdigini anlamaya calis; bir raporu acip kullanici anlatimi, ortam, hata ve teslim bilgilerini incele.
- Beklenen: Panel ham alanlari esit agirlikte gostermek yerine yoneticiye once temiz bir durum ozeti vermeli: ne oldu, etkisi nedir, tekrar ediyor mu, hangi ortamda goruluyor ve siradaki mantikli aksiyon nedir. Ham kanit silinmeden ikincil detay katmaninda kalmalidir.
- Gerceklesen: Liste tarih, konu, kullanici, e-posta, `Durum`, medya ve Detay/Sil kolonlarini ham kayit bazinda gosteriyor; en fazla 100 kayit cekiliyor, pagination veya problem bazli gruplama yok. Detay modalinda 16 teknik alan esit kutulara yigiliyor; etiket ve degerler birlesiyor. Kullanici aciklamasi, hata kodu, IP, uzun user-agent, Brevo mesaji ve teslim hatasi ayni bilgi seviyesinde duruyor; yonetici sorunu anlamak icin veriyi kendi zihninde ayiklamak zorunda kaliyor.
- Dogrulanan anlam ve is akis sorunlari:
  - Listedeki `Durum`, raporun inceleme/cozum durumu degil `brevo_status` e-posta teslim durumudur. Bu iki kavram ayri ad ve rozetlerle sunulmalidir.
  - Raporlarda `yeni`, `inceleniyor`, `cozuldu`, `tekrar/duplicate`, `yok sayildi` gibi operasyonel yasam dongusu alani bulunmuyor; sahip/not/cozum baglami da yoktur.
  - Liste sorgusu siralama/pagination olmadan son 100 kaydi getiriyor. Daha eski sorunlar sessizce gorunmez olabilir.
  - Ayni hata kodu, konu, uygulama surumu veya platformla gelen raporlar ayri satirlar olarak kaliyor; tekrar ve etki ozeti uretilmiyor.
  - Detayda tam IP, user-agent, Brevo message ID ve servis hatasi varsayilan olarak acik; kullanici anlatimiyla ayni agirlikta.
  - `Sil` kalici DELETE islemi; arsiv/cozuldu/retention ayrimi ve gorunen audit baglami olmadan ana liste aksiyonu olarak duruyor.
- Jarvis cikti modeli:
  - `Sorun`: Kullanici anlatimi ve hata sinyallerinden uretilen kisa, olgusal baslik. Ornek: `Anonim eslesmede online kullanici bulunamiyor`.
  - `Etki`: Tekil kullanici/rapor adedi, ilk ve son gorulme, platform, uygulama surumu ve ortak cihaz/ag baglami.
  - `Durum`: Yeni, inceleniyor, cozuldu, duplicate veya bilgi yetersiz gibi gercek operasyon durumu; Brevo tesliminden tamamen ayri.
  - `Kanit`: Kullanici aciklamasi, medya, hata kodu, zamanlar ve gerektiginde acilan maskeli teknik metadata.
  - `Aksiyon`: Incele, benzer raporlari gor, kullanici profiline git, durum/not guncelle, teknik kaniti ac, arsivle; yalnizca gercekten uygulanabilir eylemler.
  - Otomatik ozet/siniflandirma kullanilirsa kaynagi ve guven seviyesi gosterilmeli; sistem emin degilse sonuc uydurmak yerine `Siniflandirilamadi` demelidir.
- Liste bilgi mimarisi:
  - Varsayilan gorunum ham rapor yerine problem/olay grubu bazinda olabilir: temiz sorun basligi, durum/oncelik, rapor ve etkilenen kullanici sayisi, ilk/son gorulme, ana platform/surum ve son aksiyon.
  - Ham tekil raporlara grup detayindan ulasilmali; gruplama anahtari deterministik alanlara (normalize konu, `last_error_code`, platform, app version ve kontrollu zaman penceresi) dayanmali ve yanlis birlestirme geri alinabilmelidir.
  - Gruplama icin yeterli kanit yoksa rapor tekil kalmali; benzer gorunen farkli sorunlar zorla birlestirilmemeli.
  - Filtreler operasyonel olmali: durum, oncelik, tarih araligi, konu/kategori, hata kodu, platform, app version, medya var/yok, Brevo teslimi ve kullanici. Aktif filtreler gorunur ve tek tikla temizlenebilir olmali.
  - Gercek server-side pagination, toplam kayit/grup sayisi, sayfa boyutu ve siralama eklenmeli; 100 kayitlik sessiz limit kaldirilmali.
- Detay bilgi mimarisi:
  - Ust ozet: sorun basligi, durum/oncelik, tekrar/etki, ilk-son gorulme ve sahip/son aksiyon.
  - Kullanici bildirimi: aciklama ana kanit olarak rahat okunur bicimde; raporlayan kullanici ve iletisim tercihiyle birlikte.
  - Ortam ozeti: platform, app version, cihaz modeli, ag tipi ve son hata kodu; ortak/aykiri degerler grup detayinda ayrilmali.
  - Medya: kanit galerisi, dosya turu/boyutu, guvenli onizleme ve hata fallback'i.
  - Teknik kanit: report ID, client/server zamanlari, maskeli IP, kisaltilmis user-agent, Brevo message ID/error ve ham metadata varsayilan olarak kapali bir bolumde.
  - Islem gecmisi: durum degisiklikleri, notlar, birlestirme/ayirma, arsiv/silme ve kim/ne zaman audit kaydi.
- Kabul kriterleri:
  - Report workflow durumu icin backend veri sozlesmesi olusturulmali; `brevo_status` yalnizca `E-posta teslimi` olarak etiketlenmeli. Pending/sent/failed ile new/investigating/resolved birbirine karistirilmamali.
  - Ozet ve gruplama sonucu gercek kayitlara geri izlenebilir olmali. Her sayi ve iddia dayandigi raporlar, zaman penceresi ve filtreyle dogrulanabilmeli.
  - Ilk surum deterministik kurallarla uygulanabilir; yapay zeka zorunlu degildir. AI ozet eklenirse hassas veri gonderimi, maliyet, prompt injection, yanlis ozet ve insan onayi ayri guvenlik tasarimina tabi olmalidir.
  - Oncelik otomatik verilecekse acik kurallar kullanilmali: rapor/adet artisi, etkilenen tekil kullanici, kritik hata kodu, yeni release korelasyonu veya medya/kanit. Yalniz renk ve hisle kritik karari uretilmemeli.
  - Liste ve detay ayni terimleri kullanmali; konu kodlari (`bug`, `billing`, `other` vb.) yonetici dostu yerellestirilmis etiketlere donusmeli ve ham kod kanit katmaninda kalmali.
  - Kullanici profiline guvenli baglanti bulunmali; silinmis/anonim kullanici ve bos e-posta durumlari uygun fallback ile ele alinmali.
  - Tam IP ve user-agent maskeli/kisaltilmis olmali; goster/kopyala eylemi yetki ve audit politikasina baglanmali. Brevo hata metni ve kullanici aciklamasi XSS'e karsi escape edilmeye devam etmelidir.
  - Kalici silme ana aksiyon olmamali. Once durum/cozum/arsiv modeli, retention kurali ve audit belirlenmeli; gercek silme gerekiyorsa medya dahil kapsam, geri donulemezlik ve yetki yeniden dogrulanmalidir.
  - Medya onizleme image/video hata, buyuk dosya, desteklenmeyen MIME ve yetkisiz erisim durumlarini guvenli ele almali; dosya adi ve turu kanitla eslesmeli.
  - Client timestamp ile server created_at farki acik etiketlenmeli; saat dilimi ve gecersiz/gelecek zaman degerleri yaniltici siralama uretmemeli.
  - Liste/detay loading, bos, kismi hata, stale veri ve tekrar dene durumlarini bolumsel gostermeli; tek teknik alan eksik diye kullanici bildirimi kaybolmamali.
  - Modal/drawer odak yonetimi, Escape, kapatma sonrasi odak iadesi, arka plan scroll kilidi, mobil/zoom ve uzun metin davranisi QA-008 ile ayni standarda uymali.
  - Masaustu/mobil once-sonra ekran goruntusu QA'i; gruplama sayilari ve filtre/pagination icin DB/API karsilastirmasi; durum/not/arsiv/silme ve medya yetkileri icin audit dahil fonksiyonel regresyon testi yapilmali.
- Kanit:
  - Mevcut ekran: `docs/assets/manual-qa/qa-009-current-admin-app-report-detail.png`
  - Tasarim yonu: `Admin bilgi sunum ilkesi - Jarvis modeli` ve bu kayittaki problem/etki/kanit/aksiyon hiyerarsisi
  - Ilgili kod: `chatapp-backend/admin.html` (`loadContent` app_reports tablosu, `openSupportDetails`, `deleteSupportReport`, `.modal`, `.grid`, `.item`, `.desc`, `.media`); `chatapp-backend/admin.js` (`type=app_reports`, `/support-report/:id`, `/support-report-media/:mediaId/content`, `DELETE /support-report/:id`); `chatapp-backend/routes/support.js`
- Oncelik: P1
- Durum: Acik
### QA-010 - Global bildirimler kullanici diline gore yerellestirilmeli

- Tarih: 2026-09-02
- Alan: Admin / Backend / Push / WebSocket / Veritabani / Global urun
- Ortam: Canli web admin paneli, Bildirim Ayarlari; anlik ve planli admin notice akislari
- Jarvis hedefi: Yonetici hangi mesajın hangi dil grubuna, kac kisiye ve hangi fallback ile gidecegini gondermeden once net gorsun; kullanici yalnizca kendi dilindeki temiz bildirimi alsin; teknik dagitim sonucu dil bazli kanitta kalsin.
- Adimlar: Bildirim Ayarlari sekmesinde Turkce bir baslik ve metin girip `Hemen Gonder` veya planli `Simdi Calistir` kullan; dili English olan bir hesap/cihazda gelen WS ve push bildirimini kontrol et.
- Beklenen: Turkce locale kullanan hesap/cihaz Turkce varyanti, English locale kullanan hesap/cihaz English varyanti almalidir. Locale bilinmiyor veya gecersizse belgelenmis guvenli fallback English olmalidir. Yonetici global gonderimden once iki varyanti, hedef dagilimini ve fallback sayisini gormelidir.
- Gerceklesen: Anlik form yalnizca tek `title/body` alani topluyor ve `/admin/notify` istegini `target: all` ile gonderiyor. Planli bildirim semasi tek `title/body` sakliyor; scheduler ve `run-now` ayni metni tum kullanicilara gonderiyor. `sendSystemNotice` tum WebSocket istemcilerine tek metni broadcast ediyor ve aktif push tokenlarini locale join/segmentasyonu olmadan tek payload ile Firebase'e iletiyor. Sonuc olarak Turkce girilen bildirim English kullanicilara da Turkce gidiyor.
- Dogrulanan mevcut veri:
  - `profiles.locale` alani vardir ve yalnizca `tr`/`en` degerlerini kabul eder; kayit, giris ve profil guncelleme akislari locale'i yazabilir.
  - Aktif WebSocket istemcileri `client.lang` tasir ve bu deger baglanti sirasinda istemci dilinden normalize edilir.
  - `push_devices` token/device bilgisi tasir fakat locale tasimaz; push segmentasyonu icin `user_id -> profiles.locale` join'i veya esdeger guncel dil snapshot'i gerekir.
  - `notification_schedules` yalnizca tek `title` ve `body` kolonuna sahiptir; mevcut planlarin hangi dilde oldugu semantik olarak kayitli degildir.
- Icerik ve fallback sozlesmesi:
  - Desteklenen her locale icin ayri baslik ve metin saklanmali: en az `tr.title`, `tr.body`, `en.title`, `en.body`. Sema ileride yeni dilleri eklemeye uygun locale haritasi veya bagli ceviri tablosu olabilir.
  - Global `all` hedefinde TR ve EN varyantlari zorunlu olmali; eksik veya yalniz bosluk iceren varyantla gonderim engellenmelidir.
  - Bilinmeyen, null veya desteklenmeyen locale icin varsayilan fallback `en` olmalidir; sessizce Turkceye dusulmemelidir.
  - Yalniz belirli bir dil grubuna kampanya gerekiyorsa yonetici bunu acik `Hedef dil: TR/EN` secimiyle yapmali; tek dilli icerik yanlislikla global hedefe genislememelidir.
  - Dil ile timezone farkli kavramlardir. Bir planin `Europe/Istanbul` saatinde calismasi alicinin Turkce oldugu anlamina gelmez; locale secimi zamanlama alanindan turetilmemelidir.
- Admin bilgi mimarisi:
  - Anlik Bildirim ve Yeni Plan formlarinda TR/EN sekmeleri veya yan yana iki acik varyant bulunmali; hangi dilin eksik oldugu belirgin olmalidir.
  - Her varyant icin baslik/metin karakter sayaci, zorunluluk, kirpilma riski ve mobil notification onizlemesi bulunmali.
  - Global gonderim oncesi Jarvis ozeti gosterilmeli: `TR: X cihaz/kullanici`, `EN: Y`, `Fallback EN: Z`, `WS online: N`, `Push aktif cihaz: M`; sayilarin kaynagi ve guncellenme zamani yazilmalidir.
  - `Test gonder` akisi global gonderimden ayrilmali; secili TR/EN test hesabina veya kontrollu test cihazina varyantlar dogrulanmadan `Hemen Gonder` etkinlesmemelidir.
  - Onay ekraninda hedef (`all/online/mobile`), diller, alici tahmini, fallback, sure, push+WS kanallari ve geri alinamazlik acikca gosterilmelidir.
  - Planli Bildirimler listesi her planin mevcut dillerini, hedef kitlesini, fallback'ini, timezone'unu, sonraki/son gonderimini ve dil bazli son teslim sonucunu ozetlemelidir; uzun metinler tabloyu bogmamalidir.
- Backend dagitim tasarimi:
  - `sendSystemNotice` tek `title/body` yerine dogrulanmis `contentByLocale` ve acik fallback locale kabul etmelidir; eski tek metinli cagri global hedefte sessizce desteklenmemelidir.
  - WS tesliminde her aktif client icin normalize `client.lang` secilmeli ve ayni `deliveryId/campaignId` altinda dogru varyant gonderilmelidir.
  - Push sorgusu aktif tokenlari `user_id`, cihaz ve `profiles.locale` ile getirmeli; tokenlar locale gruplarina ayrilarak Firebase'e dil basina ayri payload ile gonderilmelidir.
  - Ayni kullanicinin birden fazla cihazinda guncel hesap locale'i kullanilacaksa bu karar belgelenmeli; cihaz bazli dil desteklenecekse push device locale snapshot'inin guncellenme kurali tanimlanmalidir.
  - WS ve push ayni kullanici/cihaza birlikte ulasabilir; mevcut urun davranisi korunurken duplicate gosterim/collapse/idempotency kurali locale segmentasyonu sonrasi da calismalidir.
  - Fallback kullanilan, locale'i bilinmeyen ve teslimden atlanan token/client sayilari ayri metrik olmalidir; basarili toplam icinde gizlenmemelidir.
- Plan ve migration guvenligi:
  - Create, update, list, toggle, scheduler tick ve `run-now` endpointleri ayni cok dilli sozlesmeyi kullanmalidir; bir yolun eski tek metni tekrar globale gondermesine izin verilmemelidir.
  - Mevcut tek dilli planlar otomatik olarak TR veya EN varsayilmamali. `Ceviri gerekli` durumuna alinmali ve iki varyant tamamlanana kadar global scheduler tarafindan calistirilmamalidir.
  - Migration geri alinabilir olmali; eski title/body gecici kanit olarak korunacaksa yeni semanin tek kaynak haline gelme tarihi ve temizleme adimi belgelenmelidir.
  - Scheduler coklu instance duplicate korumasi ve locale segmentasyonu birlikte test edilmelidir; TR ve EN payloadlari ayni planin iki ayri gunluk calismasi gibi sayilmamalidir.
- Teslimat ozeti ve audit:
  - Sonuc yalniz `WS toplam` ve `Push sent/token` gostermemeli; TR, EN ve fallback icin hedeflenen, gonderilen, basarisiz, gecersiz token ve hata kodlari ayri ozetlenmelidir.
  - Audit kaydi kampanya/plan kimligi, hedef, mevcut diller, fallback, alici sayilari, admin, zaman ve sonuc ozetini tasimali; hassas push tokenlari veya gereksiz tam icerik audit'e yazilmamalidir.
  - Admin ekrani once temiz sonucu gostermeli (`TR 120/123, EN 87/90, fallback 4, 2 gecersiz token`); ayrintili Firebase/WS hata kaniti acilir bolumde kalmalidir.
- Kabul kriterleri:
  - TR profilli/istemcili kullanici her kanalda TR; EN profilli/istemcili kullanici her kanalda EN varyanti alir.
  - Null/gecersiz locale kullanicisi English fallback alir ve fallback metriğine dahil edilir.
  - Global gonderim her iki varyant tamamlanmadan ve onay ozeti gorulmeden yapilamaz; test gonderimi global alicilara sizmaz.
  - Anlik, planli scheduler ve `run-now` ayni locale secim/fallback fonksiyonunu kullanir; davranis farki olusmaz.
  - Kullanici dilini degistirdikten sonra WS ve sonraki push gonderiminde yeni dilin ne zaman etkili olacagi tanimli ve test edilmis olur.
  - Bildirim title/body sinirlari admin, backend, WS ve Firebase payloadinda ayni sekilde dogrulanir; Unicode/emoji ve uzun TR/EN metinleri bozulmaz.
  - Android foreground/background/kapali uygulama ve web online durumunda dil dogrulanir; notification tap/deep-link davranisi korunur.
  - DB/API/WS/push log sayilari dil bazinda karsilastirilir; ayni delivery/campaign icin duplicate veya eksik segment olmadigi kanitlanir.
  - English fallback metni urun dili ve anlam acisindan manuel incelenir; otomatik makine cevirisi insan onayi olmadan global gonderime donusmez.
  - Masaustu/mobil admin QA'inda varyant formu, onizleme, alici ozeti, loading, kismi hata, stale sayim, yetkisiz durum ve klavye/ekran okuyucu akisi dogrulanir.
- Kanit:
  - Mevcut ekran: `docs/assets/manual-qa/qa-010-current-admin-notification-settings.png`
  - Ilgili kod: `chatapp-backend/admin.html` (`sendNotice`, `collectNotificationSchedulePayload`, `renderNotificationSettingsTab`); `chatapp-backend/admin.js` (`POST /notify`, notification schedule CRUD/run-now); `chatapp-backend/index.js` (`sendSystemNotice`, `runNotificationSchedulesTick`, `activeClients`); `chatapp-backend/db.js` (`profiles.locale`, `notification_schedules`)
- Oncelik: P1
- Durum: Acik
### QA-011 - Performans ekrani ham veri tablosu degil karar ozeti olmali

- Tarih: 2026-09-02
- Alan: Admin / Performans / Gozlemlenebilirlik / UX / Backend
- Ortam: Canli web admin paneli, Performans sekmesi, 24 saat penceresi
- Jarvis hedefi: Yonetici ilk bakista "sistem saglikli mi, ne degisti, hangi route etkiliyor, veri ne kadar guvenilir ve ne yapmaliyim" sorularinin temiz cevabini almali; dakikalik metrik satirlari ve teknik ornekler yalnizca sonucu dogrulamak icin acilan kanit katmaninda kalmali.
- Adimlar: Performans sekmesini ac; ozet kartlarini, dakikalik Trend tablosunu ve en yavas route orneklerini incele.
- Beklenen: Esiklere dayali tek bir saglik ozeti, onceki doneme gore degisim, veri/ornek guveni, en etkili problemler ve dogrudan inceleme aksiyonu gorulmelidir. Ham zaman serisi varsayilan ekrani isgal etmemelidir.
- Gerceklesen: Ustte dort yalniz metrik karti, altta uzun dakikalik Trend tablosu ve route ornekleri bulunuyor. Degerler neyin iyi/kotu oldugunu, esikleri, onceki donem farkini veya gercek kullanici etkisini soylemiyor; yonetici ham veriyi zihninde birlestirmek zorunda kaliyor.
- Ekrandaki somut okuma riski:
  - Referansta toplam istek 45, hata orani %0, P50/P95/P99 488.0 / 935.8 / 1064.0 ms, yavas istek 0 gorunuyor.
  - Kodda yavas istek esigi 1500 ms; admin slow-request sorgusu da minDurationMs=1500 kullaniyor. P95 yaklasik 936 ms iken yavas istek 0 olabilir, fakat esik yazmadigi icin bu sonuc yanlis bicimde "sorun yok" diye okunabilir.
  - Dakikalik tabloda P95 0.0 gorunen satirlar gercek sifir gecikme gibi sunulmamali; percentile ornegi yoksa "Veri yok" denmelidir.
  - 45 istek gibi dusuk hacimde ozellikle P99 tekil orneklerden kolay etkilenir. Ornek sayisi ve "dusuk guven" durumu gosterilmelidir.
- Varsayilan bilgi mimarisi:
  - En ustte tek durum: Saglikli, Izlenmeli, Kritik veya Veri yetersiz. Durum belgelenmis esiklerden uretilmeli ve son guncellenme zamaniyla gorunmelidir.
  - Dort karar karti yeterli olmali: P95 ve hedefe uzaklik, hata orani, trafik/ornek guveni, etkilenen route. P50/P99 acilir ayrintida kalabilir.
  - Her kart mevcut deger, esik/SLO, onceki esit pencereye gore fark, yon ve kisa anlam gostermelidir.
  - Yavas istek etiketi "Yavas istek (>=1500 ms)" olarak esigiyle yazilmali; esik ve hesap ayni kaynaktan beslenmelidir.
  - Renk tek basina anlam tasimamali; etiket, ikon ve metin birlikte kullanilmalidir.
- Trend ve anomali sunumu:
  - Dakikalik tablo yerine istek hacmi, P95 ve hata oranini ayni zaman baglaminda gosteren sade trend grafik kullanilmali; yalniz anlamli spike/degisimler isaretlenmelidir.
  - Grafik ne zaman bozuldu, ne kadar surdu ve duzeldi mi sorularini cevaplamalidir.
  - Bos bucket ile gercek 0 ayrilmali; telemetry gecikmesi ve kismi veri acik durum olarak gosterilmelidir.
  - Zaman dilimi ve pencere acik olmali; bucket boyutu secilen pencereye gore okunabilir kalmalidir.
  - Ham zaman kirilimi "Ham kaniti gor" altinda filtrelenebilir/indirilebilir ikincil detay olarak korunmalidir.
- Route ozeti:
  - Liste yalniz en yuksek P95'e gore degil; trafik payi, hata, gecikme ve tekrar sayisiyla "en cok etki yaratan" route'lari siralamalidir.
  - Her satir route/method, P95, istek-ornek sayisi, hata orani, onceki donem farki, etki seviyesi ve Incele aksiyonu gostermelidir.
  - Az ornekli route "dusuk guven" ile isaretlenmeli; tek yavas ornek sistemik sorun gibi sunulmamalidir.
  - En yavas, en hatali ve en cok etkilenen kavramlari ayrilmali; kompakt filtrelerle degistirilebilmelidir.
  - Route detayinda zaman araligi, ornek dagilimi ve ham slow-request kaniti bulunmali; hassas veri varsayilan listede aciga cikmamalidir.
- Esik, guven ve sonuc sozlesmesi:
  - P95/hata esikleri belgelenmeli; normal/uyari/kritik sinirlari frontend icindeki gizli sabitlerden turetilmemelidir.
  - Minimum ornek sayisi tanimlanmali. Bu saglanmiyorsa yesil basari yerine Veri yetersiz kullanilmalidir.
  - Baseline yoksa fark 0% uydurulmamali; Karsilastirma verisi yok denmelidir.
  - Ozet, timeseries ve slow-route cevaplari ayni pencere, timezone, esik ve veri tazeligi bilgisini tasimalidir.
  - Dashboard sistem sagligi (QA-004) ile Performans ekrani ayni esik ve durum dilini kullanmalidir.
- Aksiyon ve kanit:
  - Yalniz kanita dayali aksiyonlar sunulmali: Yavas route'lari incele, Hata orneklerini ac, Onceki donemle karsilastir. Veri desteklemiyorsa kok neden iddiasi yazilmamalidir.
  - Teknik tablo, ham ornek ve percentile dagilimi acilir kanit bolumlerinde kalmalidir.
  - Loading, stale, kismi hata, bos ve tekrar dene durumlari bolumsel gorunmelidir.
  - Son veri zamani, pencere ve telemetry kapsami gorunur olmali; Yenile dugmesi sonuc geri bildirimi vermelidir.
- Kabul kriterleri:
  - Yonetici bes saniye icinde ana durum, esige uzaklik, en buyuk etki, veri guveni ve birincil aksiyonu bulabilir.
  - Yavas istek 0 her zaman esigiyle okunur; 1499/1500/1501 ms sinir testi UI ve API'de ayni sonucu verir.
  - Orneksiz bucket 0 ms degil Veri yok; az ornekli percentile dusuk guven; baseline olmayan pencere karsilastirma verisi yok gosterir.
  - KPI, grafik, route ozeti ve ham tabloda ayni pencerenin istek/hata/ornek sayilari API kanitiyla uyusur.
  - Yogun trafikli orta gecikmeli route ile tek ornekli cok yavas route farkli etki/guvenle siralanir.
  - Hata, gecikme spike'i, telemetry kesintisi, stale veri ve bos pencere birbirinden ayrilir; hicbiri sessizce yesil olmaz.
  - Masaustu ve mobilde ozet tabloda bogulmadan okunur; detay tablolar klavye, ekran okuyucu ve kontrollu yatay tasma ile erisilebilirdir.
  - Once/sonra ekran goruntusu QA'i ve API/ham kayit karsilastirmasi yapilir; telemetry toplama regresyona ugramaz.
- Kanit:
  - Mevcut ekran: docs/assets/manual-qa/qa-011-current-admin-performance.png
  - Ilgili kod: chatapp-backend/admin.html (Performans KPI, timeseries ve slow-request gorunumu); chatapp-backend/admin.js (/performance/overview, /performance/timeseries, /performance/slow-requests); chatapp-backend/index.js (REQUEST_TELEMETRY_SLOW_MS = 1500)
- Oncelik: P2
- Durum: Acik
### QA-012 - Davranis Analitigi veriyi degil davranis sonucunu anlatmali

- Tarih: 2026-09-02
- Alan: Admin / Davranis Analitigi / Eslesme / Gozlemlenebilirlik / UX / Backend
- Ortam: Canli web admin paneli, Davranis Analitigi sekmesi, 24 saat ve saatlik kirilim
- Jarvis hedefi: Yonetici ilk bakista "kullanicilar nerede kayboluyor, ne degisti, kac kisi etkilendi, hangi eslesmelerde ne oldu ve neyi incelemeliyim" sorularinin suzulmus cevabini almali. Ham event listesi analizin kendisi degil, sonucun geriye izlenebilir kaniti olmalidir.
- Adimlar: Davranis Analitigi sekmesini ac; KPI, funnel, saatlik Trend, event/platform dagilimi, kullanici bazli davranis ve Son Olay Akisi bolumlerinden belirli bir eslesmenin nasil sonuclandigini bulmaya calis.
- Beklenen: Ana kayip ve degisim acik bir ozetle gorulmeli; funnel'in birimi ve sirasi guvenilir olmali; bir eslesme veya sohbet tek bir hikaye halinde acilabilmeli; ham event/metadata yalniz istenirse gorulmelidir.
- Gerceklesen:
  - Ustte yogun filtre satiri ve sekiz KPI, ardindan alti funnel karti, saat saat uzun tablo, event dagilimi, platform dagilimi, kullanici tablosu ve 120 kayda kadar raw olay akisi ayni uzun sayfaya yigilmis durumdadir.
  - Trend grafik degil sekiz kolonlu saatlik tablodur; bos saatler de satir uretir. Yonetici degisimi veya anomalinin zamanini tarayarak bulmak zorundadir.
  - Son Olay Akisi her eventi ayri satirda ve metadata'yi JSON olarak gosterir. Tek eslesmenin teklif, iki katilimci karari, sohbet baslangici ve bitis eventleri tek olay hikayesinde birlesmez.
  - Ekran overview, funnel, timeseries, users ve recent olmak uzere bes istegi birlikte yukler; bunlardan biri hata verirse mevcut frontend tum Davranis Analitigi sayfasini hata durumuna dusurur. Kismi veri korunmaz.
- Dogrulanan anlam ve sayim riskleri:
  - Mevcut funnel gercek sirali/cohort funnel degildir. Her adimda secilen pencere icinde o event'e sahip bagimsiz tekil kullanicilar sayilir ve tum yuzdeler gelen kullanici sayisina bolunur. Ayni yolculugu sirayla tamamladiklari kanitlanmaz.
  - Pencerenin basinda aramaya devam eden fakat user_connected eventi pencere disinda kalan kullanici, sonraki adimlarda olup tabanda olmayabilir. Bu nedenle adimlar teorik olarak artabilir veya yuzde 100'u gecebilir.
  - Overview icinde kisi ve event birimleri karisir: Tekil Gelen distinct kullanicidir; Match Denemesi event sayisidir.
  - match_offer_received her katilimci icin ayri kaydedilir. Tek gercek eslesme iki offer eventi uretebilir; Match Bulunan etiketi bunu tek eslesme sayisi gibi gostermemelidir.
  - chat_started da ayni match/conversation icindeki iki katilimci icin ayri kaydedilir. Sohbet Baslangici sayisi event sayisiysa tek sohbet iki kez gorunebilir.
  - Kabul, red ve oto kabul katilimci kararlaridir; eslesmenin nihai sonucu ile ayni birim degildir. Bir tarafin kabulu tek basina basarili eslesme anlamina gelmez.
  - Dusuk hacimde, ornegin referanstaki 4 gelen ve 1 deneme, oranlar kesin urun sonucu gibi okunmamali; ornek sayisi ve guven durumu gosterilmelidir.
- Hedef bilgi mimarisi:
  - Sayfa uc katmana ayrilmali: Ozet, Yolculuklar ve Ham Kanit. Varsayilan acilis yalniz Ozet olmalidir.
  - Ust filtreler sade olmali: zaman penceresi ve platform ilk gorunumde; ozel tarih, kirilim ve kullanici/match arama Gelismis filtrelerde bulunmalidir.
  - Aktif filtreler insan dilinde tek satirda ozetlenmeli; filtreyi temizlemek ve paylasilabilir ayni gorunume donmek kolay olmalidir.
  - Sayfa basi tek Jarvis cumlesi vermelidir: ornegin "Son 24 saatte 4 kullanicidan 1'i arama baslatti; eslesme olusmadi. Ornek dusuk, onceki donemle guvenilir karsilastirma yapilamiyor."
  - Bu cumle deterministik, sayilara geri izlenebilir kurallarla uretilmeli; veri yokken kok neden veya kesin yorum uydurulmamalidir.
- Ozet katmani:
  - En fazla dort ana sonuc gosterilmeli: aktif/tekil kullanici, aramaya baslama, gercek eslesme cifti, baslayan benzersiz sohbet. Her kart birimini acik yazmalidir.
  - Onceki esit pencereye gore sayi ve oran degisimi, ornek guveni ve veri tazeligi ayni alanda bulunmalidir.
  - "En buyuk kayip" otomatik secilmeli: baglanti -> arama, arama -> teklif, teklif -> iki taraf kabul, kabul -> sohbet. Kac kisi/eslesme kaybedildigi ve degisim yonu yazilmalidir.
  - Basarisiz sonuclar; kuyrukta bekleme, es bulunamamasi, red, timeout/oto kabul, peer ayrilmasi, iptal, baglanti kopmasi ve server error gibi acik nedenlere ayrilmalidir. Mevcut telemetry nedeni ayirmiyorsa "Olculmuyor" denmeli ve gerekli event/reason eklenmelidir.
  - Platform farki yalniz anlamli sapma varsa one cikmali; tum platform dagilim tablosu varsayilan gorunumde bulunmamalidir.
  - Anomali/degisim yoksa ekran sessiz ve soft kalmali; her metrik ayni vurgu seviyesinde bagirmamalidir.
- Guvenilir funnel sozlesmesi:
  - Once analiz birimi secilmelidir: kullanici yolculugu, arama denemesi veya match cifti. Farkli birimler tek funnel icinde karistirilmamalidir.
  - Kullanici funnel'i event sirasi ve tanimli sure/cohort kuraliyla hesaplanmalidir: connected -> search_attempt -> queued/offer -> decision -> chat_started.
  - Match funnel'i match_id bazinda tekil olmalidir: teklif olustu -> iki katilimci sonucu -> nihai kabul/red/timeout -> conversation olustu -> sohbet basladi/bitti.
  - Sohbet sayimi conversation_id distinct olmali; katilimci basina iki chat_started eventinin toplami sohbet sayisi diye sunulmamalidir.
  - Adimlar bir onceki adima gore donusum ve kaybi gostermeli; toplam gelen kullaniciya gore oran ikincil detay olabilir.
  - Pencere sinirini asan yolculuklar icin cohort karari belgelenmelidir: baslangici pencerede olan yolculugun sonucu belirli takip suresince izlenmeli veya eksik yolculuk acikca "tamamlanmadi/veri disi" sayilmalidir.
  - Duplicate, reconnect ve ayni kullanicinin birden cok arama denemesi icin tekillestirme kurali acik olmalidir.
- Trend ve sinyal sunumu:
  - Saatlik ham tablo yerine funnel donusumu, arama hacmi, match/chat sayisi ve basarisizlik oranini sade grafikle gosteren sinyal alani kullanilmalidir.
  - Yalniz anlamli degisim, spike veya sifira dusus isaretlenmeli; bos saat satirlari sayfayi uzatmamalidir.
  - Yonetici bir sinyale tiklayinca ilgili zaman araligi ve olay hikayeleri filtrelenmis olarak acilmalidir.
  - Saatlik/gunluk bucket otomatik secilebilir; timezone ve veri tazeligi gorunur kalmalidir.
  - Onceki donem ve secilen platform ayni grafikte karsilastirilabilir olmali, fakat dusuk ornekte yaniltici trend cizilmemelidir.
- Yolculuklar katmani:
  - Olay akisi raw event sirasi degil, match_id veya conversation_id ile gruplanmis hikaye kartlari/listesi olmalidir.
  - Her hikaye baslangic zamani, iki katilimci, platformlar, arama/teklif suresi, kararlar, nihai sonuc, sohbet suresi ve bitis nedenini temiz etiketlerle gostermelidir.
  - Sonuc filtreleri bulunmalidir: Sohbet basladi, Es bulunamadi, Red, Timeout/oto kabul, Iptal, Baglanti koptu, Eksik event, Server error.
  - Kullanici, match_id veya conversation_id aramasi dogrudan ilgili hikayeyi getirmeli; onlarca event arasinda manuel eslestirme gerektirmemelidir.
  - Hikaye icindeki "Teknik kaniti ac" aksiyonu kronolojik eventleri, ID'leri ve sanitize metadata'yi gostermelidir.
  - Eksik veya sirasi bozuk eventler normal basari gibi birlestirilmemeli; "Eksik telemetry" uyarisi ve eksik adim gosterilmelidir.
- Ham kanit katmani:
  - Event Dagilimi, Platform Dagilimi, Kullanici Bazli Davranis, saatlik tablo ve raw Son Olay Akisi varsayilan sayfadan bu katmana tasinmalidir.
  - Teknik event adlari yonetici dostu TR/EN etiketlere donusmeli; raw event_name yaninda veya acilir kanitta korunmalidir.
  - Metadata ham JSON yerine anahtar bilgilerin etiketli ozetiyle sunulmali; JSON yalniz kopyalanabilir gelismis detayda bulunmalidir.
  - Server-side pagination/cursor, event/sonuc/platform/tarih filtreleri ve kontrollu disari aktarma bulunmalidir; sabit ilk 100/120 kayit tum gercek gibi sunulmamalidir.
  - user_id, device_id, client_id ve davranis izi hassas kabul edilmeli; yetki, maskeleme, audit ve saklama suresi kurallari uygulanmalidir.
- Durum ve dayanıklilik:
  - Overview, funnel, trend, yolculuk ve kanit bolumleri bagimsiz loading/kismi hata/stale/bos durumuna sahip olmalidir; tek endpoint hatasi tum sayfayi yok etmemelidir.
  - Son basarili yenileme, pencere, timezone ve kapsanan platform gorunmelidir.
  - Yenile islemi mevcut sonucu aniden bosaltmamali; eski verinin stale oldugunu aciklayarak yeni veri gelene kadar kontrollu gostermelidir.
  - Sifir olay, dusuk ornek ve telemetry arizasi ayni "0" gorunumuyle karistirilmamalidir.
- Kabul kriterleri:
  - Yonetici bes saniyede ana donusumu, en buyuk kaybi, onceki donem farkini, veri guvenini ve inceleme aksiyonunu bulabilir.
  - Tek gercek match iki match_offer_received uretse de match sayisi 1; iki chat_started uretse de benzersiz sohbet sayisi 1 gorunur.
  - Ordered funnel'da her kullanici/adim tanimli sirayi ve sureyi saglar; bagimsiz distinct event toplamlari funnel diye sunulmaz.
  - Pencere sinirini asan, reconnect olan, tekrarlanan denemeli ve eksik eventli yolculuklar belgelenmis kurala gore hesaplanir.
  - Belirli bir match/conversation aramayla olay hikayesine tek adimda ulasilir; kararlar, nihai sonuc ve bitis nedeni raw log taramadan anlasilir.
  - Ozet, funnel, trend, yolculuk ve ham kanit sayilari ayni filtrelerde DB eventleriyle uzlasir; fark varsa nedeni gorunur olur.
  - Dusuk ornek kesin basari/basarisizlik gibi yorumlanmaz; baseline yoksa 0% fark uydurulmaz.
  - Bir endpoint hata verdiginde saglam bolumler gorunur kalir ve problemli bolum tekrar denenebilir.
  - Masaustu/mobil ekran goruntusu QA'i; klavye/ekran okuyucu, uzun kullanici adi, cok eventli hikaye, pagination ve hassas veri QA'i tamamlanir.
- Kanit:
  - Mevcut ekran: docs/assets/manual-qa/qa-012-current-admin-behavior-analytics.png
  - Ilgili kod: chatapp-backend/admin.html (renderAnalyticsView, loadAnalyticsTab); chatapp-backend/admin.js (/analytics/overview, /analytics/funnel, /analytics/timeseries, /analytics/users, /analytics/recent); chatapp-backend/index.js (trackBehaviorEvent, match_search_attempt, match_offer_received, match decisions, chat_started, chat_ended)
- Oncelik: P2
- Durum: Acik
### QA-013 - Yasal Metinler soft bir editor ve guvenli yayin merkezi olmali

- Tarih: 2026-09-02
- Alan: Admin / Yasal Metinler / TR-EN Icerik / Yayin / Audit / UX / Backend / Veritabani
- Ortam: Canli web admin paneli, Yasal Metinler sekmesi
- Jarvis hedefi: Yonetici ilk bakista hangi belgelerin yayinda oldugunu, hangi dilde eksik veya degisiklik bulundugunu, degisikligin kullaniciya ve yeniden kabul akisina etkisini anlamali; yalnizca sectigi belgeyi temiz bir editor ve gercek son kullanici onizlemesiyle duzenlemelidir.
- Adimlar: Yasal Metinler sekmesini ac; Privacy, Terms ve Child Safety belgelerinin TR/EN iceriklerini ve footer ayarlarini incele; tek bir belgeyi degistirip neyin canliya gidecegini, surum etkisini ve geri alma yolunu bulmaya calis.
- Beklenen: Belge bazli durum ozeti, tek belge odakli editor, TR/EN karsilastirma, taslak, diff, son kullanici onizlemesi, surum/reaccept etki analizi ve kontrollu yayin akisi bulunmalidir.
- Gerceklesen:
  - Footer metinleri/URL'leri, Terms ve Privacy surumleri ile Privacy, Terms ve Child Safety TR/EN baslik-icerikleri tek uzun formda ayni anda acilir.
  - Alti uzun textarea ve cok sayida input hiyerarsi olmadan alt alta uzar; hangi belgenin duzenlendigi, hangisinin eksik veya yayina hazir oldugu kolay anlasilmaz.
  - Tek Kaydet dugmesi tum formu tek payload olarak PUT /admin/legal endpointine yollar ve ayni legal_content_v1 canli kaydini degistirir.
  - Taslak, yayin onayi, degisiklik ozeti, son kullanici onizlemesi, yayin gecmisi veya geri alma arayuzu bulunmaz.
- Dogrulanan canli etki ve risk:
  - Public /api/legal endpointi ayni app_settings kaydini okur; basarili kayit yeni icerigi web istemcisine dogrudan sunar.
  - Terms veya Privacy surum degeri degistiginde kullanicinin son kabul ettigi surumle esitlik bozulur ve requiresReaccept true olur. Profil, arkadas, push ve support gibi korunan akislarda 428 LEGAL_REACCEPT_REQUIRED sonucu dogabilir.
  - Buna karsin Terms/Privacy metni degisip surum ayni kalirsa mevcut kabuller gecerli sayilmaya devam eder. Ekran bu iki karar arasindaki hukuki/urun etkisini aciklamaz.
  - Child Safety icin ayri bir kabul surumu mevcut degildir; degisikligin versiyonlama ve kullanici bilgilendirme kurali tanimli gorunmez.
  - Mevcut audit LEGAL_UPDATE, yeni Terms/Privacy surumleri ve zamani kaydeder; hangi belge/dil/alanin nasil degistigini, gerekceyi veya onceki metin hash/surumunu kanitlamaz.
  - Placeholder kontrolu yalniz belirli kelime kaliplarini uyarir ve kaydi engellemez. TR/EN anlamsal esdegerligi veya metnin hukuki olarak tamam oldugunu dogrulayamaz.
  - Backend tum alanlari zorunlu tutar ve karakter/URL sinirlarini kontrol eder; fakat admin alan bazli sayac ve hata gostermedigi icin sorun ancak kaydetme sonrasinda genel hata/alert olarak gorunur.
- Hedef bilgi mimarisi:
  - Varsayilan ekran editor degil yayin ozeti olmalidir.
  - Dort sakin kart bulunmalidir: Gizlilik Politikasi, Kullanim Sartlari, Cocuk Guvenligi ve Footer/Linkler.
  - Her belge karti Yayinlandi/Taslak/Eksik/Uyari durumunu, mevcut surumu, son yayin zamanini, TR-EN tamligini, degisiklik olup olmadigini ve Duzenle aksiyonunu gostermelidir.
  - Ana ozet yalniz gercek sorunlari one cikarmalidir: eksik dil, placeholder, gecersiz link, yayinlanmamis taslak, surum ile icerik uyumsuzlugu veya bekleyen reaccept etkisi.
  - Footer/Linkler hukuki belge iceriklerinden ayrilmali; seyrek degisen ikincil ayarlar olarak kendi kisa panelinde bulunmalidir.
  - Son yayinlayan admin ve son yayin zamani gorunmeli; ham audit ayrintisi acilir kanit katmaninda kalmalidir.
- Belge editoru:
  - Bir seferde yalniz secilen belge duzenlenmelidir; diger belgelerin uzun icerikleri sayfada render edilmemelidir.
  - TR ve EN sekmeleri veya kontrollu yan yana karsilastirma sunulmalidir. Dar ekranda iki sutun zorlanmamali, dil sekmelerine donmelidir.
  - Baslik, icerik, surum ve belgeye ozel durum birlikte bulunmali; footer alanlari belge editorune karismamalidir.
  - Her alanda karakter sayaci, zorunluluk, limit, kaydedilmemis degisiklik ve alan bazli hata gorunmelidir.
  - Uzun metin editoru okunabilir font, satir araligi, arama, kontrollu yukseklik ve tam ekran duzenleme secenegi sunmalidir; alti ayri ic scroll ayni anda gorunmemelidir.
  - Sayfadan/sekmeden ayrilirken kaydedilmemis degisiklik varsa acik uyari verilmelidir.
  - Klavye kisayolu varsa kazara canli yayin degil yalniz taslak kaydi yapmalidir.
- Icerik formati ve onizleme:
  - Desteklenen format acik secilmelidir: duz metin, Markdown veya guvenli zengin metin. Admin editoru ile LegalScreen ayni render sozlesmesini kullanmalidir.
  - Mevcut icerikte # ve ## benzeri Markdown gorunumleri varsa bunlar son kullanicida baslik mi yoksa literal karakter mi olacak onizlemede birebir gorulmelidir.
  - TR ve EN icin masaustu/mobil son kullanici onizlemesi bulunmali; baslik, paragraflar, listeler, linkler ve uzun satirlar gercek uygulamadaki gibi render edilmelidir.
  - Onizleme sanitize edilmis olmali; script, tehlikeli HTML, javascript URL ve istenmeyen dis link davranisi engellenmelidir.
  - Footer linkleri icin hedef URL ve kullaniciya gorunen etiket birlikte test edilebilmelidir.
- Taslak ve yayin akisi:
  - Duzenleme canli kaydi degistirmemeli; once Taslagi Kaydet ile belge/dil bazli taslak olusmalidir.
  - Yayinla adiminda mevcut canli surum ile taslak arasinda alan bazli diff gosterilmelidir: eklenen, silinen ve degisen bolumler.
  - Admin degisiklik gerekcesi girmeli ve degisikligin sinifini secmelidir: yazim/format, aciklama, maddi hukuki degisiklik.
  - Terms/Privacy maddi degisikliginde surum artisi zorunlu olmali; yalniz yazim degisikliginde surum ayni kalacaksa bu karar gerekce ve audit ile acik kaydedilmelidir.
  - Surum degisimi icin etki ozeti backend tarafindan hesaplanmalidir: yeniden kabul etmesi beklenen kullanici sayisi, etkilenen akislari, mevcut ve yeni surumler.
  - Yayin onayi hangi belgelerin/dillerin degisecegini, reaccept etkisini, geri alinamayan kullanici kabullerini ve yayinlayan admini acik gostermelidir.
  - TR/EN zorunlu alanlari, placeholder veya onizleme hatasi varsa yayin engellenmeli; yalnizca uyariyi kapatip gecme olmamalidir.
  - Bir belgenin yayin hatasi diger ilgisiz belge/footer taslagini kaybettirmemelidir.
- Surum, gecmis ve geri alma:
  - Her yayin degismez bir snapshot olusturmalidir: belge, TR/EN icerik, surum, icerik hash'i, admin, gerekce, yayin zamani ve onceki yayin baglantisi.
  - Gecmis ekraninda surumler karsilastirilabilmeli ve o tarihte kullaniciya sunulan tam metin gorulebilmelidir.
  - Geri alma eski snapshot'i sessizce overwrite etmemeli; yeni bir yayin olayi olarak onizleme, etki hesabi ve onaydan gecmelidir.
  - Terms/Privacy geri almasinda kabul surumunun nasil davranacagi acik politika olmalidir; daha eski surume donmek mevcut kabul kayitlarini belirsiz hale getirmemelidir.
  - Eszamanli iki admin editorunde optimistic concurrency/revision kontrolu bulunmali; eski acik sayfa yeni yayini ezmemelidir.
- Jarvis yayin ozeti:
  - Yayin sonrasinda temiz sonuc gosterilmelidir: hangi belge/diller yayinlandi, onceki -> yeni surum, yeniden kabul etkisi, public API dogrulamasi ve onizleme linkleri.
  - Teknik DB/audit ayrintisi varsayilan mesajda bulunmamali; Kaniti gor ile acilmalidir.
  - Kismi yayin veya public API dogrulama hatasi basari gibi gosterilmemeli; hangi adimin tamamlandigi ve guvenli sonraki aksiyon yazilmalidir.
  - Son kullaniciya yansima cache veya istemci yenilemesine bagliysa beklenen yayilma suresi belirtilmelidir.
- Durumlar ve erisilebilirlik:
  - Loading, bos/default fallback, taslak var, kayit basarisiz, yayin basarisiz, stale editor, conflict ve yetkisiz durumlari ayri sunulmalidir.
  - Kaydet/Yayinla dugmeleri loading sirasinda tekrar tetiklenmemeli; sonuc toast'a ek olarak kalici durum satirinda gorulmelidir.
  - Sticky aksiyon alani uzun metinde her zaman ulasilabilir olmali fakat icerigi kapatmamalidir.
  - Belge ve dil sekmeleri klavye/ekran okuyucu semantigine uymali; durum yalniz renkle anlatilmamalidir.
- Kabul kriterleri:
  - Yonetici bes saniyede uc belgenin yayin/taslak/eksik durumunu, mevcut surumlerini ve ana riski gorebilir.
  - Tek belge acildiginda diger uzun metinler gorunmez; TR/EN duzenleme ve gercek son kullanici onizlemesi kolayca degistirilir.
  - Kaydedilmemis degisiklik sayfadan ayrilirken kaybolmaz veya acik onay olmadan atilmaz.
  - Kaydet yalniz taslak olusturur; canli public API ancak diff, validasyon, etki ozeti ve yayin onayindan sonra degisir.
  - Terms/Privacy surum degisikligi beklenen kullanicilarda requiresReaccept uretir; surum ayniysa mevcut kabuller korunur ve bu karar audit'te gerekcelidir.
  - Maddi icerik degisip surum unutuldugunda yayin engellenir veya acik yetkili karar gerektirir; sessiz uyumsuzluk olmaz.
  - TR/EN eksigi, placeholder, limit, gecersiz URL ve guvensiz icerik alan bazinda gosterilir ve riskli yayin engellenir.
  - Yayin snapshot'i, diff, admin, gerekce ve onceki surum korunur; geri alma yeni denetlenebilir yayin olayi yaratir.
  - Public /api/legal, web LegalScreen, footer, kayit kabul metni ve reaccept modali ayni yayin/surum degerlerini gosterir.
  - Eszamanli editor conflict'i, API hatasi, kismi dogrulama, mobil/dar ekran ve uzun 30 bin karakter siniri otomatik/manual QA'dan gecer.
- Kanit:
  - Mevcut ekran: docs/assets/manual-qa/qa-013-current-admin-legal-editor.png
  - Ilgili kod: chatapp-backend/admin.html (renderLegalEditor, collectLegalPayload, saveLegalContent, placeholder warning); chatapp-backend/admin.js (GET/PUT /legal, LEGAL_UPDATE audit); chatapp-backend/utils/legalContent.js (normalizasyon, validasyon, app_settings kaydi); chatapp-backend/utils/legalAcceptance.js (surum esitligi ve requiresReaccept); chatapp-backend/index.js (GET /api/legal); chatapp-frontend/src/App.jsx ve screens/LegalScreen.jsx
- Oncelik: P1
- Durum: Acik
### QA-014  Anonim eşleşme arama ekranını canlı, dürüst ve işlevsel hâle getir

**Durum:** Otomatik doğrulandı; Web/Android manuel QA Checkpoint B / Wave 19'a ertelendi
**Öncelik:** P1  
**Tarih:** 2026-09-02  
**Alan:** Frontend / anonim eşleşme / WebSocket durumları / animasyon / içerik / TR-EN / Web-Android  
**Bağlantılı kayıt:** QA-003 eşleşme bulundu ve kabul ekranını kapsar; QA-014 ise arama ve bekleme aşamasını kapsar. kisi tek ve kesintisiz bir deneyim olarak ele alınmalıdır.

#### Amaç ve ana ürün ilkesi

Bu ekran yalnızca bekliyorsun demeyecek. Kullanıcıya aynı anda üç şey sağlayacak:

1. Aramanın gerçekten devam ettiğini hissettirecek.
2. Bağlantı ve eşleşme durumunu dürüstçe anlatacak.
3. Kullanıcıyı başlayacak sohbete hazırlayacak.

Ekran canlı olacak fakat yorucu olmayacak; kullanıcıya küçük ama anlamlı bir kontrol verecek. Jarvis yaklaşımına uygun olarak ham event, teknik durum veya metin yığını göstermeyecek; sistem veriyi süzüp şu anda ne oluyor, sorun var mı, kullanıcı ne yapabilir? sorularını tek bakışta yanıtlayacak.

Net kararlar:

- Mevcut pasif ve otomatik değişen alıntıları çoğaltmak ana çözüm olmayacak.
- Anahtar/radar görseli iki anonim TalkX parçacığının canlı animasyonuyla değiştirilecek.
- Metinler yalnızca süreye değil gerçek WebSocket ve kuyruk durumuna göre değişecek.
- Eşleşme zamanı bilinmediği için sahte ilerleme çubuğu, yüzde veya kalan süre gösterilmeyecek.
- Sohbet havası ilk sürümde eşleştirmeyi etkilemeyecek ve havuzu bölmeyecek.
- Sohbet başlangıcı kendiliğinden dönmeyecek; kullanıcı Başka soru ile değiştirecek.
- Seçilen hava ve soru eşleşme teklifi, QA-003 kabul ekranı ve sohbet başlangıcı boyunca korunacak; otomatik gönderilmeyecek.
- Ekran soft, kısa ve küçük telefonda kaydırma gerektirmeden `100dvh` içine sığacak.

#### Mevcut sorun

- `MatchScreen.jsx` cyan anahtar, radar halkaları ve döngüsel tarama göstergesi kullanıyor; TalkXe özgü canlı bir eşleşme hissi kurmuyor.
- Beş sabit soru sekiz saniyede bir otomatik dönüyor; kullanıcı seçimi olmadığı için alan pasif dolguya dönüşüyor.
- `handleStartAnon`, sunucudan `queued` onayı gelmeden eşleşme ekranını açıyor; hazırlanma ve aktif arama ayrışmıyor.
- Uzayan bekleme, reconnect ve bağlantı kurulamadı durumları doğru ve ayrı biçimde anlatılmıyor.
- PTAL ET sert ve bağlamsız; kullanıcı aslında aramayı durduruyor.
- Arama animasyonu gerçek `match_offer` ile anlamlı bir finale ulaşmadığı için QA-003 kabul ekranına geçiş kopuk kalıyor.

#### 1. Yeni ana animasyon  iki anonim TalkX parçacığı

- Bir parçacık TalkX cyan, diğeri mor/pembe neon renginde olacak.
- Parçacıklar cinsiyet, kimlik veya fiziksel özellik çağrıştırmayan soyut biçimler olacak.
- Farklı yörüngelerde hareket edecek, zaman zaman yaklaşacak ve yeniden uzaklaşacaklar.
- Yaklaştıklarında aralarında kısa ışık çizgileri, dalgalar veya yumuşak enerji izi oluşabilecek.
- Gerçek `match_offer` gelmeden tamamen birleşmeyecekler. Animasyon neredeyse eşleşti gibi sahte bir ilerleme hissi vermeyecek.
- Normal döngü yaklaşık 68 saniye olacak; hızlı, oyun gibi veya dikkat dağıtan değil ambient ve soft görünecek.
- Gerçek teklif geldiğinde parçacıklar merkeze yaklaşacak, kısa cyanpembe ışık dalgası oluşacak ve QA-003 ekranına geçilecek.
- Reconnect sırasında hareket yavaşlayacak, bağlantı çizgisi kesik veya hafif titreşimli görünecek. Bağlantı dönünce kısa toparlanma dalgasıyla normal harekete geçilecek.
- `prefers-reduced-motion` açıkken yörünge kaldırılacak; sabit iki parçacık ve hafif opacity nefesi kullanılacak.
- Animasyon CSS/SVG temelli ve WebView dostu olmalı; ağır canvas, sürekli pahalı blur veya gereksiz render üretmemeli.

#### 2. Gerçek arama durum modeli

UI açık bir `searchPhase` modeli kullanmalı:

- `preparing`: `joinQueue` gönderildi, sunucunun `queued` onayı bekleniyor.
- `queued`: Sunucu kuyruğa girişi onayladı, aktif arama başladı.
- `extended`: Aynı arama bekleme eşiklerini geçti.
- `reconnecting`: WebSocket gerçekten koptu, yeniden bağlantı deneniyor.
- `offline`: Yeniden bağlantı belirlenen denemeler sonunda kurulamadı.
- `cancelled`: Kullanıcı veya sunucu aramayı kapattı.
- `offer`: Gerçek `match_offer` alındı; QA-003 kabul aşamasına geçiliyor.

Davranış kuralları:

- `preparing` sırasında sayaç başlamayacak.
- `queued` yalnızca sunucunun `queued` cevabıyla başlayacak ve o anda `queuedAt` tutulacak.
- `reconnecting` yalnızca gerçek socket durumundan üretilecek; beklemenin uzaması bağlantı sorunu gibi sunulmayacak.
- Sunucu kuyruk konumunu gerçekten koruyorsa kaldığı yerden sürdürülüyor denebilir. Yeni kuyruk açılıyorsa arama yeniden başlatıldı denmeli.
- Kuyruk korunacaksa sunucu tarafında `searchId` veya eşdeğer kimlik ve yeniden katılım onayı tanımlanmalı; istemci varsayım yapmamalı.
- Durdurmada tek `leaveQueue` gönderilmeli, tekrar tıklama engellenmeli ve geçici arama durumu temizlenmeli.
- Eski aramadan geciken `queued`, `match_offer` veya reconnect olayları yeni aramayı etkilememeli; arama kimliği/oturum koruması kullanılmalı.
- `offer` aşamasına yalnızca gerçek `match_offer` geçirebilmeli.

#### 3. Duruma ve bekleme süresine bağlı metin sistemi

Metinler TR ve EN için doğal karşılıklarla tanımlanacak; eşikler tek bir config kaynağında tutulacak.

**Arama hazırlanırken  `preparing`**

- Başlık: Arama hazırlanıyor
- Alt metin: Bağlantın kontrol ediliyor
- Sayaç gösterilmez.

**Kuyruk onayından sonraki ilk saniyeler  yaklaşık 08 saniye**

- Başlık: Eşleşme aranıyor
- Alt metin: Çevrimiçi biri aranıyor
- steğe bağlı destek: Seni yeni biriyle buluşturmaya çalışıyoruz

Mevcut sistem tercih tabanlı değilse Sana uygun biri aranıyor denmeyecek; karşılığı olmayan beklenti yaratmayacağız.

**Arama biraz uzadığında  yaklaşık 820 saniye**

- Başlık: Aramaya devam ediyoruz
- Alt metin: Yeni bir eşleşme aranıyor

**Ortam sakin olduğunda  yaklaşık 2045 saniye**

- Başlık: Şu an biraz sakin görünüyor
- Alt metin: Aramaya devam ediyoruz, biraz daha sürebilir

**Çok uzun sürdüğünde  yaklaşık 45 saniye ve sonrası**

- Başlık: Henüz yeni biri bulunamadı
- Alt metin: Aramaya devam edebilir veya daha sonra tekrar deneyebilirsin
- Arama zaten süresiz devam ediyorsa işlevsiz Aramaya devam et butonu olmayacak; açıklama ve Aramayı durdur yeterli.

**Bağlantı yeniden kurulurken  `reconnecting`**

- Başlık: Bağlantı yeniden kuruluyor
- Kuyruk gerçekten korunuyorsa: Aramanı kaldığı yerden sürdürmeye çalışıyoruz
- Kuyruk korunmuyorsa bu cümle kullanılmayacak.

**Bağlantı geri geldi fakat yeni kuyruk açıldıysa**

- Başlık: Bağlantı geri geldi
- Alt metin: Arama yeniden başlatıldı

**Bağlantı kurulamazsa  `offline`**

- Başlık: Bağlantı kurulamadı
- Alt metin: nternet bağlantını kontrol edip tekrar deneyebilirsin
- Aksiyonlar: Tekrar dene ve Aramayı kapat

#### 4. Dürüst geçen süre

- Sahte ilerleme, yüzde ve kalan süre olmayacak.
- Küçük ve ikincil bir geçen süre gösterilebilir: `00:08`.
- Sayaç yalnızca gerçek `queued` onayında başlayacak.
- ptalde sıfırlanacak, `match_offer` geldiğinde duracak.
- Bağlantı kopunca arama sunucuda duruyorsa sayaç duracak; yeni kuyrukta yeniden başlayacak, korunan kuyrukta aynı aramayı doğru sürdürecek.
- Süre `Date.now() - queuedAt` üzerinden hesaplanarak drift önlenecek.
- Sayaç her saniye ekran okuyucuya okutulmayacak; `aria-live` yalnız anlamlı durum değişikliklerinde kullanılacak.

#### 5. Sohbet havası seçimi

- Başlık: Sohbete nasıl başlamak istersin?
- Kategoriler: Rastgele, Eğlenceli, Gündelik, Derin. Samimi seçilecekse tüm sistemde tek ad kullanılmalı.
- Varsayılan Rastgele olacak.
- lk sürümde seçim eşleştirme havuzunu, önceliği veya sunucu filtresini değiştirmeyecek; düşük kullanıcı sayısında havuz bölünmeyecek.
- Seçim yalnızca soru destesini, kabul ekranındaki hazır başlangıcı ve sohbet açılınca sunulan öneriyi belirleyecek.
- Bu havadan biri aranıyor gibi yanlış vaat kullanılmayacak.
- Seçim arama oturumunda korunacak; kategori değişince o kategoriye ait yeni soru gösterilecek.
- Chipler klavye ile kullanılabilir, belirgin seçili durumda ve yeterli dokunma alanında olacak.

#### 6. şlevsel sohbet başlangıcı kartı

```text
Sohbet başlangıcı
Bugün seni en çok ne güldürdü?
                         Başka soru 
```

- Soru kendiliğinden değişmeyecek; kullanıcı Başka soru ile değiştirecek.
- Her kategoride 810 kaliteli soru; dil başına yaklaşık 3240 soru yeterli.
- Aynı oturumda yakın zamanda gösterilenler tekrar seçilmeyecek; havuz bitince kontrollü sıfırlanacak.
- Seçim `MatchScreen` içindeki local index olarak kalmayacak. `selectedMood` ve kararlı `selectedPromptId`, arama oturumu/App düzeyinde tutulacak.
- Aynı `promptId` için doğal TR ve EN karşılıkları olacak; dil değişiminde kimlik korunacak.
- Sorular gerçek isim, konum veya kişisel bilgi istemeyecek; cinsel, saldırgan, hassas ya da tetikleyici olmayacak; global ve kültürden bağımsız olacak.
- Mobilde ideal olarak üç satırı aşmayacak.
- Seçilen soru `match_offer` geldiğinde kaybolmayacak. QA-003 ekranında Sohbet başlangıcın hazır biçiminde ikincil gösterilebilir.
- Chat composerda Göndermek için dokun önerisi olabilir; kullanıcı onayı olmadan otomatik gönderilmeyecek.
- Peer reject/offer kapanmasıyla aynı arama sürüyorsa seçim korunacak. Tam kapatma ve yeni oturumda temizleme/koruma kuralı açıkça tanımlanacak.

#### 7. Görsel hiyerarşi

Nihai sıralama:

1. Canlı iki parçacık animasyonu.
2. Eşleşme aranıyor, gerçek durum alt metni ve küçük sayaç.
3. Sohbete nasıl başlamak istersin? kategori chipleri.
4. Kompakt başlangıç kartı ve Başka soru.
5. kincil Aramayı durdur aksiyonu.

Görsel kurallar:

- Animasyon ana görsel olacak; durum metni kısa ve net kalacak.
- Kategori ve soru kartı ana durumun önüne geçmeyecek.
- PTAL ET yerine Aramayı durdur kullanılacak.
- Durdurma aksiyonu görünür fakat baskın olmayan soft danger/outline ve en az 44 px olacak.
- Koyu zemin ve cyanmor neon kimlik korunacak; glow, kalın çerçeve ve iç içe kartlar azaltılacak.
- 320 px genişlik, kısa ekran, safe-area ve Android WebView dâhil `100dvh` içinde kaydırmasız çalışacak.
- Kısa ekranda önce animasyon küçülecek; metin veya ana aksiyon kesilmeyecek.
- Masaüstünde kontrollü maksimum genişlik kullanılacak.

#### 8. Eşleşme bulundu geçişi ve QA-003

Gerçek `match_offer` geldiğinde:

- Sayaç duracak.
- Kategori ve `promptId` korunacak.
- Parçacıklar merkeze yaklaşacak ve cyanpembe dalga oluşacak.
- Yaklaşık 300600 ms sonra QA-003 kartı açılacak. Geçiş sunucunun `autoAcceptAt` süresini geciktirmeyecek veya countdown ile çelişmeyecek.
- Hazır başlangıç, kabul ekranında kimlik, sayaç ve ana CTAdan daha baskın olmayacak.
- Peer reject/leave/offer timeout sonrası temiz biçimde yeniden `queued` durumuna dönülecek; eski countdown veya offer verisi kalmayacak.
- Sohbet başladığında prompt yalnızca kullanıcıya ait gönderilebilir öneri olarak Chat ekranına aktarılacak.

#### 9. çerik ve yerelleştirme modeli

- `match.q1``match.q5` yerine kararlı `promptId`, kategori ve locale alanlı ölçeklenebilir model kurulacak.
- Her durum ve soru TR/EN karşılığıyla aynı sürümde teslim edilecek.
- Eksik çeviride aynı ekranda karışık Türkçe/ngilizce gösterilmeyecek; güvenli fallback ve eksik içerik kontrolü olacak.
- Teknik WebSocket/kuyruk terimleri kullanıcıya gösterilmeyecek.

#### 10. Ölçümleme ve Jarvis özeti

Anlamlı eventler:

- `match_search_started`
- `match_queue_confirmed`
- `match_status_tier_seen`
- `match_mood_selected`
- `match_prompt_changed`
- `match_search_cancelled`
- `match_reconnect_started` / `match_reconnect_result`
- `match_offer_received`

Kurallar:

- Tam soru yerine `promptId` ve kategori kaydedilecek.
- Mood eşleştirmeyi etkilemediği için panel/telemetry içinde `preference_match` gibi yanıltıcı ad kullanılmayacak.
- Eventler QA-012 davranış analitiğinde ham yığın yerine karar vermeye yarayan temiz özetlere dönüşebilecek.

#### Kabul kriterleri

- [ ] Anahtar/radar kaldırılmış ve iki anonim TalkX parçacığı uygulanmış.
- [ ] Animasyon gerçek tekliften önce birleşmiyor; yalnız `match_offer` ile final hareketi yapıyor.
- [ ] Reduced motion ve düşük güçlü WebView destekleniyor.
- [ ] `preparing`, `queued`, uzun bekleme, `reconnecting`, `offline`, `cancelled`, `offer` ayrışıyor.
- [ ] Sayaç yalnız `queued` onayında başlıyor; cancel/reconnect/offer davranışı sunucuyla uyumlu.
- [ ] Metinler gerçek state ve merkezi süre eşiklerine göre değişiyor; karşılığı olmayan vaat yok.
- [ ] Sahte progress, yüzde veya tahmini kalan süre yok.
- [ ] Mood ilk sürümde havuzu bölmüyor ve eşleştirme tercihi gibi anlatılmıyor.
- [ ] Soru otomatik dönmüyor; Başka soru ile değişiyor ve yakın tekrar engelleniyor.
- [ ] Her kategoride 810 güvenli ve kaliteli TR/EN prompt ile kararlı `promptId` var.
- [ ] Mood/prompt teklif, QA-003 ve Chat önerisi boyunca korunuyor; otomatik mesaj yok.
- [ ] Aramayı durdur kullanılıyor ve çift `leaveQueue` engelleniyor.
- [ ] Eski aramadan geciken socket olayları yeni oturumu bozamıyor.
- [ ] Ekran 320 px, kısa telefon ve safe-area ile Web/Androidde `100dvh` içinde kaydırmasız.
- [ ] Anlamlı durumlar erişilebilir duyuruluyor; sayaç her saniye okunmuyor; aksiyonlar klavye/dokunma ile çalışıyor.
- [ ] Arama  teklif  kabul/ret  sohbet veya yeniden arama uçtan uca test edilmiş.
- [ ] Kuyruğu koruyan ve yeniden başlatan reconnect ayrı test edilmiş; metinler gerçek davranışla çelişmiyor.

#### Manuel test matrisi

- Web ve Android WebViewde normal kuyruk onayı ve 08 / 820 / 2045 / 45+ saniye geçişleri.
- Geciken `joinQueue` cevabı: sayaç başlamadan Arama hazırlanıyor.
- Kısa kopma: gerçek reconnect ve korunan kuyruk.
- Korunmayan kuyruk: Arama yeniden başlatıldı ve yeni sayaç.
- Kalıcı offline: Tekrar dene ve Aramayı kapat.
- Hızlı art arda durdurma: tek `leaveQueue`.
- Eski arama eventinin yeni aramaya gecikmesi: event yok sayılır.
- Mood, prompt yenileme, tekrar engeli ve TR/EN değişimi.
- `match_offer`, peer reject, timeout, auto accept ve başarılı sohbette seçim korunması.
- Reduced motion, 320 px, kısa telefon, safe-area, klavye ve ekran okuyucu.

#### lgili kod alanları

- `chatapp-frontend/src/screens/MatchScreen.jsx`
- `chatapp-frontend/src/App.jsx`
- `chatapp-frontend/src/i18n.jsx`
- `chatapp-frontend/src/screens/ChatScreen.jsx`
- `chatapp-backend/index.js` içindeki `joinQueue`, `queued`, `leaveQueue`, `match_offer` ve reconnect akışları

#### Görsel kanıt

- Mevcut durum: `docs/assets/manual-qa/qa-014-current-anon-match-search.png`
- Hedef görsel ayrıca çizilse bile bu brief davranış, dürüst state ve içerik kurallarında ana otoritedir.


### QA-015 — TalkX Sistem sohbeti ve hedefli kalıcı sistem mesajları

**Durum:** Açık  
**Öncelik:** P1  
**Tarih:** 2026-09-02  
**Alan:** Kullanıcı uygulaması / Arkadaşlar / Admin panel / Backend / WebSocket / Push / Veritabanı / TR-EN / Web-Android  
**Bağlantılı kayıt:** QA-010 çok dilli push dağıtımını kapsar. QA-015, push'u tek otorite olmaktan çıkarıp uygulama içinde kalıcı ve güvenilir TalkX Sistem sohbeti kurar.

#### Amaç ve ürün kararı

Panel; tek kullanıcıya, seçili kişilere, ülke/dil/platform segmentine veya herkese doğrudan mesaj gönderebilmelidir. Kullanıcı bunu geçici toast değil, Arkadaşlar ekranında doğrulanmış **TalkX Sistem** göndericisinden gelen kalıcı sohbet olarak görmelidir.

Doğru model:

1. Mesaj ve hedef snapshot'ı önce veritabanında kalıcı oluşturulur.
2. Online kullanıcıya WebSocket ile anında teslim edilir.
3. Push, kalıcı mesajın dikkat çekme katmanı olur.
4. Push başarısız olsa bile mesaj kaybolmaz; sonraki uygulama açılışında görülür.
5. Teslim, okunma ve hata ham log değil Jarvis özeti olarak panele döner.

Ana otorite push değil, veritabanındaki kalıcı sistem mesajıdır.

#### 1. Arkadaşlar ekranındaki TalkX Sistem

    ✓ TalkX Sistem
    Yeni bir mesajın var
    2 dk önce                         1

- TalkX logosu, TalkX Sistem adı ve doğrulanmış rozet kullanılır.
- Sahte normal kullanıcı, UUID, profil veya friendship oluşturulmaz.
- Engellenemez, arkadaşlıktan çıkarılamaz ve normal profil detayı açılmaz.
- İlk gerçek sistem mesajıyla görünür. Baştan görünmesi istenirse boş satır yerine gerçek hoş geldin mesajı oluşturulur.
- Unread rozeti, son mesaj önizlemesi ve zaman diğer sohbetlerle tutarlı çalışır; yeni mesajda görünür üst bölümde yer alır.
- Geçmiş kronolojik, kalıcı ve hesap bazlıdır; yeniden kurulumda ve başka cihazda yüklenir.
- Sistem kimliği normal arkadaş sohbetinden güvenilir biçimde ayrışır.

#### 2. Tek yönlü ilk sürüm

- Composer gizlenir veya “Bu kanal TalkX bilgilendirmeleri içindir.” bilgisine dönüşür.
- Kullanıcı cevapsız bir adrese mesaj gönderemez.
- Destek, uygulama raporu ve moderasyon iletişimi ayrı kalır.
- Gelecekte yanıt istenirse sahiplik ve destek kuyruğu olan ayrı “Destek ile konuş” ürünü tasarlanır.

#### 3. Panel hedefleme

Yeni sade **Sistem Mesajları** ekranı şu hedefleri destekler:

- **Tek kişi:** kullanıcı adı, görünen ad veya UUID ile arama; Profil Detayı içinden hedef önceden seçili açılabilir.
- **Seçili kişiler:** Profiller tablosu çoklu seçimi ve “Seçilenlere sistem mesajı gönder”.
- **Grup/segment:** ülke/bölge, uygulama dili, Web/Android, son aktiflik ve kayıt tarihi.
- **Herkes:** tüm uygun aktif hesaplar; büyük hedefte ek onay.

Hedef özeti kullanıcı kimliği/dili/ülkesi/cihaz durumunu veya seçili-geçersiz-kapsam dışı sayıları gösterir.

Coğrafi dürüstlük:

- IP/kayıt verisi “anlık konum” diye sunulmaz.
- “Kayıt ülkesi”, “Son bilinen ülke” veya “IP'den tahmin edilen ülke” kaynağı açık yazılır.
- Belirsiz kayıtlar ayrı sayılır; yanlış segmente sessizce eklenmez.
- Hassas/kesin konum hedeflemesi yapılmaz.

#### 4. Sade gönderim akışı

    Yeni sistem mesajı

    Hedef
    Türkiye · Türkçe kullananlar
    Tahmini alıcı: 184 kişi

    İçerik türü
    [ Bilgilendirme ▼ ]

    Türkçe
    Başlık: ...
    Mesaj: ...

    English
    Title: ...
    Message: ...

    [ Kendime test gönder ]   [ Önizle ]
                              [ Gönder ]

- Hedef ve içerik uzun forma dönüşmez; progressive disclosure/adımlı yapı kullanılabilir.
- Başlık/metin karakter sınırı, kalan karakter ve alan doğrulaması bulunur.
- Boş, aşırı uzun, eksik dil veya desteklenmeyen link engellenir.
- Önizleme Arkadaşlar satırı, sohbet balonu ve push'u Web/Android için gösterir.
- Kendime test gerçek hedefi oluşturmadan yetkili admin test hesabına aynı davranışı yollar.
- Son gönderim hedef sayısı ve içerik özetli açık onay ister.

#### 5. TR/EN yerelleştirme

- Türkçe ve English başlık/metin aynı kampanyada zorunlu tutulur.
- Kullanıcı profil locale'ine göre doğru varyantı alır.
- Null/geçersiz/desteklenmeyen locale tanımlı English fallback kullanır.
- Aynı ekranda karışık dil gösterilmez; doğal karşılıklar kullanılır.
- Panel dil bazında alıcı ve fallback sayısını önceden gösterir.
- İlk güvenli sürümde tek kişilik mesajda da iki dil korunur.
- QA-010 ile aynı locale/fallback kaynağı kullanılır; ikinci dil sistemi kurulmaz.

#### 6. Tek sistem mesajı davranışı

- İlk sürümde pazarlama, operasyon, kritik veya benzeri ayrı bildirim sınıfları ve kullanıcı tercih kanalları oluşturulmaz.
- Panelden gönderilen içerik kullanıcıya doğrulanmış TalkX Sistem mesajı olarak gelir.
- Sistem mesajının push'u normal arkadaş mesajı bildirimiyle aynı genel izin davranışını kullanır.
- Kullanıcı cihaz veya uygulama düzeyinde push iznini kapatmışsa push gösterilmez; kalıcı mesaj TalkX Sistem sohbetinde yine bulunur ve unread olarak görünür.
- Ayrı pazarlama/operasyon susturma ayarı, kategori bazlı notification channel veya yeni bir Bildirim Tercih Merkezi ilk sürüm kapsamında değildir.
- Paneldeki iç etiketler yalnız yönetim ve raporlama amacı taşıyabilir; teslimat önceliğini veya kullanıcı tercihlerini sessizce değiştirmez.
- Teknik campaign/event kodları kullanıcıya gösterilmez.

#### 7. Güvenli CTA

Mesaj isteğe bağlı tek uygulama içi aksiyon taşıyabilir: Profili aç, Güncellemeyi gör, Kuralları incele veya izinli sayfa.

- Yalnız allowlist route/action kimlikleri kullanılabilir.
- Serbest dış URL, HTML, script ve rastgele deep-link yoktur.
- CTA etiketi TR/EN tutulur.
- Hedef eski sürümde yoksa mesaj kalır, CTA güvenle gizlenir.
- Tıklama ölçülebilir; hassas içerik loglanmaz.

#### 8. Gönderim öncesi güvenlik

    Toplam hedef:                    184
    TR içerik kullanacak:           131
    EN içerik kullanacak:            53
    Aktif push cihazı bulunan:      142
    Yalnız uygulama içinde alacak:   42
    Belirsiz/uygun olmayan:           0

- Sayılar gerçek hedef sorgusundan gelir; gönderimde kesin recipient snapshot'ı tutulur.
- Büyük toplu gönderim yeniden doğrulama/ikinci onay ister; toplu yetki normal moderasyondan ayrılabilir.
- Çift tıklama iki kampanya üretmez; idempotency key zorunludur.
- Batch/queue ve rate limit backend/Firebase yükünü kontrol eder.
- İptal yalnız kuyruğa alınmamış alıcılara uygulanır; teslim edilmiş mesaj geri alınmış sayılmaz.
- Gönderim sonrası içerik sessizce değiştirilmez; düzeltme yeni mesaj/açık sürüm kaydıdır.

#### 9. Teslimat

**Kalıcı kayıt:** Campaign ve recipient kayıtları transaction ile önce oluşturulur; Sistem sohbeti bunları ana kaynak okur.

**WebSocket:** Online kullanıcıya kararlı mesaj kimliği, çözülmüş locale ve izinli CTA taşıyan versiyonlu system_message eventi gider. Reconnect/tekrar event duplicate üretmez.

**Push:** Kullanıcı offline veya Sistem sohbeti açık değilse dikkat katmanı olarak gider. Mesaj kimliğiyle Sistem sohbetini açar; tam geçmiş yerine geçmez. Push hatası kalıcı mesajı bozmaz. Geçersiz token temizlenir. Çoklu cihaz push'u duplicate sohbet kaydı üretmez. Sistem sohbeti açıkken gereksiz local push/toast gösterilmez.

#### 10. Unread ve okunma

- Sistem satırı unread sayısını gösterir.
- Read receipt tanımlı görünme anında gönderilir; yalnız route açmak tüm geçmişi körlemesine okundu yapmaz.
- Read idempotent ve hesap bazlı çoklu cihaz senkronudur.
- Mesaj geçmişinin retention ve kullanıcı tarafında görünürlük davranışı açık tanımlanır; ayrı kategori susturma sistemi kurulmaz.
- “Okundu” yalnız görüntülenme sinyalidir; içerik anlaşıldı anlamına gelmez.

#### 11. Veri modeli — sahte kullanıcı yok

**system_message_campaigns**

- Kararlı id/idempotency
- TR/EN başlık-metin
- İzinli CTA ve içerik sürümü
- Hedef türü, filtre özeti ve snapshot
- draft, validating, queued, sending, completed, partial_failed, cancelled durumları
- oluşturan/gönderen admin, zamanlar, içerik hash'i ve audit

**system_message_recipients**

- campaign_id + user_id unique
- çözülmüş locale
- uygulama içi oluşturma, WebSocket teslim, push sonucu, okunma ve CTA zamanları
- kullanıcıya ait okunma ve teslim durumu

Tek kişi bir recipient'lı kampanyadır; seçili kişiler ve herkes aynı motoru kullanır. Ortak içerik campaign'de, kullanıcı teslim/okunması recipient'ta tutulur. Gerçek kişiye özel farklı içerik tek alıcılı ayrı campaign olur. Silme, retention ve anonimleştirme veri yaşam döngüsüne eklenir.

#### 12. API ve event sözleşmesi

- Admin hedef önizleme, kendime test, draft/doğrulama/gönderme ve sonuç özeti.
- Kullanıcı Sistem geçmişi için cursor pagination, unread sayı ve read receipt.
- İzinli CTA çözümleme.
- WebSocket system_message ve gerekirse system_message_read_sync.
- Admin endpointlerinde rol/yetki, CSRF yaklaşımı, rate limit ve audit.
- Kullanıcı yalnız kendi recipient kayıtlarını okur.
- API/event aynı kararlı kimliği kullanır.
- İstemci push payload'ını kalıcı geçmişe yazmaz; geçmiş API/DB'den doğrulanır.

#### 13. Gönderim sonrası Jarvis özeti

    Türkiye bakım bilgilendirmesi

    Hedeflenen                 184
    Uygulama içinde mevcut     184
    Canlı teslim                37
    Push başarılı              139
    Push başarısız               8
    Okundu                      91

- Push hatası açıldığında süzülmüş hata sınıfları/etkileri görünür.
- Push başarısız “mesaj ulaşmadı” değildir; kalıcı uygulama içi durum ayrı gösterilir.
- TR/EN ve fallback görünür.
- Partial failure, devam eden queue, gecikmeli veri ve tamamlandı ayrışır.
- Recipient detayı yetkili kişiye açılabilir; varsayılan ekranda UUID/token/Firebase hata yığını yoktur.
- Özet ham kanıta geri izlenebilir.

#### 14. Audit ve kötüye kullanım önleme

- Kim, ne zaman, hangi hedefe, kaç kişiye, hangi içerik hash'iyle gönderdi audit edilir.
- Tek kişilik mesajın da içerik/hedef değişikliği kayda girer.
- Güvenli düz metin/sınırlı renderer ile XSS engellenir.
- Hedef filtreleri parametreli ve allowlist tabanlıdır.
- Retry/worker restart recipient duplicate üretmez.
- Batch hata oranına göre backoff/durdurma uygular.
- Test mesajı gerçek metriğe karışmaz veya test etiketlidir.
- Hassas hedef listeleri gereksiz loglanmaz.

#### 15. İlk sürüm sınırı

**Dâhil:** doğrulanmış Sistem sohbeti, tek yönlü kalıcı geçmiş, tek/seçili/ülke/dil/herkes hedefi, Web/Android ve temel aktiflik/tarih filtresi, TR/EN fallback, tek güvenli CTA, unread/read sync, normal bildirim izniyle WebSocket+push, test/önizleme/onay, temiz sonuç özeti, yetki/audit/idempotency/batch.

**Dâhil değil:** serbest dış link/zengin HTML, Sistem hesabına cevap, ayrı pazarlama/operasyon bildirim sınıfları, kategori bazlı susturma veya Bildirim Tercih Merkezi, otomatik karmaşık kampanyalar, şablon/A-B testi, çok aşamalı otomasyon ve gelişmiş zamanlama.

#### Kabul kriterleri

- [ ] Sahte user/friendship olmadan doğrulanmış TalkX Sistem kaydı var.
- [ ] Kalıcı geçmiş, unread, pagination ve çoklu cihaz read senkronu çalışıyor.
- [ ] İlk sürüm tek yönlü; composer yerine kanal açıklaması gösteriyor.
- [ ] Tek kişi, seçili kişiler, ülke, dil, platform, tarih/aktiflik ve herkes hedefleri var.
- [ ] Coğrafi kaynak dürüst etiketli; belirsizler ayrı.
- [ ] TR/EN ve English fallback doğru locale'e gidiyor.
- [ ] Hedef/dil/push/uygulama içi/belirsiz sayıları gönderimden önce görünüyor.
- [ ] Kendime test, Web/Android önizleme ve son onay çalışıyor.
- [ ] Campaign/recipient gönderimden önce güvenli oluşturuluyor.
- [ ] Online anında, offline sonraki açılışta aynı kalıcı mesajı görüyor.
- [ ] Push hatasında mesaj kaybolmuyor ve doğru raporlanıyor.
- [ ] Reconnect, retry, çift tıklama ve worker restart duplicate üretmiyor.
- [ ] CTA yalnız izinli uygulama içi hedef açıyor.
- [ ] Sistem engellenemiyor, arkadaşlıktan çıkarılamıyor ve profil gibi açılmıyor.
- [ ] Yetki, audit, rate limit, batch/backoff ve hassas veri maskelemesi var.
- [ ] Sonuç özeti hedef, kalıcı kayıt, canlı teslim, push, locale/fallback ve okunmayı ayırıyor.
- [ ] Silme ve retention tanımlı; Sistem mesajı ayrı pazarlama/operasyon tercihi olmadan normal mesaj bildirimi davranışını kullanıyor ve push kapalıyken kalıcı sohbette korunuyor.
- [ ] Web/Android tek, çoklu, segment, herkes, offline, çoklu cihaz, reconnect ve push hatası E2E test edilmiş.

#### Manuel test matrisi

- Profil Detayı ve Sistem Mesajları sayfasından tek kullanıcı.
- Profiller çoklu seçimi.
- Ülke+dil, platform, aktiflik, kayıt tarihi hedef snapshot doğruluğu.
- Belirsiz/IP tahmini ülke etiketi.
- TR, EN, null/geçersiz locale ve fallback.
- Online/offline, Sistem sohbeti açık/farklı sohbet açık teslimat.
- Tokenı olmayan, geçersiz tokenlı ve çoklu cihazlı kullanıcı.
- Retry, reconnect, çift tıklama ve worker restart duplicate kontrolü.
- Unread, görünme/read receipt ve diğer cihaz senkronu.
- Test gönderiminin gerçek hedef/metriğe karışmaması.
- Desteklenen/desteklenmeyen CTA ve eski sürüm.
- Yetkisiz admin, büyük gönderim onayı, rate limit ve audit.
- Engelleme, silme, profil açma veya mesaj yazma girişimleri.
- Push hatasında yeniden açılışta kalıcı mesaj.
- Dar ekran, ekran okuyucu, klavye, uzun metin ve karakter sınırı.

#### İlgili alanlar

- chatapp-frontend/src/screens/FriendsScreen.jsx
- chatapp-frontend/src/screens/ChatScreen.jsx
- chatapp-frontend/src/App.jsx
- chatapp-frontend/src/api.js
- chatapp-backend/admin.html
- chatapp-backend/admin.js
- chatapp-backend/index.js
- chatapp-backend/db.js
- chatapp-backend/utils/push.js
- messages, conversations, push_devices ve push_delivery_logs referanstır; Sistem mesajları friendship zorunluluğuna bağlanmaz.

#### Net ürün özeti

Bu özellik “panelden push atmak” değildir. TalkX'in kullanıcıyla kalıcı, çok dilli, güvenilir ve ölçülebilir iletişim kurduğu **Sistem sohbetidir**. Push yalnız dikkat çekme kanalıdır.


### QA-016 — Web ve Android istemci Release Health / crash görünürlüğü

**Durum:** Açık  
**Öncelik:** P1  
**Tarih:** 2026-09-02  
**Alan:** Web frontend / Capacitor Android / Admin panel / Operasyon / Telemetry / Gizlilik / Release yönetimi  
**Bağlantılı kayıtlar:** Frontend gerçek release sürümü, QA-004 Dashboard, QA-011 Performans ve release smoke checklist maddeleri. QA-016 sunucu performansından farklı olarak kullanıcının cihazında bozulan deneyimi ölçer.

#### Amaç

TalkX yöneticisi binlerce ham stack trace içinde hata aramayacak. Sistem istemci hatalarını güvenli biçimde toplayacak, aynı kök nedene ait olayları gruplayacak, sürüm ve ekran bazında etkiyi hesaplayacak ve şu tip temiz sonuçlar sunacak:

> Android 1.4.2 sürümünde MatchScreen açılış hatası arttı · 12 kullanıcı / 18 oturum etkilendi · önceki sürüme göre +%240.

Release Health şu soruları ilk bakışta cevaplamalıdır:

1. Aktif Web ve Android sürümleri sağlıklı mı?
2. Yeni sürümden sonra hangi hata veya akış kötüleşti?
3. Kaç tekil kullanıcı ve oturum etkilendi?
4. Sorun hangi ekran, platform, OS ve sürümde yoğunlaşıyor?
5. Bu yeni hata mı, eski hatanın regresyonu mu, yoksa düşük örnekli belirsiz sinyal mi?
6. Yönetici şimdi ne yapmalı ve iddiayı doğrulayan maskelenmiş kanıt nerede?

#### 1. Ürün sınırı ve sağlayıcı kararı

Bu brief belirli bir servisi zorunlu kılmaz. Uygulamadan önce iki yol karşılaştırılır:

- **Yönetilen sağlayıcı:** Sentry, Firebase Crashlytics veya eşdeğer bir servis; hızlı sembolleştirme/source map, native crash ve alert avantajına karşı gizlilik, maliyet, veri bölgesi ve vendor bağımlılığı değerlendirilir.
- **TalkX içinde toplama:** Daha fazla kontrol sağlar fakat native crash yakalama, source map, ingestion güvenliği, ölçek, grouping ve alert bakımını bizim üstlenmemizi gerektirir.

Hangi yol seçilirse seçilsin kullanıcıya ve admin paneline sunulan veri modeli, gizlilik sınırı, Jarvis özeti ve kabul kriterleri aynı kalır. Aynı olayı hem sağlayıcıya hem TalkX backend'ine kontrolsüz çift gönderen iki ayrı otorite kurulmaz.

#### 2. Toplanacak istemci sinyalleri

**Web ve ortak React/Capacitor katmanı**

- React ErrorBoundary tarafından yakalanan render hataları
- window error
- unhandled promise rejection
- Uygulamanın açılmasını engelleyen chunk/dinamik import yükleme hataları
- Kritik başlangıç/config yükleme hataları
- Tekrarlayan ve kullanıcı akışını bitiren WebSocket yeniden bağlantı başarısızlığı
- Kritik API akışının kontrollü hata kodu; her 4xx veya normal kullanıcı doğrulama hatası crash sayılmaz
- Uygulama içindeki kontrollü “beklenmeyen hata” recovery ekranları

**Android native katmanı**

- Fatal native crash
- Uygulama açılışında crash/başlatılamama
- Java/Kotlin veya plugin kaynaklı uncaught exception
- Destekleniyorsa ANR/uygulama yanıt vermiyor sinyali
- Önceki çalıştırmada oluşan crash'in sonraki güvenli açılışta teslimi

Normal ağ kesintisi, kullanıcı iptali, yanlış şifre, eşleşme bulunamaması veya beklenen API validation sonucu crash olarak sayılmaz. Bunlar kendi ürün/operasyon eventlerinde kalır.

#### 3. Güvenli event zarfı

Her olayda yalnız tanımlı alanlar bulunur:

- Kararlı event_id ve occurrence_at
- release_version, build_number ve deploy/commit kimliği
- platform: web veya android
- runtime: browser/WebView/native ve uygulama ortamı
- screen/route/flow adı
- hata adı, kontrollü error_code ve maskelenmiş kısa mesaj
- fingerprint/grouping anahtarı
- maskelenmiş stack; source map çözümü sunucu/sağlayıcı tarafında
- anonim/pseudonymous session ve user etki kimliği
- cihaz ailesi, OS major, browser/WebView major
- app foreground/background ve temel network durumu
- izinli son teknik adımlardan oluşan kısa breadcrumb
- severity ve handled/unhandled bilgisi

Fingerprint yalnız hata metnine dayanmaz; hata tipi, normalize stack frame'leri, ekran ve kontrollü error code birlikte kullanılır. Dinamik UUID, zaman, kullanıcı adı gibi parçalar grouping öncesinde normalize edilir.

#### 4. Kesin gizlilik sınırı

Aşağıdakiler crash eventine asla eklenmez:

- Anonim veya arkadaş sohbeti mesaj metni
- Fotoğraf/medya içeriği
- Şifre, session/JWT tokenı, Authorization header
- Push tokenı
- Tam IP
- Kullanıcı adı veya görünen ad
- Destek/rapor açıklaması
- Input, textarea veya serbest form değerleri
- Tam URL query/hash içinde kimlik veya hassas parametre
- API request/response body'nin kontrolsüz kopyası

Breadcrumb allowlist tabanlıdır: örneğin “MatchScreen açıldı”, “joinQueue isteği başladı”, “queued alındı”. Kullanıcının yazdığı içerik veya karşı taraf kimliği breadcrumb'a girmez.

PII redaksiyonu istemcide başlar, ingestion katmanında ikinci kez uygulanır. Redaksiyondan geçmeyen olay reddedilir veya hassas alanı silinerek açık güven işaretiyle kaydedilir.

#### 5. Release kimliği ön koşulu

Release Health, gerçek sürüm olmadan güvenilir çalışamaz:

- Frontend 0.0.0 kullanamaz; Web deploy sürümü/commit SHA üretim build'ine gömülür.
- Android versionName ve versionCode aynı release kaydıyla bağlanır.
- Source map veya native symbol dosyası tam release kimliğiyle eşleşir.
- Staging, production ve local eventleri kesin ayrılır.
- Release başlaması/deploy zamanı kaydedilir; önceki sürüm kıyası doğru pencere kullanır.
- Source map herkese açık servis edilmez; yetkili hata çözümleme katmanında tutulur.

#### 6. Dayanıklı ve gürültüsüz toplama

- Event gönderimi uygulamanın ana akışını bloke etmez.
- Offline olaylar sınırlı, şifreli/uygun yerel kuyrukta tutulur ve sonraki bağlantıda gönderilir.
- Kuyrukta maksimum olay/adet/boyut ve süre sınırı vardır.
- event_id ile retry, reconnect ve yeniden açılış duplicate oluşturmaz.
- Aynı saniyede oluşan sonsuz hata döngüsü istemci throttling ve circuit breaker ile kesilir.
- Backend/sağlayıcı ingestion kullanıcı, cihaz, origin ve proje bazında rate limit uygular.
- Yüksek hacimli handled hata için sampling yapılabilir; fatal crash ve yeni kritik hata mümkün olduğunca korunur.
- Sampling oranı metrikte saklanır; panel örneklenmiş sayıyı kesin gerçek sayı gibi sunmaz.
- İstemci saati bozuksa server_received_at korunur ve saat sapması işaretlenir.
- Telemetry gönderimi başarısız olduğu için yeni telemetry hatası döngüsü üretilmez.

#### 7. Gruplama ve etki hesabı

Her issue grubu için:

- Toplam occurrence
- Etkilenen tekil pseudonymous kullanıcı
- Etkilenen session
- İlk ve son görülme
- Etkilenen release/build
- Platform, OS, browser/WebView dağılımı
- Ana ekran/akış
- Handled/unhandled ve fatal oranı
- Crash-free session oranına etkisi
- Önceki release ve önceki eş zamanlı pencereye göre fark
- Yeterli örnek/guven durumu
- Yeni, tekrar eden, regresyon veya çözüldü sinyali

Aynı hatayı yanlış gruplama veya iki farklı hatayı birleştirme ihtimali vardır. Admin detayında issue'yu ayırma/birleştirme imkânı veya en azından grouping override kaydı ve audit bulunmalıdır. Ham olaylar kaybolmaz; özet geri izlenebilir olur.

#### 8. Release sağlık durumları

Deterministik ve görünür eşiklerle:

- **Sağlıklı:** anlamlı yeni regresyon yok, crash-free oran hedef içinde.
- **İzleniyor:** düşük örnekli yeni hata veya küçük artış.
- **Bozuldu:** yeterli örnekle anlamlı artış ya da çekirdek akış etkisi.
- **Kritik:** yüksek etki, fatal crash, açılış/giriş/eşleşme/sohbet gibi çekirdek akışın kullanılamaması.
- **Veri yok:** release kimliği yok, telemetry gelmiyor veya örnek yetersiz.

Eşikler gizli sihirli karar değildir. Minimum session/kullanıcı, artış oranı, crash-free hedefi, severity ve çekirdek ekran ağırlığı config olarak belgelenir. Düşük örnek kırmızı alarm üretmez; “İzleniyor · yalnız 2 oturum” denir.

#### 9. Admin Release Health ekranı

**Üst özet**

- Aktif Web release
- Aktif Android release/build
- Son 24 saat crash-free session
- Yeni issue sayısı
- Regresyon sayısı
- Etkilenen tekil kullanıcı
- Telemetry son veri zamanı ve güven durumu

Örnek:

    Android 1.4.2                         BOZULDU
    Crash-free session: %96,8            önceki: %99,4
    2 yeni regresyon · 12 kullanıcı
    Ana etki: MatchScreen açılışı

**Öncelikli sorunlar**

Ham tarih tablosu yerine etkiye göre kart/satır:

    MatchScreen açılış hatası
    12 kullanıcı · 18 oturum · 46 olay
    Android 1.4.2 · +%240 · ilk kez bu release
    Son görülme: 4 dk önce
    [İncele]

**Release karşılaştırması**

- Bu release ve önceki release
- Crash-free session
- Etkilenen kullanıcı oranı
- Yeni/regresyon/çözülen issue
- En çok bozulan ekranlar
- Yeterli ortak trafik yoksa “karşılaştırma için veri yetersiz”

Dashboard'da yalnız tek kısa Release Health kartı bulunur; araştırma Release Health detayına gider. Performans ekranındaki API gecikmesiyle istemci crash'i aynı metrik gibi karıştırılmaz.

#### 10. Issue detayında progressive disclosure

İlk görünüm:

- Olgusal sorun başlığı
- Durum/severity/güven
- Etki: kullanıcı, session, occurrence
- İlk/son görülme
- Release, platform ve ekran
- Önceki release farkı
- Olası son release korelasyonu; nedensellik kanıtlanmadıysa “release sonrası arttı” denir, “bu deploy bozdu” denmez
- Önerilen aksiyon: incele, sahip ata, fixed release belirt, izlemeye al

Açılır kanıt:

- Maskelenmiş ve source-map çözülmüş stack
- Error code/name
- Cihaz/OS/WebView dağılımı
- İçeriksiz allowlist breadcrumb
- Örnek event zamanları
- Event/sample oranı
- Release/deploy bağlantısı
- PII redaksiyon durumu

Varsayılan ekranda binlerce event, tam kullanıcı kimliği, ham cihaz fingerprint'i veya çözümsüz minified stack yoktur.

#### 11. Issue yaşam döngüsü

Durumlar:

- Yeni
- İnceleniyor
- Düzeltildi
- İzleniyor
- Bilinen/kabul edildi
- Yanlış gruplama
- Regresyon
- Çözüldü

Bir issue “Düzeltildi” denince fixed release/build belirtilir. Yeni release sonrası aynı fingerprint eşik üstünde dönerse otomatik “Regresyon” önerisi oluşur. Durum, sahip, not ve grouping değişiklikleri audit edilir. Otomatik çözülme belirli süre/traffic sonrasında olur; yalnız olay gelmemesi telemetry kesintisiyse çözülmüş sayılmaz.

#### 12. Alarm üretimi

Her event alarm üretmez. Alarm adayları:

- Yeni release'te yeterli örnekle crash-free session düşüşü
- Yeni fatal crash grubu
- Çekirdek ekranda anlamlı etkilenen kullanıcı artışı
- Önceden düzeltilmiş issue regresyonu
- Telemetry'nin tamamen kesilmesi
- Uygulama açılış crash'i veya ANR artışı

Alarm cooldown/dedupe kullanır. Aynı issue için tekrar tekrar bildirim atılmaz; etki seviyesi belirgin değişirse güncellenir. Alarm; durum, etki, release ve inceleme bağlantısı taşır, ham stack dökmez.

#### 13. Kullanıcıya gösterilecek recovery

Kullanıcı teknik stack veya “undefined is not a function” görmez.

- Ekran seviyesinde kurtarılabiliyorsa yalnız o yüzey güvenli fallback gösterir.
- Uygulama seviyesinde ErrorBoundary temiz bir “Bir şeyler ters gitti” ekranı sunar.
- Aksiyonlar bağlama göre Yeniden dene, Ana sayfaya dön veya uygulamayı yeniden aç olur.
- Kopyalanabilir kısa destek referansı üretilebilir; kullanıcı kimliği veya hata detayı içermez.
- Aynı recovery sonsuz reload döngüsü yaratmaz.
- Kritik state kaybı veya mesajın gönderilip gönderilmediği bilinmiyorsa dürüstçe belirtilir; otomatik tekrar duplicate mesaj üretmez.

#### 14. Veri yaşam döngüsü

- Ham client error eventleri kısa ve tanımlı süre tutulur.
- Issue/release rollup'ları daha uzun tutulabilir.
- Pseudonymous user/session kimliği etki sayımı içindir; profil ekranına gizli izleme anahtarı olarak açılmaz.
- Hesap silme ve analytics/telemetry retention matrisiyle uyumlu anonimleştirme/silme uygulanır.
- Source map, symbol ve stack erişimi rol/yetki altında olur.
- Staging test verisi production sağlığına karışmaz.
- Sağlayıcı kullanılırsa veri bölgesi, alt işleyen, DPA/retention, erişim ve maliyet sınırı belgeye girer.

#### 15. Başarı ölçütleri

- Yönetici beş saniyede aktif release'in sağlıklı olup olmadığını görür.
- Yeni release regresyonu tekil event aramadan bulunur.
- Etkilenen kullanıcı/session ve artış oranı ham kanıtla doğrulanır.
- Düşük örnek, veri yok ve telemetry kesintisi gerçek “0 hata” ile karışmaz.
- Hiçbir event sohbet metni, token veya serbest kullanıcı girdisi taşımaz.
- Release/build ve source map eşleşmesiyle stack okunabilir olur.
- Kullanıcı temiz recovery görür ve telemetry ürün akışını bozmaz.

#### Kabul kriterleri

- [ ] Web ErrorBoundary, window error, unhandled rejection ve kritik chunk/acılış hataları kontrollü yakalanıyor.
- [ ] Android native fatal crash ve destekleniyorsa ANR doğru release/build ile ilişkilendiriliyor.
- [ ] Gerçek frontend/Android release kimliği ve production/staging ayrımı var.
- [ ] Event schema allowlist tabanlı; sohbet, token, username, tam IP ve form değeri taşımıyor.
- [ ] Offline queue, retry, event_id dedupe, throttling, sampling ve ingestion rate limit çalışıyor.
- [ ] Source map/symbol dosyaları release ile güvenli eşleşiyor ve açık servis edilmiyor.
- [ ] Issue grouping aynı kök nedeni birleştiriyor; yanlış grouping geri alınabilir/audit edilebilir.
- [ ] Tekil kullanıcı, session, occurrence, first/last seen, ekran, platform ve release etkisi doğru hesaplanıyor.
- [ ] Önceki release karşılaştırması aynı trafik/örnek sınırlarını dikkate alıyor.
- [ ] Sağlıklı/İzleniyor/Bozuldu/Kritik/Veri yok eşikleri görünür ve deterministik.
- [ ] Dashboard kısa özet, Release Health ise etki sıralı sorunlar ve maskeli kanıt sunuyor.
- [ ] Düşük örnek ve telemetry kesintisi “hata yok” gibi görünmüyor.
- [ ] Issue yaşam döngüsü, owner/not, fixed release ve regresyon takibi auditli.
- [ ] Alarm dedupe/cooldown gürültüyü önlüyor.
- [ ] Kullanıcı recovery ekranı teknik detay göstermiyor ve güvenli yeniden deneme sağlıyor.
- [ ] Ham event/rollup retention, hesap silme ve sağlayıcı veri politikası tanımlı.
- [ ] Kontrollü staging Web/Android hataları admin özetine doğru sürüm, ekran ve etkiyle yansıyor.

#### Manuel test matrisi

- React render crash ve ekran ErrorBoundary.
- Global window error ve unhandled rejection.
- Chunk yükleme ve uygulama açılış hatası.
- Beklenen API validation ile gerçek kritik API hatasının ayrılması.
- Tekrarlayan WebSocket kopmasının crash yerine doğru operasyon sinyali olması.
- Android native crash; sonraki açılışta güvenli teslim.
- Offline event, kuyruk sınırı, reconnect ve duplicate event_id.
- Aynı kök hatanın dinamik UUID/zaman içerse bile gruplanması.
- İki farklı hatanın yanlış birleşmemesi ve grouping override.
- 0/az/yeterli örnek, yeni issue, regresyon, çözülen issue ve telemetry kesintisi.
- Web deploy, Android versionName/versionCode ve staging/production ayrımı.
- Source map ile minified stack çözümü ve yetkisiz erişim engeli.
- Mesaj, token, username, IP, form verisi ve URL query redaksiyonu.
- Çok yüksek hata döngüsünde throttling/sampling/circuit breaker.
- Release karşılaştırması, crash-free session ve etkilenen kullanıcı doğruluğu.
- Admin özetinden maskeli kanıta geri izleme.
- Recovery: yeniden dene, ana sayfa, duplicate mesaj üretmeme ve sonsuz reload engeli.

### QA-017 — Global / kendi ülkem anonim eşleşme kapsamı

- **Durum:** Açık
- **Öncelik:** P1
- **Tarih:** 2026-09-12
- **Alan:** Ürün / Frontend / anonim eşleşme / Backend / WebSocket / Veritabanı / TR-EN / Web-Android / Gizlilik
- **Bağlantılı kayıtlar:** QA-014 arama ve bekleme yüzeyinin, QA-003 ise eşleşme teklif/kabul anının ana otoritesidir. QA-017 bu akışı yeni bir ekrana bölmeden eşleşme kapsamı seçimiyle genişletir; QA-014 animasyonunu veya QA-003 aksiyon hiyerarşisini yeniden tanımlamaz.

#### Amaç ve bağlayıcı ürün kararı

TalkX global anonim sohbet kimliğini korur. Varsayılan eşleşme kapsamı `GLOBAL` olur. Kullanıcı isterse sunucunun hesabı için doğruladığı kendi ülkesini kesin kapsam olarak seçebilir.

Temel ürün cümlesi:

> Global varsayılan eşleşme kapsamıdır. Kullanıcı kendi ülkesini kesin filtre olarak seçebilir; düşük bulunabilirlikte Global yalnızca önerilir, hiçbir zaman sessizce uygulanmaz.

Bu karar aşağıdaki sorunları birlikte çözer:

1. Global deneyim TalkX'in ana kimliği ve en geniş kullanılabilir havuzu olarak kalır.
2. Aynı ülke, ortak dil/kültür ve yakın saat dilimi isteyen kullanıcıya anlaşılır bir seçim sunulur.
3. Düşük kullanıcılı ülke havuzları kullanıcıyı sonsuz ve açıklamasız beklemeye kilitlemez.
4. Kullanıcı ülke seçtiği hâlde yabancı bir kullanıcıyla sessizce eşleştirilmez.
5. Yeni seçim QA-014'ün canlı fakat sakin bekleme tasarımına ve QA-003'ün güçlü teklif anına yapıştırılmış ayrı bir özellik gibi görünmez.

#### 1. İlk sürüm sınırı

**Dâhil:**

- `Global`
- Sunucunun kullanıcı için doğruladığı tek gerçek ülke
- İlk kullanımda Global varsayımı
- Kullanıcının açıkça yaptığı son geçerli scope seçimini hatırlama
- Arama başlamadan scope seçimi
- Aktif arama sırasında kontrollü scope değişimi
- Ülke beklemesi uzadığında kullanıcı onaylı Global önerisi
- Global ve ülke için ayrı mantıksal kuyruk
- Aynı scope ile reconnect, peer reject, timeout ve requeue
- TR/EN içerik, Web/Android, accessibility ve telemetry

**Dâhil değil:**

- Manuel olarak başka bir ülke seçme
- Birden fazla ülke seçme
- Dil, yaş, cinsiyet, ilgi alanı veya saat dilimi filtresi
- Country kullanıcılarını sessizce Global kullanıcılarla karıştırma
- Kesinliği doğrulanmamış canlı kullanıcı sayısı gösterme
- GPS veya hassas konum isteme
- QA-003 kartına yeni bayrak, badge, CTA veya ayrı bilgi bloğu ekleme
- Ülke kapsamını ücretli öncelik veya sıralama sinyaline dönüştürme

`My Language`, advanced filtreler ve canlı havuz sayıları ileride ayrıca kanıtlanırsa değerlendirilir; QA-017'nin uygulama kapsamına sızmaz.

#### 2. Bilgi mimarisi ve ekran yerleşimi

Scope seçimi yeni bir ara ekran veya modal olmayacak. Aynı kontrol iki bağlı yüzeyde aynı görsel konum ve anlamla kullanılacak:

1. **Arama başlamadan önce:** `HomeScreen` içindeki mevcut anonim eşleşme başlatma kartında, ana başlatma aksiyonunun hemen üzerinde.
2. **Arama başladıktan sonra:** QA-014 `MatchScreen` yüzeyinde, ana ambient parçacık animasyonunun üzerinde.

Böylece kullanıcı scope'u `joinQueue` gönderilmeden seçer; arama sırasında da hangi havuzda olduğunu görür ve isterse kontrollü biçimde değiştirebilir. İki ayrı seçim bileşeni farklı state tutmaz; ikisi aynı `preferredMatchScope` ve sunucunun onayladığı `effectiveMatchScope` verisini kullanır.

Önerilen düzen:

    TALKX

    Kimlerle eşleşmek istersin?
    ┌─────────────────────────────┐
    │   Global    │   Türkiye     │
    └─────────────────────────────┘

    [ Mevcut anonim eşleşmeyi başlat CTA'sı ]

QA-014 arama hâli:

    ┌───────────────────────────────────┐
    │       Global    │    Türkiye      │
    └───────────────────────────────────┘

           iki anonim TalkX parçacığı
             mevcut QA-014 animasyonu

             Dünya genelinde aranıyor...
                         00:18

             sohbet havası / başlangıç
                  Aramayı durdur

Kontrol ana CTA değildir. Ambient animasyon ve gerçek arama durumu ekranın ana odağı kalır.

#### 3. Görsel dil ve tema koruması

- Mevcut koyu zemin, neon cyan/mor-pembe ve glass yüzey dili korunur.
- Kontrol yeni bağımsız kart değil, mevcut kart/yüzeyin içindeki kompakt segmented control olur.
- Seçili segment hafif cyan-pembe glow, mevcut border tokenı ve yüksek fakat dengeli kontrast alır.
- Seçili olmayan segment okunabilir fakat düşük görsel ağırlıkta kalır.
- Kalın glow, ikinci dış çerçeve, yeni gradient ailesi veya ek dekoratif badge eklenmez.
- Bayrak kullanılırsa metnin yanında küçük destekleyici işaret olur; tek başına anlam taşımaz. Platformlar arası emoji farkı kaliteyi bozarsa mevcut ikon sistemi veya kontrollü flag asset'i kullanılır.
- Gerçek ülke adı gösterilir: `Global | Türkiye`, `Global | Germany`, `Global | Brazil`. Ülke biliniyorken `My Country` sistem dili kullanıcıya gösterilmez.
- Uzun ülke adlarında segment metni kırılmaz; kontrollü küçültme/ellipsis ve erişilebilir tam ad sağlanır.
- Dokunma hedefi en az 44x44 px, belirgin focus-visible ve klavye yön tuşu/Tab davranışı bulunur.
- Renk veya bayrak tek anlam taşımaz; seçili durum metin, `aria-checked` ve görsel durumla birlikte anlatılır.
- 320 px ve kısa telefonlarda kontrol tek satırda kalır. Yükseklik baskısında önce QA-014 animasyon boşluğu küçülür; durum metni, scope ve ana aksiyon kesilmez.
- `prefers-reduced-motion` scope kontrolünü etkilemez; QA-014'ün azaltılmış hareket kuralları aynen geçerlidir.

Erişilebilir semantik bir `radiogroup` veya aynı davranışı eksiksiz veren segmented selection modeli olmalıdır. Ekran okuyucu örneği: `Eşleşme kapsamı, Global, seçili, 1 / 2`.

#### 4. Label ve içerik sistemi

TR örnekleri:

- Başlık: `Kimlerle eşleşmek istersin?`
- Segmentler: `Global` / `Türkiye`
- Global arama: `Dünya genelinde eşleşme aranıyor...`
- Country arama: `Türkiye'de eşleşme aranıyor...`
- Scope değişimi: `Arama kapsamı değiştirildi. Dünya genelinde yeniden aranıyor...`
- Fallback: `Türkiye'de eşleşme bulmak biraz daha uzun sürüyor.`
- Aksiyonlar: `Global'e geç` / `Burada aramaya devam et`
- Ülke yok: `Bu hesap için ülke eşleşmesi henüz kullanılamıyor.`

EN örnekleri:

- Başlık: `Who do you want to meet?`
- Segmentler: `Global` / resolved country display name
- Global arama: `Searching worldwide...`
- Country arama: `Searching in Türkiye...`
- Scope değişimi: `Search scope changed. Restarting worldwide...`
- Fallback: `Finding a match in Türkiye is taking a little longer.`
- Aksiyonlar: `Go Global` / `Keep searching here`
- Ülke yok: `Country matching isn't available for this account yet.`

`Kimse yok`, `son kişi`, `hemen bulunacak` veya doğrulanmamış sıra/online sayısı gibi iddialar kullanılmaz.

#### 5. Scope ve arama state'inin ayrılması

QA-014'teki `searchPhase` yaşam döngüsü korunur:

- `preparing`
- `queued`
- `extended`
- `reconnecting`
- `offline`
- `cancelled`
- `offer`

QA-017 bunu ikinci ve bağımsız bir state ekseniyle genişletir:

- `preferredMatchScope`: Kullanıcının arayüzdeki son açık tercihi; `GLOBAL | COUNTRY`
- `effectiveMatchScope`: Sunucunun aktif arama için onayladığı kapsam; `GLOBAL | COUNTRY | null`
- `effectiveCountry`: Sunucunun COUNTRY araması için döndürdüğü canonical kod ve yerelleştirilmiş ad
- `scopeChangeStatus`: `idle | switching | failed`
- `fallbackStatus`: `hidden | eligible | visible | declined | accepted`
- `searchId`: Her yeni arama/scope için kararlı ve sunucu tarafından doğrulanan kimlik

Scope, bağlantı phase'i değildir. Örneğin kullanıcı `COUNTRY + reconnecting` veya `GLOBAL + extended` durumunda olabilir. `extended` olmak otomatik scope değişimi anlamına gelmez.

UI seçili görünümü yalnız `preferredMatchScope` üzerinden kesin başarılı gibi göstermemeli. Arama başladıktan sonra aktif kapsamın otoritesi `effectiveMatchScope` ve geçerli `searchId` olur.

#### 6. İlk açılış ve tercih saklama

- Yeni veya daha önce seçim yapmamış kullanıcı `GLOBAL` ile başlar.
- Kullanıcının açıkça seçtiği son başarılı scope hesap/cihaz tercihinde saklanabilir.
- Kayıtlı tercih `COUNTRY` olsa bile canonical ülke eksik, geçersiz, stale veya backend tarafından kullanılamaz durumdaysa sessizce ülke kuyruğuna girilmez.
- Bu durumda Global seçilir ve ülke segmenti pasif/non-technical açıklamayla sunulur.
- Ülke değişimi veya yeniden doğrulama aktif aramanın ortasında otomatik uygulanmaz.
- Logout sonrası başka hesap aynı cihazdaki önceki hesabın country tercihini devralmaz.
- Server preference ve yerel cache çelişirse authenticated server verisi otoritedir; cache yalnız hızlı ilk çizim içindir.

#### 7. Arama başlatma

Kullanıcı başlatma CTA'sına bastığında:

1. Frontend seçili tercihi ve yeni istemci `searchId`/request id ile isteği gönderir.
2. `COUNTRY` isteğinde client kullanıcı tarafından değiştirilebilir ülke adı/kodu göndermese tercih edilir; gönderse bile backend bunu otorite kabul etmez.
3. Backend authenticated kullanıcı için canonical ülkeyi çözer, scope'u doğrular ve eski aktif kuyruğu temizler.
4. UI `preparing` olur; sayaç başlamaz.
5. Sunucu `queued` ile gerçek `effectiveMatchScope`, varsa country code/display name, `queuedAt`, `searchId` ve fallback zaman bilgisini onaylar.
6. Yalnız bu onaydan sonra QA-014 sayacı ve `queued` phase'i başlar.
7. `COUNTRY` doğrulanamıyorsa sunucu tanımlı hata döndürür; frontend kendi kendine Global arama başlatmaz. Kullanıcıya Global ile başlama aksiyonu sunulur.

Örnek istek:

    {
      "type": "joinQueue",
      "searchId": "uuid",
      "scope": "COUNTRY"
    }

Örnek onay:

    {
      "type": "queued",
      "searchId": "uuid",
      "scope": "COUNTRY",
      "country": {
        "code": "TR",
        "displayName": "Türkiye"
      },
      "queuedAt": "server-time",
      "fallbackEligibleAt": "server-time"
    }

`displayName` locale göre backend veya ortak canonical ülke kataloğundan üretilir; eşleştirme anahtarı her zaman ISO koddur.

#### 8. Aktif aramada scope değiştirme

Kullanıcı arama sırasında diğer segmente dokunabilir. Modal veya ikinci ekran açılmaz; ancak değişim sessiz ve iyimser biçimde tamamlanmış gibi de gösterilmez.

Akış:

1. Segmentler kısa süre `switching` durumuna geçer ve çift tıklama engellenir.
2. UI `Arama kapsamı değiştiriliyor...` der; mevcut sayaç durur.
3. Backend kullanıcı bazında tek işlem içinde eski `searchId` ve kuyruğu geçersiz kılar.
4. Yeni `searchId` ve yeni scope ile kuyruğa giriş yapılır.
5. Yeni `queued` onayı gelince sayaç sıfırdan başlar ve `effectiveMatchScope` güncellenir.
6. Eski aramadan geciken `queued`, fallback veya `match_offer` eventleri reddedilir.
7. Değişim başarısız olursa kullanıcı aynı anda iki kuyrukta bırakılmaz; backend son kesin durumu döndürür, UI bunu açıkça gösterir ve güvenli `Tekrar dene` sunar.

Tercihen tek atomik event kullanılır:

    {
      "type": "changeMatchScope",
      "fromSearchId": "old-uuid",
      "searchId": "new-uuid",
      "scope": "GLOBAL"
    }

Ayrı `leaveQueue` + `joinQueue` kullanılacaksa da atomiklik sunucu tarafındaki kullanıcı kilidi/state machine ile garanti edilir; iki bağımsız istemci mesajının doğru sırada ulaşacağı varsayılmaz.

#### 9. Country fallback davranışı

Country araması düşük bulunabilirlik nedeniyle uzarsa sistem kullanıcıyı otomatik Global'e taşımaz.

- Fallback eşiği client içine dağınık sabit yazılmaz.
- İlk ürün varsayımı yaklaşık 30 saniyedir; gerçek değer trafik/ülke verisiyle merkezi config üzerinden ayarlanır.
- Sunucu `fallbackEligibleAt` döndürebilir veya `country_fallback_available` eventi gönderebilir.
- Fallback görünmesi ülke aramasını durdurmaz.
- Kullanıcı öneriyi kapatır veya `Burada aramaya devam et` seçerse aynı `searchId` ve ülke kuyruğu devam eder.
- `Global'e geç` scope değişimiyle aynı atomik mekanizmayı kullanır; yeni `searchId`, yeni `queuedAt` ve sıfırlanan sayaç oluşur.
- Tek arama oturumunda aynı fallback kartı sürekli yeniden açılmaz.
- Reconnect, görünmüş fallback'i yanlışlıkla yeni öneri gibi çoğaltmaz.
- Backend ülke kuyruğunda kesin uygun kullanıcı sayısını bilmiyorsa metin `kimse yok` demez; yalnız beklemenin uzadığını söyler.

Önerilen kompakt alan:

    Türkiye'de eşleşme bulmak biraz daha uzun sürüyor.

    [ Global'e geç ]   [ Burada aramaya devam et ]

Bu alan modal değildir; QA-014 başlangıç kartını, durdurma aksiyonunu veya animasyonu ekrandan itmez.

#### 10. QA-003 teklif ekranının korunması

Gerçek `match_offer` geldiğinde:

- QA-014'ün mevcut final parçacık hareketi ve 300–600 ms geçiş kuralı korunur.
- Teklif aktif `searchId`, `effectiveMatchScope` ve COUNTRY ise aynı canonical country code ile doğrulanır.
- Scope kontrolü teklif ekranında interaktif kalmaz.
- QA-003 kartına ilk sürümde yeni ülke bayrağı, `Country match` badge'i, yeni CTA veya ayrı açıklama bloğu eklenmez.
- QA-003'ün kimlik, countdown/progress, `Sohbete Başla`, `Geç` ve `Eşleşmeyi iptal et` hiyerarşisi aynen korunur.
- QA-014 mood/prompt aktarımı devam eder; scope bu içeriğin önüne geçmez.
- Peer reject, timeout veya offer kapanması sonrası otomatik requeue kullanıcının son onaylanmış scope'uyla yapılır.
- Kullanıcı `Geç` dediğinde yalnız kişiyi reddeder; scope değişmez.
- Kullanıcı `Eşleşmeyi iptal et` dediğinde tüm arama kapanır; tercih sonraki başlangıç için saklanabilir fakat aktif kuyruk kalmaz.

Backend `match_offer` içinde scope/search kimliğini bütünlük için taşır; frontend bunu QA-003'te göstermek zorunda değildir.

#### 11. Ülke verisinin otoritesi ve gizlilik

Mevcut `legal_acceptances.location_country` alanı:

- Yasal kabul zamanına ait tarihsel snapshot'tır.
- Serbest metin ülke adı tutar.
- Kaynak ve çözümleme kalitesi değişebilir.
- Kullanıcı seyahat etmiş, VPN kullanmış veya veri stale kalmış olabilir.
- Eşleştirme için canonical ISO ülke kodu değildir.

Bu nedenle alan doğrudan matchmaking anahtarı yapılmaz. Migration sırasında yalnız aday kaynak olarak incelenebilir; normalize ve doğrulama olmadan yeni alana taşınmaz.

Buradaki `doğrulanmış` ifadesi kimlik/KYC doğrulaması değildir; ülke kodunun tanımlı sunucu politikasıyla canonical hâle getirilmiş ve eşleşme için uygun kabul edilmiş olmasıdır.

Hesap/profil seviyesinde ayrı canonical model gerekir. İsimler uygulama sırasında mevcut şemaya göre kesinleştirilir; anlam en az şunları taşır:

- `match_country_code`: ISO 3166-1 alpha-2
- `match_country_source`: kayıt IP'si, doğrulanmış profil veya tanımlı başka kaynak
- `match_country_status`: verified / inferred / unavailable / stale gibi kontrollü enum
- `match_country_updated_at`
- Gerekirse policy/version bilgisi

Kurallar:

- Tam IP, GPS koordinatı, şehir veya adres queue kaydına kopyalanmaz.
- Client ülke kodunu keyfi biçimde seçemez.
- Kullanıcıya yalnız kendi effective ülkesi gösterilir; peer'in hassas konum kaynağı açıklanmaz.
- Ülke tespiti kesin değilse sistem bunu kesin gerçek gibi kullanmaz.
- VPN/seyahat sinyali aktif aramayı sessizce değiştirmez.
- Retention, hesap silme ve privacy metni mevcut geo veri yaşam döngüsüyle birlikte kararlaştırılır.
- Admin/analitikte düşük hacimli ülke kırılımları tek kullanıcıyı açığa çıkarmayacak minimum cohort kurallarına tabi olur.

#### 12. Backend kuyruk modeli

Bugünkü tek bellek içi `waitingQueue`, scope bilgisi taşımayan tek havuzdur. QA-017 ile mantıksal partition gerekir:

    match:global
    match:country:TR
    match:country:DE
    match:country:BR

Bu fiziksel olarak `Map<queueKey, QueueEntry[]>`, eşdeğer indeks veya ileride paylaşımlı queue olabilir. İlk uygulama teknoloji seçiminden bağımsız olarak şu semantiği sağlamalıdır:

- Bir kullanıcı aynı anda en fazla bir aktif queue entry taşır.
- `GLOBAL` yalnız `GLOBAL` kullanıcılarla eşleşir.
- `COUNTRY` yalnız aynı canonical ISO koda sahip `COUNTRY` kullanıcılarla eşleşir.
- COUNTRY ve GLOBAL havuzları otomatik karıştırılmaz.
- FIFO/fairness mevcut block, ban, shadow-ban ve pair rematch cooldown kurallarıyla birlikte korunur.
- Geçersiz/disconnected entry temizliği tüm partition'larda çalışır.
- Queue entry en az `clientId`, `dbUserId`, socket referansı/instance yönlendirmesi, `searchId`, scope, country code, `queuedAt` ve trigger taşır.
- Pending match scope/search kimliğini iki katılımcı için korur.
- Oda kurulduğunda match scope telemetry'ye taşınabilir; sohbet davranışını değiştirmez.
- Çoklu backend instance planlanırsa process memory tek otorite kalamaz; paylaşımlı ve atomik queue/lock çözümü ayrıca uygulanır.

Country kuyruğu boş olması hata değildir. Uzun bekleme product eventidir; crash veya bağlantı problemi sayılmaz.

#### 13. WebSocket event sözleşmesi

Minimum event ailesi:

- `joinQueue`
- `queued`
- `changeMatchScope`
- `match_scope_change_failed`
- `country_fallback_available` veya eşdeğer server time alanı
- `leaveQueue`
- `queue_left`
- `match_offer`
- `match_offer_closed`

Her queue/offer eventi ilgili `searchId` taşır. COUNTRY eventleri ayrıca canonical country code taşır; display name yalnız sunum verisidir.

Önerilen kontrollü hata kodları:

- `MATCH_COUNTRY_UNAVAILABLE`
- `MATCH_COUNTRY_STALE`
- `MATCH_SCOPE_INVALID`
- `MATCH_SCOPE_CHANGE_FAILED`
- `MATCH_SEARCH_STALE`

Frontend teknik kodu doğrudan kullanıcıya göstermez; TR/EN eyleme dönük metne çevirir.

Server kullanıcı bazında aktif aramayı tutar:

    activeSearch = {
      searchId,
      scope,
      countryCode,
      queuedAt,
      queueKey,
      connectionId,
      status
    }

Aynı client veya ikinci cihaz yeni arama başlattığında mevcut ürün politikası açık olmalıdır: eski arama iptal edilir ya da yeni istek reddedilir. İki cihazın aynı hesapla iki farklı scope'ta kuyruğa girmesine izin verilmez.

#### 14. Reconnect, requeue ve yarış durumları

- Kısa reconnect'te backend geçerli `searchId` ve queue entry'yi koruyorsa aynı scope/sayaç sürer.
- Queue korunmuyorsa yeni `searchId` ve yeni sayaçla `Arama yeniden başlatıldı` denir.
- Peer reject, offer timeout veya conversation oluşturma hatasından sonra otomatik requeue son onaylanmış scope'u kullanır; bugünkü parametresiz `queueClientForRematch -> joinQueue` davranışı Global'e düşecek biçimde bırakılmaz.
- Scope değişimi ile `match_offer` aynı anda yarışırsa yalnız backend'in aktif state'inde geçerli search kazanır.
- Eski search için gelen offer iki tarafta da güvenli kapanır; kullanıcı stale QA-003 kartı görmez.
- Hızlı segment tıklamalarında yalnız son geçerli intent işlenir; her tıklama ayrı queue entry üretmez.
- `leaveQueue`, cancel ve scope change idempotent olur.
- App background/foreground dönüşünde client local görünüme değil backend active-search snapshot'ına göre toparlanır.
- Backend restart/instance kaybı queue'yu düşürürse UI bunu reconnect gibi sonsuza kadar saklamaz; aramanın yeniden başlatılması gerektiğini dürüstçe söyler.

#### 15. Capability flag ve geriye uyum

Frontend ve backend aynı anda deploy edilmeyebilir. Bu nedenle welcome/config cevabında sürümlü capability bulunmalıdır:

    matchScopes: {
      enabled: true,
      supported: ["GLOBAL", "COUNTRY"],
      countryAvailable: true
    }

- Backend özelliği desteklemiyorsa selector tamamen gizlenir ve mevcut Global akış aynen çalışır.
- Backend yalnız GLOBAL döndürüyorsa client COUNTRY isteğinde ısrar etmez.
- Eski client yeni backend'de mevcut `joinQueue` ile Global'e girmeye devam eder.
- Yeni eventler bilinmeyen eski client davranışını bozmamalıdır.
- Rollout feature flag ve gerekirse ülke/cohort bazlı kontrollü açılışla yapılır.
- Feature kapatıldığında aktif COUNTRY aramalarının nasıl sonlandırılacağı veya Global önerileceği deploy runbook'unda belirlenir; sessiz scope değişimi yine yapılmaz.

#### 16. Ölçümleme ve Jarvis özeti

Anlamlı eventler:

- `match_scope_selector_seen`
- `match_scope_selected`
- `match_search_started` içinde requested scope
- `match_queue_confirmed` içinde effective scope
- `match_scope_change_started`
- `match_scope_change_result`
- `match_country_fallback_shown`
- `match_country_fallback_action`
- `match_offer_received` içinde scope
- `match_search_cancelled` içinde scope ve süre

Kurallar:

- Country code yalnız ürünün kendi kullanıcısına ait canonical ve izinli boyutta tutulur.
- Tam IP, GPS, peer konumu veya serbest ülke metni telemetry'ye konmaz.
- `shown`, `accepted`, `declined/continued` ayrılır; kartı görmeyen kullanıcı reddetmiş sayılmaz.
- Scope değişimi yeni search olarak sayılırken aynı kullanıcı yolculuğunda önceki search ile bağ güvenli pseudonymous id üzerinden korunur.
- Global ve Country için median/P95 bekleme, offer oranı, kabul oranı, fallback kabulü, cancel ve sohbet başlangıcı ölçülür.
- Az trafik `başarısız ülke` diye yorumlanmaz; örnek sayısı ve zaman penceresi görünür olur.
- Admin varsayılanında ülke ülke ham kullanıcı tablosu değil, yeterli cohort'lu sonuç özeti sunulur.

Örnek Jarvis özeti:

> Country aramalarında median bekleme 34 sn · Global 11 sn · 186 uygun aramanın %27'si Global önerisini kabul etti · 9 ülkede örnek yetersiz.

Bu sayıların scope tanımı, pencere, tekil kullanıcı/search birimi ve veri tazeliği açıklanır.

#### 17. Kabul kriterleri

- [ ] Global TalkX'in ilk kullanım varsayılanı ve ana ürün kapsamı.
- [ ] Kullanıcı scope'u arama başlamadan seçebiliyor; seçim yeni ekran veya modal oluşturmuyor.
- [ ] Aynı soft segmented control anonim eşleşme başlatma kartı ve QA-014 arama yüzeyinde ortak state ile çalışıyor.
- [ ] Ülke biliniyorsa `My Country` yerine gerçek yerelleştirilmiş ülke adı gösteriliyor.
- [ ] Ülke yok/geçersiz/stale ise COUNTRY kuyruğuna girilmiyor; Global otomatik başlatılmadan anlaşılır alternatif sunuluyor.
- [ ] Seçili ve seçili olmayan durumlar tema, contrast, focus, 44 px dokunma ve ekran okuyucu kurallarını karşılıyor.
- [ ] Scope ve QA-014 `searchPhase` iki bağımsız state ekseni olarak modellenmiş.
- [ ] Sayaç yalnız yeni scope için sunucu `queued` onayından sonra başlıyor.
- [ ] Aktif aramada scope değişimi tek kullanıcı/tek queue garantisiyle atomik ve idempotent.
- [ ] Eski `searchId` eventleri yeni scope'u veya QA-003 teklifini bozamıyor.
- [ ] COUNTRY yalnız aynı canonical ISO koda sahip COUNTRY kullanıcılarla eşleşiyor.
- [ ] GLOBAL yalnız GLOBAL kullanıcılarla eşleşiyor; havuzlar sessizce karışmıyor.
- [ ] Uzayan country aramasında Global yalnız kullanıcı onaylı fallback olarak sunuluyor.
- [ ] Fallback eşiği merkezi config/server time'a bağlı; reconnect duplicate öneri üretmiyor.
- [ ] Peer reject, timeout ve otomatik requeue aynı onaylanmış scope'u koruyor.
- [ ] QA-003 teklif kartının mevcut hiyerarşisi, CTA'ları ve countdown'u değişmiyor.
- [ ] QA-014 mood/prompt ve parçacık geçişi scope eklenince kaybolmuyor.
- [ ] `legal_acceptances.location_country` doğrudan queue anahtarı yapılmıyor.
- [ ] Canonical ülke ISO kodu, kaynak/status ve güncellenme zamanı kontrollü veri modelinde tutuluyor.
- [ ] Client keyfi country code ile başka ülke kuyruğuna giremiyor.
- [ ] Queue/telemetry tam IP, GPS, şehir veya peer konumu taşımıyor.
- [ ] Capability flag ile eski frontend/backend Global davranışı bozulmuyor.
- [ ] Global/Country bekleme, fallback, offer, kabul, cancel ve chat başlangıcı tanımlı eventlerle ölçülüyor.
- [ ] TR/EN, uzun ülke adı, 320 px, kısa telefon, WebView, keyboard ve reduced-motion testleri geçiyor.
- [ ] İki istemcili otomasyon ve manuel Web/Android QA ile scope izolasyonu kanıtlanıyor.

#### 18. Manuel ve otomatik test matrisi

**Temel kapsam**

- Yeni kullanıcı: Global seçili, Global queue onayı ve teklif.
- Dönen Global kullanıcısı: tercih korunur.
- Dönen COUNTRY kullanıcısı: geçerli ülke ile tercih korunur.
- Türkiye/Türkiye COUNTRY eşleşmesi.
- Türkiye/Almanya COUNTRY kullanıcılarının eşleşmemesi.
- GLOBAL kullanıcıyla COUNTRY kullanıcısının sessizce eşleşmemesi.
- İki GLOBAL kullanıcının mevcut block/cooldown kurallarıyla eşleşmesi.

**Ülke verisi**

- Null, boş, serbest metin, küçük/büyük harf, geçersiz ISO ve stale durum.
- `legal_acceptances.location_country` var fakat canonical alan yok.
- VPN/seyahat veya ülke güncellemesi sırasında aktif aramanın değişmemesi.
- Uzun ülke adı, farklı locale display name ve eksik çeviri.
- Client'ın sahte `countryCode` göndermesi ve backend reddi/ignore davranışı.

**Scope değişimi ve yarışlar**

- Global -> Country ve Country -> Global normal geçiş.
- Çok hızlı art arda segment tıklama.
- `changeMatchScope` ile aynı anda eski `queued`.
- `changeMatchScope` ile aynı anda eski `match_offer`.
- Leave onayı gecikmesi ve yeni join.
- Scope change backend hatası; sıfır veya iki queue entry oluşmaması.
- İkinci cihazdan farklı scope araması.
- App refresh/background/foreground sırasında active-search recovery.

**Fallback**

- Eşik öncesi öneri görünmemesi.
- Eşik sonrası arama sürerken tek öneri.
- `Global'e geç` ve yeni sayaç.
- `Burada aramaya devam et`.
- Öneriyi kapatma ve aynı session'da tekrar rahatsız etmeme.
- Fallback görünürken match offer gelmesi.
- Fallback sırasında reconnect ve duplicate event.
- Config değişimi ve server/client saat farkı.

**QA-014 ve QA-003 regresyonu**

- `preparing`, `queued`, `extended`, `reconnecting`, `offline`, `cancelled`, `offer`.
- İki parçacık animasyonu ve yalnız gerçek offer ile final hareketi.
- Mood/prompt'un scope değişiminde korunması ve sessiz kayıp olmaması.
- QA-003 countdown/progress, kabul, geç, iptal, peer accepted, timeout ve auto accept.
- Peer reject/timeout sonrası aynı scope requeue.
- QA-003'te yeni scope kontrolü/badge/CTA oluşmaması.
- Chat başlangıcında scope'un mesaj içeriği veya kullanıcıya açılan peer konumu hâline gelmemesi.

**Platform ve accessibility**

- Web desktop, 320 px mobil web ve kısa ekran.
- Android WebView, safe-area, back tuşu ve background dönüşü.
- Klavye, screen reader, focus-visible ve 44 px hedef.
- Bayraksız/asset yüklenemeyen durum; metinle anlamın korunması.
- Reduced motion ve düşük güçlü cihaz.
- TR/EN ve büyük sistem fontu.

#### 19. İlgili kod ve veri alanları

- `chatapp-frontend/src/screens/HomeScreen.jsx` — arama öncesi scope seçimi
- `chatapp-frontend/src/screens/MatchScreen.jsx` — QA-014 içinde ortak segmented control, phase ve fallback
- `chatapp-frontend/src/App.jsx` — preferred/effective scope, `searchId`, event routing ve QA-003 geçişi
- `chatapp-frontend/src/i18n.jsx` ve mevcut locale mesaj kaynakları — TR/EN scope/country/fallback metinleri
- `chatapp-backend/index.js` — bugünkü tek `waitingQueue`, `joinQueue`, `removeFromQueue`, `queueClientForRematch`, `createPendingMatch`, `match_offer`, reconnect ve active client state
- `chatapp-backend/db.js` — canonical country migration ve veri yaşam döngüsü
- `chatapp-backend/admin.js` — mevcut geo snapshot'larının kaynak/kalite anlamı; matchmaking otoritesiyle karıştırılmaması
- `legal_acceptances.location_country` — yalnız tarihsel kayıt/aday migration kaynağı, doğrudan queue anahtarı değil

#### 20. Uygulama sırası ve durma noktası

Bu kayıt ileride wave'lere bölünürken bağımlılık sırası korunur:

1. Canonical ülke veri kararı ve migration.
2. Sürümlü WebSocket/capability/search sözleşmesi.
3. Partition queue, tek aktif arama ve atomik scope değişimi.
4. Frontend ortak scope state'i ve arama öncesi selector.
5. QA-014 içi selector, scope metinleri ve fallback.
6. QA-003 geçiş/requeue regresyon koruması.
7. Telemetry/Jarvis özeti.
8. Otomatik test, Web/Android manuel QA ve rollout flag.

Bu sıra burada yalnız bağımlılık kaydıdır; wave planı veya uygulama başlangıcı değildir. Ayrı talimat gelmeden kod, migration, UI veya rollout yapılmaz.

#### Net ürün özeti

> Kullanıcı TalkX'e girdiğinde Global varsayılanı görür. İsterse yalnız kendi doğrulanmış ülkesini seçer. Arama QA-014 içinde aynı tema ve gerçek state'lerle sürer. Ülke havuzu yavaşsa Global önerilir ama kullanıcı seçmeden uygulanmaz. Eşleşme geldiğinde QA-003 aynen odağa geçer. Backend tek aktif ve kimlikli aramayla scope izolasyonunu, aynı scope requeue'yu ve stale event güvenliğini garanti eder.


### Ilk manuel oturum

- Tarih: 2026-09-01
- Durum: Tarayici kontrol baglantisi Windows ortam hatasi nedeniyle bekliyor; bu bir TalkX uygulama hatasi degildir.
- Not: Canli HTTP ve endpoint kontrolleri tamamlandi. Tiklamali frontend/admin turu tarayici baglantisi kullanilabilir oldugunda devam edecek.

## 17. Fikir parki

- [ ] [P3] Global buyume ve edinim kanallari.
- [ ] [P3] Monetizasyon modeli.
- [ ] [P3] Eslesme kalitesi ve tercih sinyalleri.
- [ ] [P3] Yeni sosyal ozellikler.
- [ ] [P3] Gelismis moderasyon ve otomasyon.
