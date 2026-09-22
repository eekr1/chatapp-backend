# TalkX Wave 01 Plan — Ürün Sınırı ve İnternet Yüzeyi Güvenliği

> Bu belge yalnız Wave 01 için hazırlanmış uygulama planıdır.
> Canonical ayrıntı Plan A/B/C stable ID maddelerindedir; burada yeniden mimari üretilmez.
> Wave 01 Sale Release kapsamı 2026-09-23 tarihinde uygulandı ve otomatik doğrulandı. Manuel QA Checkpoint A / Wave 19'a ertelendi.

## 1. Durum ve yürütme sınırı

- **Wave:** 01
- **Wave adı:** Ürün sınırı, internet yüzeyi güvenliği ve global uyum başlangıcı
- **Plan durumu:** Uygulandı
- **Wave durumu:** AUTO-VERIFIED / COMMITTED / MANUAL-QA-DEFERRED
- **Uygulama durumu:** Sale Release kapsamı tamamlandı
- **Uygulama yetkisi:** 2026-09-23 tarihinde kullanıcı tarafından verildi
- **Önceki wave:** Yok
- **Sonraki wave:** Wave 02 — ayrı kullanıcı talimatıyla planı hazırlandı; aktif değil ve uygulanmayacak

Bu planın hazırlanması kod, bağımlılık güncellemesi, güvenlik politikası değişikliği, Play Console işlemi, deploy veya Wave 02 aktivasyonu/uygulaması için yetki değildir.

## 1.1 Sale Release override — TAM / ÇEKİRDEK

- **Satış öncesi uygulanır:** Web/Android ürün vaadi, HTTP/WS type-length validation, body/payload limiti, origin kontrolü, guest/legacy fallback'in kapatılması ve minimum HTTP güvenlik header'ları.
- **Final manuel checklist'e taşınır:** Play Console hedef kitle/content rating/Data Safety, mağaza metni karşılaştırması ve insan legal/child-safety incelemesi. Bunlar Wave 01 commit'ini engellemez; Wave 19 Sale Acceptance QA'da kapanır.
- **Kapanış:** Zorunlu otomatik kontroller geçer, tek Wave 01 commit'i alınır ve **DUR**. Wave 02 yalnız kullanıcının ayrı açık başlatma talimatıyla açılır.
- Bu override, aşağıdaki ayrıntılı planın manuel QA'yı Wave 01 ilerleme kapısı yapan cümlelerinden üstündür; canonical Plan A/B/C kriterleri silinmez ve kanıtlanmayanlar açık kalır.

## 2. Canonical referanslar

Uygulama sırası değişmez:

1. `A-PRD-001` — Plan A / tek ürün vaadi ve anonimlik dili / bütün kabul kriterleri
2. `B-SEC-001` — Plan B / WebSocket ve API input güvenliği / bütün kabul kriterleri
3. `C-COMP-001` — Plan C / global erişim, yaş ve mağaza uyumu / bütün kabul kriterleri

Yürütme kaynağı: `../TALKX_WAVE_MAP.md` / Wave 01.
Kilitli karar kaynağı: `../TALKX_MASTER_BACKLOG.md` / §1, §3, §5, §6 ve ilgili QA kanıtları.

## 3. Wave sonucu

Wave 01 sonunda:

- TalkX'in tek cümlelik ürün vaadi Web, Android ve mağaza metni için aynı çekirdek anlamı taşıyacak,
- Hesaplı fakat kullanıcılar arasında anonim model ile servis düzeyindeki veri işleme birbirine karıştırılmayacak,
- HTTP ve WebSocket internet girdileri ölçülü, doğrulanmış ve kontrollü biçimde reddedilebilir olacak,
- Token gerektiren realtime işlemler guest/legacy fallback üzerinden çalışmayacak,
- Global dağıtım, yaş, content rating ve çocuk güvenliği gereksinimleri ürün kimliğini sessizce 18+ yapmadan kanıta bağlanacak,
- Yerel otomatik kanıt ile Play Console/insan incelemesi gerektiren manuel kanıt açıkça ayrılacak.

## 4. Doğrulanmış başlangıç fotoğrafı

### 4.1 Repo ve değişiklik güvenliği

- Repo kökünde önceden var olan geniş bir dirty durum bulunuyor.
- Tarihsel `backend/` ve `frontend/` ağacı Git tarafından silinmiş; güncel `chatapp-backend/`, `chatapp-frontend/`, `android/` ve `docs/` ağaçları untracked görünüyor.
- Wave 01 bu kullanıcı değişikliklerini sahiplenmez, geri almaz, taşımaz veya temizlemez.
- Uygulama başlangıcında hedef dosyaların hash/durum fotoğrafı alınır; kapanışta yalnız Wave 01 farkları raporlanır.

### 4.2 A-PRD-001 mevcut gerçek

- TR/EN Home metinleri anonim mesajların geçici, arkadaş mesajlarının kalıcı/geçmişli olduğunu kısmen anlatıyor.
- Auth metni e-posta toplanmadığını ve hesap kurtarma olmadığını dürüstçe söylüyor.
- Splash alt başlığı `Cyber Connect`; ürünün anonim birebir eşleşme olduğunu tek bakışta anlatmıyor.
- Web manifest açıklaması yalnız `TalkX real-time chat`; çekirdek ürün vaadi eksik.
- Web, Android ve store için tek canonical ürün cümlesi repoda tanımlı değil.
- Kullanıcılar arası anonimlik ile servis veri işlemesi arasındaki ayrım ana kullanıcı metinlerinde görünür değil.
- Store listing metni ve canlı mağaza beyanı repo dışında; bu turda doğrulanmış sayılmaz.

### 4.3 B-SEC-001 mevcut gerçek

- HTTP için talkx.chat, www.talkx.chat, localhost ve Capacitor originlerini içeren allowlist mevcut.
- Origin'siz HTTP istekleri genel olarak kabul ediliyor; origin güven işareti değil.
- `express.json()` için açık body limiti yazılmamış.
- WebSocket server `maxPayload` veya upgrade/origin doğrulaması olmadan oluşturuluyor.
- WebSocket `hello_ack` geçerli token yoksa legacy/guest kullanıcı oluşturabiliyor.
- Auth öncesi `hello_ack` dışındaki eventler işlenmiyor; bu koruma korunacak.
- Geçersiz JSON sessizce bırakılıyor; bilinmeyen event için merkezi kontrollü hata yok.
- Event alan/type/uzunluk kontrolleri parçalı; bazı eventlerde doğrulama var, anonim `message` gibi alanlarda açık server uzunluk sınırı yok.
- Görsel veri için 2 MB binary limit mevcut; WebSocket genel payload limiti base64 zarfını da taşıyacak şekilde bunun üzerinde olmalı.
- HTTP rate limiterlar ve basit WS hız limiti mevcut; bunların yeniden tasarımı `B-SEC-002` / Wave 02 kapsamıdır.
- Backend package'ında otomatik test scripti yok; mevcut `test_auth_flow.js` bağımsız yardımcı script niteliğinde.
- `ws`, `multer`, `express-rate-limit` ve diğer internet yüzeyi bağımlılıkları davranış testi olmadan yükseltilmeyecek.

### 4.4 C-COMP-001 mevcut gerçek

- Android uygulama kimliği `com.talkx.app`; cleartext kapalı ve backup kapalı.
- Repo içinde yalnız hesap silme kamusal sayfası belirgin; store/yaş/CSAE/CSAM/ülke uyum kanıt paketi bulunmuyor.
- Play Console hedef kitle, content rating, Data Safety ve bölge dağıtımı repo içinden doğrulanamaz.
- Terms/Privacy/Community Guidelines/Child Safety İngilizce insan incelemesi kanıtı yok.
- Çocuk güvenliği owner, escalation, yetkili makam bildirim kanalı ve doğrulanmış irtibat kaydı eksik.
- Bu alan hukuki tavsiye olarak yorumlanmayacak; belirsiz maddeler owner ve inceleme durumu ile kaydedilecek.

## 5. Kilitli Wave 01 kararları

### 5.1 Ürün dili

Canonical çekirdek anlam:

> TalkX, hesap sahibi kullanıcıları global rastgele birebir sohbette birbirine karşı anonim olarak eşleştirir; sohbetten sonra kullanıcılar isterse arkadaş olup kalıcı mesajlaşmaya geçebilir.

Kurallar:

- TR/EN aynı anlamı taşır; kelimesi kelimesine çeviri zorunlu değildir.
- “Anonim” servis tarafından hiç veri işlenmediği anlamına gelmez.
- Anonim eşleşme mesajlarının geçici, arkadaş sohbetinin kalıcı olduğu doğru veri kaynağına dayanarak anlatılır.
- E-posta/kurtarma politikası değiştirilmez.
- Ürün sessizce 18+ yapılmaz ve tek ülkeye indirgenmez.
- Pazarlama sloganı deneyi veya yeni özellik vaadi eklenmez.

### 5.2 Realtime kimlik sınırı

- Socket bağlantısı kimlik doğrulanana kadar yalnız handshake durumundadır.
- `hello_ack` için geçerli session token zorunludur.
- Token yoksa veya geçersizse guest kullanıcı oluşturulmaz; kontrollü auth hatası sonrası bağlantı kullanılabilir state'e geçmez.
- Auth olmadan queue, match, message, media, presence, report veya direct event çalışmaz.
- Mevcut client session-expired/recovery davranışı doğrulanmadan hata/close sırası değiştirilemez.

### 5.3 Origin ve payload sınırı

- Browser WebSocket origin'i explicit allowlist ile doğrulanır.
- Capacitor için `https://localhost` ve gerekiyorsa doğrulanmış `capacitor://localhost` açık native origin olarak ele alınır.
- Origin'siz bağlantı varsayılan güvenli kanal sayılmaz. Gerçek Android handshake origin'i test edilmeden blanket izin veya blanket red uygulanmaz.
- HTTP CORS yalnız browser okuma iznidir; auth yerine kullanılmaz.
- HTTP JSON body limiti açık ve testli olacaktır.
- WebSocket `maxPayload`, mevcut 2 MB görselin base64/envelope maliyetini taşıyacak fakat sınırsız belleği engelleyecek şekilde belgeli olacaktır.
- Mesaj, nickname, kimlik, reason ve serbest metin alanları server tarafında type ve uzunluk sınırına sahip olacaktır.
- Bilinmeyen event, bilinmeyen alan, yanlış type ve bozuk JSON hiçbir yan etki üretmeden kontrollü reddedilir.

### 5.4 Uyum kanıtı

- Repo içi kanıt ile Play Console/canlı panel kanıtı ayrı tutulur.
- Mağaza beyanı kod, veri akışı ve gerçek operasyonla eşleşmeden “tamam” işaretlenmez.
- CSAE/CSAM metni tek başına yeterli değildir; owner, escalation, irtibat ve bildirim yolu gerekir.
- TR/EN legal metinlerin insan incelemesi AI tarafından varsayılamaz.
- Bölgesel kısıt önerisi ürün ve kullanıcı etkisiyle birlikte açık onay ister.

## 6. Uygulama paketleri

### Paket 01A — A-PRD-001 ürün vaadi

Hedef yüzeyler:

- `chatapp-frontend/src/i18n/messages.tr.js`
- `chatapp-frontend/src/i18n/messages.en.js`
- `chatapp-frontend/src/screens/SplashScreen.jsx`
- `chatapp-frontend/src/screens/HomeScreen.jsx`
- `chatapp-frontend/public/site.webmanifest`
- Gerekirse aynı anlamı tüketen Web/Android kamusal ürün metinleri

İşler:

- Tek canonical ürün vaadi için TR/EN anahtarları oluştur.
- Splash/Home üzerinde tema ve bilgi hiyerarşisini bozmadan beş saniyede anlaşılır konumlandırma yap.
- Anonim ve arkadaş modu saklama farkını gerçek davranışla karşılaştır.
- Manifest açıklamasını aynı çekirdek anlamla eşle.
- Servis veri işlemesini “hiç veri yok” iddiasına dönüştürme.
- Store metni için kopyalanabilir TR/EN kaynak üret; canlı mağazaya gönderme.

### Paket 01B — B-SEC-001 input güvenliği

Muhtemel hedef yüzeyler:

- `chatapp-backend/index.js`
- `chatapp-backend/routes/auth.js`
- `chatapp-backend/routes/profile.js`
- `chatapp-backend/routes/friends.js`
- `chatapp-backend/routes/push.js`
- `chatapp-backend/routes/support.js`
- İnternet girdisi alan ilgili admin route sınırları
- Yeni ortak doğrulama yardımcısı gerekirse `chatapp-backend/utils/`
- `chatapp-backend/package.json` ve yalnız gerekli güvenlik testleri

İş sırası:

1. HTTP route ve WS event envanterini test fixture'ına dönüştür.
2. Ortak tip, allowlist, uzunluk ve ID doğrulama yardımcılarını küçük ve saf fonksiyonlar olarak kur.
3. `express.json` limitini açıklaştır; multipart/support limitini ayrı koru.
4. `x-powered-by` ve minimum güvenlik header kararını admin/static davranışını bozmadan uygula.
5. WebSocket server'a belgeli `maxPayload` ve doğrulanmış origin politikası ekle.
6. Guest/legacy handshake fallback'ini kaldır; geçerli token sınırını testle.
7. Her mevcut event için gerekli alan/type/uzunluk allowlist'ini uygula; iş semantiğini değiştirme.
8. Bilinmeyen/bozuk eventlerin yan etkisiz kontrollü reddini testle.
9. Error/rejection loglarında token, şifre, mesaj veya ham payload bulunmadığını doğrula.
10. Dependency audit sonucunu kaydet; davranış testi olmadan paket yükseltme.

Wave 02'ye bırakılanlar:

- Rate-limit mimarisinin yeniden tasarımı
- Sürümlü genel API/event schema sistemi
- Yeni error contract ailesi
- Reconnect/matchmaking state değişikliği
- Structured logging platformunun tamamı

### Paket 01C — C-COMP-001 global uyum başlangıcı

Hedef çıktı:

- `docs/TALKX_GLOBAL_COMPLIANCE_MATRIX.md` — kanıt, owner, durum ve açık karar matrisi
- Gerekirse kamusal policy kaynaklarına yönlendiren mevcut legal yüzey düzeltmeleri
- Wave 01 sonuç bölümünde canlı panel ve insan incelemesi kanıt bağlantıları

Matris en az şunları içerir:

- Google Play hedef kitle ve content rating soruları
- Anonim/rastgele sohbet özelliğinin beyan etkisi
- Data Safety ile kod/veri akışı karşılaştırması
- Ülke/bölge dağıtım seçenekleri ve kullanıcı etkisi
- CSAE/CSAM politika kaynağı
- Operasyon owner ve escalation
- Yetkili makam bildirim süreci
- Çocuk güvenliği irtibatı
- Terms/Privacy/Community Guidelines/Child Safety TR/EN durumları
- Web/Android/store ürün vaadi eşliği
- Kanıt türü: repo, canlı panel, insan incelemesi veya açık eksik
- Son doğrulama tarihi

Canlı Play Console değişikliği, mağaza yayını ve hukuki onay bu planla otomatik yetkilendirilmez.

## 7. Açık kapsam dışı

- B-SEC-002 rate-limit/abuse yeniden tasarımı
- B-API-001 sürümlü API ve error schema çalışması
- B-AUTH-001 session/çoklu cihaz yaşam döngüsü
- C-ADMIN-001 admin kabuğu
- QA-014/003/017 matchmaking uygulaması
- Yeni hesap kurtarma veya e-posta zorunluluğu
- 18+ yeniden konumlandırma
- Global ürünü tek ülkeye kapatma
- Canlı DB, migration, Render restart/deploy
- Play Store production publish
- Wave 02 aktivasyonu veya uygulaması

## 8. Otomatik doğrulama planı

### Backend statik ve dependency

- `node --check chatapp-backend/index.js`
- Değişen route ve utils dosyalarında `node --check`
- `npm --prefix chatapp-backend audit --omit=dev`
- Dependency değişirse lockfile ve davranış regresyonu

### Backend güvenlik test matrisi

- Geçerli token / token yok / bozuk token handshake
- Allowed web origin / TalkX production origin / Capacitor origin / yabancı origin / origin yok
- JSON olmayan frame
- Genel payload sınır altı / sınır üstü
- 2 MB görsel + base64 zarfı
- Bilinmeyen event
- Eksik, fazla ve yanlış tipli alan
- Anonim ve direct mesaj boş/sınır/sınır üstü
- Auth öncesi queue/message/media/report denemesi
- Reddedilen girdide DB, queue, room veya teslim yan etkisi olmaması
- Hata/log çıktısında token, şifre, mesaj ve ham payload bulunmaması

Testler tekrarlanabilir bir backend test komutuna bağlanır; yalnız ad-hoc elle script bırakılmaz.

### Frontend

- `npm --prefix chatapp-frontend run lint`
- `npm --prefix chatapp-frontend run build`
- `npm run check:text-encoding`
- TR/EN anahtar eşliği
- Ürün vaadi string snapshot veya hedefli component testi

### Android yerel

- Güncel Web build sonrası yalnız doğrulama amacıyla asset eşliği
- Manifestte cleartext/backup/app id regresyonu
- Wave 18 release zinciri veya mağaza bundle/publish çalıştırılmaz

## 9. Manuel QA havuzu — Checkpoint A / Wave 19 (commit kapısı değil)

### Web TR/EN

- Splash → Auth → Home akışında beş saniyelik ürün anlaşılırlığı
- Anonim birebir eşleşme, hesaplı anonimlik ve arkadaşlığa geçiş anlamı
- Anonim/arkadaş saklama farkı
- E-posta toplamama ve kurtarma olmamasıyla çelişki bulunmaması
- 320 px, kısa ekran ve desktop görünümü
- Mevcut TalkX neon/glass temasının bozulmaması

### Android

- Gerçek cihaz/WebView'da aynı ürün anlamı
- Ürün metninin safe-area veya küçük ekranda ana aksiyonu itmemesi
- Gerçek handshake Origin değerinin kaydedilmesi
- Geçerli session, session expired ve yabancı origin davranışı

### Güvenlik

- Kontrollü local/staging istemciyle origin ve payload sınırları
- Reddedilen bağlantının active client/queue oluşturmaması
- Geçerli Web ve Android bağlantısının regresyonsuz çalışması
- Admin/static/legal sayfalarının header/CORS değişikliğinden bozulmaması

### Harici uyum kapısı

Kullanıcı veya yetkili insan inceleyici:

- Play Console hedef kitle/content rating/Data Safety ekranlarını doğrular,
- Bölge dağıtım durumunu kaydeder,
- Store açıklamasını canonical ürün vaadiyle karşılaştırır,
- Çocuk güvenliği owner/irtibat/escalation bilgisini doğrular,
- TR/EN legal içerik için insan incelemesi sonucunu kaydeder.

Bu kanıt olmadan C-COMP-001 canonical olarak kapanmaz; ancak Wave 01 Sale Release scope'u otomatik doğrulanıp commit edilebilir. Açık kanıt Wave 19'a taşınır.

## 10. Kanıt ve kabul eşlemesi

| Plan ref | Gerekli kanıt | Kapanış |
|---|---|---|
| A-PRD-001 | TR/EN diff, Web/Android ekran görüntüsü, manifest/store karşılaştırması, veri-anonimlik incelemesi | Plan A kabul kriterlerinin tamamı kanıtlı |
| B-SEC-001 | Test matrisi, dependency audit, origin/payload/auth sonuçları, log redaction örneği | Plan B kabul kriterlerinin tamamı kanıtlı |
| C-COMP-001 | Uyum matrisi, Play Console ekran kanıtı, owner/irtibat doğrulaması, insan legal incelemesi | Plan C kabul kriterlerinin tamamı kanıtlı |

Checkbox yalnız kanıtlanan canonical kabul kriteri için işaretlenir. Yerel kod tamamlanması harici uyum kanıtını otomatik kapatmaz.

## 11. Riskler ve rollback

| Risk | Koruma | Rollback |
|---|---|---|
| Android Origin beklenenden farklı | Önce gerçek cihaz handshake gözlemi; native allowlist explicit | Origin enforcement değişikliğini geri al, blanket allow açma |
| `maxPayload` 2 MB görseli kırar | Base64/envelope sınır testi | Önceki WS config'e dön, doğrulanmış üst sınırı yeniden hesapla |
| Guest fallback kaldırılması eski clientı kırar | Desteklenen sürüm ve session recovery testi | Güvenliği gevşetmeden feature/capability kararı için dur |
| Header/CORS admin/static yüzeyi kırar | Route bazlı smoke | Yalnız header/CORS değişikliğini geri al |
| Ürün metni hukuki iddia üretir | Veri akışı ve insan incelemesi | Son doğrulanmış metne dön |
| Dependency update regresyonu | Tek paket, lockfile diff ve davranış testi | Paket/lockfile değişikliğini geri al |
| Dirty repo kullanıcı işini örter | Başlangıç hash/status ve hedef dosya listesi | Yalnız Wave 01 farkını geri al; kullanıcı dosyasına dokunma |

## 12. Başlangıç kapısı

Wave 01 uygulamasına geçmeden önce:

- [x] Kullanıcı açıkça “Wave 01'i başlat” dedi.
- [x] Backend ve frontend repo başlangıç fotoğrafı hedef dosyalar için kaydedildi; ikisi de temiz ve `origin/main` ile 0/0 idi.
- [x] Web ve Android desteklenen originleri explicit allowlist + otomatik policy testiyle doğrulandı; gerçek cihaz handshake kontrolü Checkpoint A'ya ertelendi.
- [x] Canlı/harici panel işlemlerinin ayrıca onay istediği kabul edildi ve bu işlemler yapılmadı.
- [x] Wave 02 kapsamına taşma olmadığı tekrar kontrol edildi.

Bu kutular plan hazırlanırken işaretlenmez.

## 13. Sonuç alanı

- **Başlangıç zamanı:** 2026-09-23
- **Tamamlanan Plan refs:** A-PRD-001 Sale Release kapsamı; B-SEC-001'in guest/payload/origin/limit/header kriterleri; C-COMP-001 repo içi uyum başlangıcı ve A-PRD-001 çelişki kontrolü
- **Değişen dosyalar:** Backend güvenlik doğrulaması/testleri, HTTP input sınırları, global uyum matrisi ve canonical plan kapanışı; frontend TR/EN Splash/Home/manifest/store-copy kaynağı
- **Otomatik kanıt:** Backend syntax + 6/6 unit; frontend lint 0 error/9 warning; production build; frontend audit 0; backend audit 8 moderate transitive; text encoding; Capacitor sync/asset equality; Android Gradle unit test
- **Manuel QA:** Checkpoint A / Wave 19'a ertelendi
- **Harici uyum kanıtı:** Play Console, store listing, child-safety owner/escalation/contact ve TR/EN insan legal incelemesi `docs/TALKX_GLOBAL_COMPLIANCE_MATRIX.md` içinde açık eksik olarak kaydedildi
- **Kullanıcı onayı:** Wave 01 başlangıç/onay talimatı alındı; final manuel kabul Wave 19'a ertelendi
- **Wave durumu:** AUTO-VERIFIED / COMMITTED / MANUAL-QA-DEFERRED
- **Sonraki wave:** Başlatılmadı

## 14. Durma kuralı

Wave 01 Sale Release kapsamı uygulandı, otomatik doğrulandı ve manuel QA Checkpoint A / Wave 19'a ertelendi. Bu kapanıştan sonra:

- Wave 01 dışında kod, dependency, test hazırlığı veya refactor yapılmaz,
- Play Console veya canlı servis işlemi açık onay olmadan yapılmaz,
- Wave 02 ayrı açık kullanıcı talimatı olmadan aktive edilmez veya uygulanmaz,
- Wave 02 `Bekliyor` kalır.
