# TalkX Monetizasyon: Eşleşme Hakkı ve Ödüllü Reklam

Bu belge, TalkX backend'inin iki ticari kuralını tanımlar: **günlük eşleşme hakkı (kota)** ve **AdMob ödüllü reklam ile hak kazanma**. Kural, JSON sözleşmesi ve ödül güvenlik modeli tek kaynaktan (`utils/matchQuota.js`, `utils/adRewards.js`) gelir; frontend bu sözleşmeyi tek taraflı değiştiremez.

Kurulum ve genel mimari için `README.md`, PC barındırma için `ops/windows/README.md` dosyasına bakın.

## 1. Eşleşme hakkı (kota) kuralları

### Hak nedir, ne zaman tüketilir

Hak, **başarıyla kurulmuş rastgele eşleşme** için birimdir. Her eşleşme her iki taraf için birer hak düşer.

| Durum | Hak tüketimi |
|---|---|
| Eşleşme başarıyla finalize oldu | **Evet**, taraf başına 1 hak |
| Arama başarısız oldu / zaman aşımı | Hayır |
| Kullanıcı aramayı iptal etti | Hayır |
| Sunucu kaynaklı yeniden kuyruk (requeue) | Hayır (yalnız yeni hak olup olmadığı kontrol edilir) |
| Arkadaş mesajlaşması, DM | Hayır, arkadaşlık hiçbir zaman kotayla sınırlanmaz |

Kontrol iki aşamalıdır:

1. **Kuyruğa giriş (`canStartSearch`)**: yeni bir hak bulunup bulunmadığına bakılır. Bulunamazsa istemciye `search_error` / `MATCH_QUOTA_EXHAUSTED` gönderilir.
2. **Tüketim (`consumeMatch`)**: yalnız eşleşme finalize edildiğinde, atomik ve öncelikli sırayla bir hak düşülür. Tüketim hatası eşleşmeyi bozmaz; eşleşme korunur ve hata loglanır.

### Hak kaynakları ve öncelik

Tüketim sırası: **welcome → daily → bonus**. Her bucket kendi `UPDATE ... WHERE` koşuluyla korunur, bu yüzden eşzamanlı tüketiciler aynı birimi iki kez alamaz.

| Bucket | Kaynak | Davranış |
|---|---|---|
| `welcome_remaining` | `MATCH_WELCOME_FREE` | İlk kota satırı okunduğunda bir kez verilir. Varsayılan `0` (kapalı) |
| `daily_used` / günlük | `MATCH_DAILY_FREE` | Günlük ücretsiz hak. Varsayılan `30`. **Üst üste binmez** |
| `bonus_balance` | `AD_REWARD_MATCHES` | Doğrulanmış ödüllü reklamla kazanılır. **Birikir**, günlük kap ile sınırlı değildir |

### Gün sınırı

- Gün anahtarı `Europe/Istanbul` saat dilimine göre üretilir (`YYYY-MM-DD`), sıfırlama o gece yarısında olur.
- Uygulama `Intl.DateTimeFormat` kullanır; ileride saat dilimi ofseti değişse bile gün anahtarı ve sıfırlama anı doğru kalır.
- Yeni gün, ilk okumada **lazy reset** ile uygulanır: `daily_used` ve `ads_today` sıfırlanır; `welcome_remaining` ve `bonus_balance` korunur.
- `resetsAt` alanı bir sonraki sıfırlamanın ISO tarihini döner.

### Günlük reklam ödülü tavanı

`AD_DAILY_MAX` (varsayılan `5`), kullanıcı başına günde alınabilecek ödüllü reklam ödülü sayısını sınırlar. Tavan hem `POST /api/ads/reward-session` isteğinde (`rewardedAvailable`), hem de SSV kredilendirmesinde (`UPDATE ... WHERE ads_today < cap`) ayrıca korunur; eşzamanlı geri çağırmalar tavanı aşamaz.

### Kotaları kapatma

`MATCH_QUOTA_ENABLED=false` yapıldığında **hiçbir** kontrol yapılmaz, veritabanına yazılmaz ve davranış bu özellikten önceki hâle döner. Bu, özelliği geri almak veya kademeli açmak için kullanılan anahtardır.

### Kota nesnesi sözleşmesi

`GET /api/match-quota` ve WS `quota_update` olayı aynı nesneyi döner:

```json
{
  "quota": {
    "enabled": true,
    "welcomeRemaining": 0,
    "dailyLimit": 30,
    "dailyUsed": 3,
    "dailyRemaining": 27,
    "bonusBalance": 6,
    "totalRemaining": 33,
    "resetsAt": "2026-11-20T21:00:00.000Z",
    "adsToday": 1,
    "adsDailyMax": 5,
    "rewardPerAd": 3,
    "rewardedAvailable": true
  }
}
```

`rewardedAvailable`, SSV açıkken ve günlük reklam tavanı dolmadıysa `true` olur.

## 2. Akış diyagramı (metin)

```text
                    ┌────────────────────────────────┐
                    │  İstemci: ödüllü reklam göster  │
                    └───────────────┬────────────────┘
                                    │
                     POST /api/ads/reward-session
                                    │
                    ┌───────────────▼────────────────┐
                    │  Backend: kota kontrolü        │
                    │  adsToday < AD_DAILY_MAX ?      │
                    │   hayır → 409 AD_LIMIT_REACHED  │
                    │   evet ↓                        │
                    │  nonce üret (TTL 30 dk)         │
                    │  ad_reward_sessions'a yaz        │
                    │  { nonce, expiresAt } dön       │
                    └───────────────┬────────────────┘
                                    │
                    ┌───────────────▼────────────────┐
                    │  AdMob ödüllü video oynatılır    │
                    │  custom_data = nonce             │
                    └───────────────┬────────────────┘
                                    │
                 Google → GET /api/ads/admob-ssv?...
                                    │
                    ┌───────────────▼────────────────┐
                    │  SSV doğrulama                   │
                    │  1) zorunlu paramlar var mı?    │
                    │  2) ad_unit izinli mi?          │
                    │  3) imza (ECDSA) geçerli mi?    │
                    │  4) nonce geçerli ve kullanılmamış│
                    │  5) transaction_id yeni mi?      │
                    └───────────────┬────────────────┘
                                    │ geçerli
                    ┌───────────────▼────────────────┐
                    │  Tek transaction:                │
                    │  ad_reward_ledger'a ekle (UNIQUE)│
                    │  match_quota.bonus_balance += N  │
                    │  ads_today += 1                  │
                    │  nonce'yi kullanıldı işaretle    │
                    │  COMMIT → bonus haklar eklendi   │
                    └────────────────────────────────┘
```

Eşleşme tarafı:

```text
joinQueue → canStartSearch (hak var mı?)
              hayır → WS search_error / MATCH_QUOTA_EXHAUSTED
              evet  → kuyruğa gir
                        ↓
              eşleşme finalize edilir
                        ↓
              consumeMatch: welcome → daily → bonus (1 birim)
                        ↓
              WS quota_update (yeni kota nesnesi)
```

## 3. SSV güvenlik modeli

`GET /api/ads/admob-ssv` kimlik doğrulaması olmayan, Google'ın çağırdığı uçtur. Güvenlik dört katmanlıdır:

1. **İmza doğrulama.** AdMob, imzalanmış sorgu dizesini gönderir. Sunucu, `signature` parametresi çıkarılmış **ham** sorgu dizesini Google'ın doğrulama anahtarlarıyla ECDSA/SHA-256 üzerinden doğrular. Segmentler decode/re-encode edilmez, böylece yüzde kodlama bayt bayt korunur. Anahtarlar `https://www.gstatic.com/admob/reward/verifier-keys.json` adresinden çekilir ve `ADMOB_SSV_KEY_CACHE_TTL_MS` süresince önbelleklenir. Anahtar `key_id` ile daraltılabilir; daraltma sonucu eşleşmezse doğrulama başarısızdır.
2. **Nonce (tek kullanımlık oturum).** Ödül yalnızca `POST /api/ads/reward-session` ile üretilmiş, süresi dolmamış, kullanılmamış ve `user_id` ile eşleşen bir nonce ile kredilendirilebilir. Nonce'lar `ad_reward_sessions` tablosunda tutulur, TTL 30 dakikadır. Bir kullanıcının canlı nonce sayısı 3 ile sınırlıdır; taşma durumunda en eski nonce geçersiz kılınır (yeni nonce'a yer açılır). Kullanılmış nonce ikinci kez kabul edilmez.
3. **Ledger (idempotenslik).** `ad_reward_ledger.transaction_id` UNIQUE'dir. Aynı `transaction_id` ile gelen ikinci geri çağırma `duplicate_transaction` olarak reddedilir ve hiçbir hak yazılmaz. Yazma tek bir transaction içinde yapılır: ledger kaydı, bonus kredisi ve nonce'in kullanıldı işaretlenmesi **ya hep ya hiç**.
4. **Birim ve kapsam denetimi.** Yalnızca `ADMOB_REWARDED_AD_UNITS` içindeki ad unit'leri kabul edilir (liste boşsa herhangi biri). `reward_amount` AdMob'dan gelir, geçersizse `AD_REWARD_MATCHES` kullanılır. Kredi yazımı `ads_today < AD_DAILY_MAX` koşuluyla korunur, tavan aşılamaz.

### HTTP durum eşlemesi

| Sonuç | HTTP | Anlam |
|---|---|---|
| Hak kredilendi | `200` | `{"success": true}` |
| Kesin geçersiz (parametre eksik, imza geçersiz, nonce geçersiz/kullanılmış, `transaction_id` yinelenmiş, ad unit izinsiz, günlük tavan dolu, SSV kapalı) | `200` | `{"success": false, "reason": "..."}` — AdMob **tekrar denemez**, hak verilmez |
| Geçici hata (doğrulama anahtarları alınamıyor) | `503` | `{"success": false, "retryable": true}` — AdMob sonra **tekrar dener** |
| Beklenmeyen sunucu/DB hatası | `503` | `{"success": false, "reason": "server_error", "retryable": true}` |

Ayrımın nedeni: `200` dönmek AdMob'ın "teslim edildi, işlem tamamlandı" demesidir. Kesin reddedilmiş bir ödülü tekrar denetmek anlamsız; geçici bir altyapı hatasını ise `200` ile kapatmak ödülü kalıcı olarak kaybettirir.

Ayrıca SSV uç kendi hız sınırlayıcısına sahiptir (10 dakika / 120 istek, IP başına) ve `/api` genel limiter'ının üstüne biner.

### `ADMOB_SSV_ENABLED=false` iken

Uç çalışmaya devam eder ama hiçbir hak yazmaz: `ssv_disabled` sebebiyle `200` döner. Böylece AdMob tarafında "callback ulaşmıyor" hatası oluşmaz, ürün kapalıyken de test edilebilir.

## 4. AdMob panel ayarları

AdMob konsolunda ödüllü reklam (Rewarded) ad unit'i ve Server-Side Verification (SSV) şu şekilde yapılandırılır:

| Alan | Değer |
|---|---|
| SSV callback URL'si | `https://api.talkx.chat/api/ads/admob-ssv` |
| Method | `GET` |
| `custom_data` (nonce) | `POST /api/ads/reward-session` yanıtındaki `nonce` değeri |
| `user_id` | TalkX kullanıcı kimliği (backend'in SSV doğrulamasında nonce sahibiyle eşleştirilir) |
| Ödüllü reklam ad unit id | `4754991352` |
| Reward amount | `3` (`AD_REWARD_MATCHES` ile aynı olmalı) |

Backend tarafında aynı ad unit `ADMOB_REWARDED_AD_UNITS=4754991352` olarak tanımlanır. Tam ad unit biçimi (`ca-app-pub-…/4754991352`) da kabul edilir.

> AdMob panelindeki SSV URL'si ile backend'in `ADMOB_REWARDED_AD_UNITS` listesi **birebir aynı ad unit'i** göstermelidir; aksi halde SSV `ad_unit_not_allowed` ile 200 döner ve ödül gelmez.

Callback URL'si HTTPS olmalı ve uç `GET` ile erişilebilir olmalıdır. Kimlik doğrulama istenmez; imza doğrulaması güvenliği sağlar.

## 5. İşletim notları

### Ödül gelmiyorsa nereye bakılır

1. **Backend logları.** `C:\TalkX\logs` altındaki servis logunda `admob ssv callback not credited` satırlarını arayın. `reason` alanı doğrudan nedeni söyler:
   - `ssv_disabled` → `ADMOB_SSV_ENABLED` açık değil.
   - `invalid_params` → `signature`, `transaction_id`, `custom_data` veya `user_id` eksik; istemci nonce'u `custom_data` olarak göndermiyor.
   - `ad_unit_not_allowed` → AdMob panelindeki ad unit ile `ADMOB_REWARDED_AD_UNITS` eşleşmiyor.
   - `signature_invalid` → imza doğrulanamadı. Sorgu dizesi istemci/SDK tarafında bozulmuş olabilir ya da doğrulama anahtarı önbelleği eskimiş olabilir.
   - `nonce_invalid` → nonce süresi dolmuş (30 dk), kullanılmış veya `user_id` eşleşmiyor.
   - `duplicate_transaction` → aynı ödül ikinci kez gönderilmiş; hak zaten verilmiş demektir.
   - `keys_unavailable` → Google doğrulama anahtarlarına ulaşılamıyor; sunucu 503 döndüğü için AdMob tekrar deneyecektir.
   - `AD_LIMIT_REACHED` → günlük ödül tavanı doldu.
2. **Veritabanı.** `ad_reward_sessions` içindeki nonce'in `used_at` ve `expires_at` değerlerini kontrol edin; `ad_reward_ledger` içinde ilgili `transaction_id` kaydı varsa ödül verilmiş demektir.
3. **Kota.** `GET /api/match-quota` çıktısında `bonusBalance`, `adsToday` ve `adsDailyMax` değerlerini kontrol edin.
4. **AdMob paneli.** SSV callback URL'si, `custom_data` gönderimi, ödül değeri ve günlük raporlanan SSV başarısızlık oranı.
5. **Kota tükenmesi.** `MATCH_QUOTA_EXHAUSTED` alan istemcide "hak kalmadı" anlamına gelir; `GET /api/match-quota` ile hangi bucket'ın tükendiği görülür.

### Sık karşılaşılan durumlar

- **Ödül hakkı artıyor ama eşleşme başlatılamıyor.** Kota kontrolü toplam (`welcome + daily + bonus`) üzerinden yapılır. Bonus varsa toplam sıfır olamaz; `MATCH_QUOTA_ENABLED` kapalıysa kontrol hiç yapılmaz.
- **Günlük hak "erken" sıfırlanıyor.** Sıfırlama `Europe/Istanbul` gece yarısındadır; `resetsAt` alanı bunu doğrular.
- **SSV 503 döndürüyor.** 503 "kalıcı ret" değildir; AdMob tekrar denemesi beklenir. Kalıcı 503 ise veri tabanı veya anahtar erişimi sorununa işaret eder.
- **Ödül iki kez sayılmıyor.** Ledger UNIQUE kısıtı ve nonce'in tek kullanımlılığı sayesinde her `transaction_id` en fazla bir kez kredilendirilir.

### Güvenlik notları

- SSV uçundaki hız sınırı kötüye kullanımı sınırlar; uç imza doğrulaması olmadan hiçbir hak yazmaz.
- Bonus haklar `match_quota.bonus_balance` içinde birikir; ödül kötüye kullanımı günlük tavanla sınırlıdır.
- Secret değerleri (doğrulama anahtarları, `DATABASE_URL`, admin parolası) hiçbir dokümana veya loga yazılmaz.

## 6. Yapılandırma özeti

| Değişken | Varsayılan | Etki |
|---|---|---|
| `MATCH_QUOTA_ENABLED` | `true` | `false` → tüm kota kontrolleri kapanır |
| `MATCH_WELCOME_FREE` | `0` | Tek seferlik hoş geldin hakkı |
| `MATCH_DAILY_FREE` | `30` | Günlük ücretsiz hak |
| `AD_REWARD_MATCHES` | `3` | Video başına eklenen bonus hak |
| `AD_DAILY_MAX` | `5` | Günlük ödül tavanı |
| `ADMOB_SSV_ENABLED` | `false` | `true` → SSV hak krediler |
| `ADMOB_REWARDED_AD_UNITS` | boş | İzinli ödüllü ad unit'leri (`4754991352`) |
| `ADMOB_SSV_KEY_CACHE_TTL_MS` | `86400000` | Anahtar önbellek ömrü |
| `ADMOB_SSV_VERIFIER_KEYS_URL` | Google resmi | Doğrulama anahtarı kaynağı |
| `REQUIRE_AGE_CONFIRMATION` | `false` | `true` → 18+ onayı zorunlu (geçiş dönemi) |
