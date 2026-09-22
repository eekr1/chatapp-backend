# TalkX Sale Release Yürütme Sözleşmesi

Bu dosya, TalkX Sale Release wave'lerinin hangi çalışma alanında ve hangi Git sınırlarıyla yürütüleceğini tanımlar. Ürün kapsamının canonical kaynağı ilgili master plan, Plan A/B/C, Wave Map ve seçilmiş wave dosyasıdır; bu sözleşme ürün kararı eklemez.

## Çalışma alanı ve Git sınırları

- `C:\Users\Enis\Desktop\chatapp` yalnız **workspace/orchestration root** olarak kullanılır. Tek bir ürün reposu veya ortak commit kökü değildir.
- Bağımsız ana Git repoları:
  1. `chatapp-backend/`
  2. `chatapp-frontend/`
- Git durumu, diff, stage ve commit işlemleri her repo içinde ayrı yürütülür. Workspace root'tan toplu `git add .` veya ortak commit alınmaz.
- Backend ve frontend'i birlikte etkileyen bir wave'de değişiklikler repo bazında ayrılır. Her repo yalnız kendi dosyalarını içeren, aynı wave numarasını taşıyan ayrı bir commit alır.
- Kullanıcının wave öncesinde veya wave sırasında yaptığı unrelated değişiklikler sahiplenilmez, düzeltilmez, stage edilmez, commitlenmez ya da geri alınmaz.

## Canonical plan kaynağı

- Tek canonical plan kaynağı `chatapp-backend/Plans/` klasörüdür.
- Okuma sırası:
  1. `TALKX_MASTER_BACKLOG.md`
  2. `TALKX_WAVE_MAP.md`
  3. İlgili `TALKX_PLAN_A_PRODUCT_CLIENT.md`, `TALKX_PLAN_B_PLATFORM_REALTIME_DATA.md` ve `TALKX_PLAN_C_ADMIN_TRUST_RELEASE.md` stable ID'leri
  4. Yalnız açıkça başlatılmış `waves/TALKX_WAVE_NN.md`
  5. Güncel repo, kod, test ve ortam kanıtı
- Workspace root'taki `Plans/` canonical değildir. Varsa duplicate/stale yerel kopya olarak değerlendirilir; plan okuması, düzenlemesi veya karar üretimi için kullanılmaz.
- Root `Plans/` yeniden canonical klasörden kopyalanmaz veya senkron tutulmaz. Güvenli olduğunda kaldırılabilir; kaldırma işlemi ayrı ve açık kullanıcı talimatı gerektirir.

## Wave aktivasyonu ve yürütme akışı

- Bir wave yalnız kullanıcı açıkça **“Wave NN'i başlat”** dediğinde aktif olur. Hazır bir wave dosyasının varlığı aktivasyon sayılmaz.
- Aktif wave için zorunlu sıra:
  1. Seçilen wave kapsamını ve repo başlangıç durumunu doğrula.
  2. Yalnız wave kapsamındaki implementasyonu yap.
  3. Zorunlu otomatik doğrulamaları çalıştır ve sonuçları kaydet.
  4. Yalnız wave dosyalarını ilgili repo veya repolarda stage et.
  5. Her etkilenen repoda wave numarasını açıkça taşıyan ayrı commit oluştur.
  6. Commit kimliklerini ve otomatik doğrulama sonucunu raporla.
  7. Dur.
- Backend/frontend cross-repo wave'lerinde tek ortak commit oluşturulmaz. Örneğin iki repo da etkilenmişse backend ve frontend ayrı ayrı `Wave NN` commit'i alır.
- Otomatik doğrulama başarısızsa başarısızlık gizlenmez; kapsam içi düzeltme ve yeniden doğrulama yapılır. Güvenli biçimde kapatılamıyorsa commit alınmadan durulur ve blocker raporlanır.
- Manuel QA, Wave 01–18 için implementasyon sonrası ilerleme kapısı değildir; ilgili wave'in checkpoint kaydına ve/veya final Wave 19 Sale Acceptance QA aşamasına ertelenir.
- Bir wave'in tamamlanması sonraki wave'i başlatmaz. Sonraki wave için yeni ve açık kullanıcı talimatı beklenir; hazırlık, refactor veya ön implementasyon yapılmaz.

## Yetki ve geri döndürülemez işlemler

- Kod ve plan değişikliği yetkisi; live deploy, production veritabanı işlemi, Play Console değişikliği, secret/credential işlemi veya legal içeriğin canlı yayımlanması için yetki sayılmaz.
- Aşağıdaki işlemler uygulanmadan hemen önce açık kullanıcı onayı gerekir:
  - live deploy, production restart veya production config değişikliği;
  - production veritabanında migration, veri yazma/silme, restore veya cutover;
  - Google Play Console yükleme, rollout, release veya mağaza ayarı;
  - secret, token, credential ya da canlı environment variable ekleme/değiştirme;
  - privacy policy, terms, child safety veya başka legal içeriğin canlı yayımlanması.
- Bu işlemler wave planında yazıyor olsa bile otomatik yetkilendirilmiş sayılmaz. Onay verilmezse uygulanmaz; yalnız gerekli checkpoint ve manuel adım olarak raporlanır.

## Kapanış kontrolü

Wave kapanmadan önce şu koşullar birlikte doğrulanır:

- Değişiklikler yalnız aktif wave kapsamındadır.
- Unrelated kullanıcı değişiklikleri stage veya commit edilmemiştir.
- Otomatik doğrulamalar çalıştırılmış ve sonuçları raporlanmıştır.
- Her etkilenen repo kendi wave-numaralı commit'ine sahiptir.
- Manuel QA açıkça deferred/checkpoint olarak kaydedilmiştir.
- Yetki gerektiren canlı işlem izinsiz yapılmamıştır.
- Sonraki wave başlatılmamıştır.

