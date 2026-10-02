# TalkX Backend Kaynak Paketi

Bu arşiv, TalkX API/WebSocket servisi ile yönetim panelinin alıcıya devredilecek çalıştırılabilir kaynak paketidir.

## Bilinçli olarak dahil edilmeyenler

- İç test ve regresyon klasörleri
- Wave durumları, tarihsel planlar ve ekip çalışma notları
- CI/quality gate tanımları ve görsel inceleme kanıtları
- `.env`, Firebase service-account, veritabanı dökümü ve kullanıcı verisi
- `node_modules`, build çıktıları ve yerel cache dosyaları

Bu öğelerin hariç tutulması ürünün runtime kaynak kodunu veya normal başlatma akışını değiştirmez. Satış öncesi test sonuçları ve teknik doğrulama kanıtları ayrı due-diligence dosyalarında sunulur.

## Başlangıç

1. `.env.example` dosyasını `.env` olarak kopyalayın.
2. Buyer-owned PostgreSQL, Firebase ve support bilgilerini tanımlayın.
3. `npm ci` çalıştırın.
4. Migration durumunu kontrol edin ve gerekli migration'ları uygulayın.
5. `npm start` ile servisi başlatın; `/health/live` ve `/health/ready` uçlarını doğrulayın.

Gerçek üretim credential'ları bu kaynak arşivine dahil değildir ve kapanışta buyer-owned değerlerle oluşturulmalıdır.

Bağımlılık ve lisans özeti için `THIRD_PARTY_NOTICES.md` dosyasına bakın.
