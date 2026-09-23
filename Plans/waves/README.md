# TalkX Wave Planları

> Bu klasör, canonical `TALKX_WAVE_MAP.md` içindeki 19 wave'in ayrıntılı uygulama planlarını taşır. Dosyanın varlığı wave'i aktif etmez.

> **Sale Release yürütme kuralı:** Kullanıcı wave'i açıkça başlatır; yalnız ilgili Sale Release override kapsamı uygulanır, zorunlu otomatik kontroller çalışır, tek wave commit'i alınır ve işlem durur. Manuel QA Wave 01–18 için ilerleme kapısı değildir; checkpoint/Wave 19 havuzuna taşınır.

## Canonical yapı

- Toplam wave sayısı: **19** (`01`–`19`).
- Dosya adı: `TALKX_WAVE_NN.md`.
- Sıra, Plan A/B/C katılımı ve wave durumu: `../TALKX_WAVE_MAP.md`.
- Ayrıntılı kapsam ve kabul kriterleri: ilgili `../TALKX_PLAN_A_PRODUCT_CLIENT.md`, `../TALKX_PLAN_B_PLATFORM_REALTIME_DATA.md` ve `../TALKX_PLAN_C_ADMIN_TRUST_RELEASE.md` stable ID'leri.
- Bu klasör yeni ürün kararı üretmez ve plan metinlerini kopyalamaz.

## Agent okuma sırası

1. `../TALKX_MASTER_BACKLOG.md`
2. `../TALKX_WAVE_MAP.md` — Sale Release scope ve yürütme override'ı
3. İlgili Plan A/B/C stable ID'leri
4. Yalnız seçilen `TALKX_WAVE_NN.md`
5. Güncel repo, kod, test ve ortam kanıtı

## Dosya envanteri

| Wave | Dosya | Plan katılımı | Hazırlık | Aktivasyon |
|---:|---|---|---|---|
| 01 | `TALKX_WAVE_01.md` | Plan A + Plan B + Plan C | Hazır | Aktif değil |
| 02 | `TALKX_WAVE_02.md` | Plan B + Plan C | Hazır | Aktif değil |
| 03 | `TALKX_WAVE_03.md` | Plan A | Hazır | Aktif değil |
| 04 | `TALKX_WAVE_04.md` | Plan B + Plan C | Hazır | Aktif değil |
| 05 | `TALKX_WAVE_05.md` | Plan B + Plan A | Hazır | Aktif değil |
| 06 | `TALKX_WAVE_06.md` | Plan B + Plan C | Uygulandı | Auto-verified / committed / QA deferred |
| 07 | `TALKX_WAVE_07.md` | Plan B + Plan A | Hazır | Aktif değil |
| 08 | `TALKX_WAVE_08.md` | Plan B + Plan A + Plan C | Hazır | Aktif değil |
| 09 | `TALKX_WAVE_09.md` | Plan B + Plan A | Hazır | Aktif değil |
| 10 | `TALKX_WAVE_10.md` | Plan B + Plan A | Hazır | Aktif değil |
| 11 | `TALKX_WAVE_11.md` | Plan B + Plan C + Plan A | Hazır | Aktif değil |
| 12 | `TALKX_WAVE_12.md` | Plan C + Plan B + Plan A | Hazır | Aktif değil |
| 13 | `TALKX_WAVE_13.md` | Plan B + Plan A + Plan C | Hazır | Aktif değil |
| 14 | `TALKX_WAVE_14.md` | Plan B + Plan C | Hazır | Aktif değil |
| 15 | `TALKX_WAVE_15.md` | Plan C | Hazır | Aktif değil |
| 16 | `TALKX_WAVE_16.md` | Plan B + Plan C | Hazır | Aktif değil |
| 17 | `TALKX_WAVE_17.md` | Plan A + Plan B + Plan C | Hazır | Aktif değil |
| 18 | `TALKX_WAVE_18.md` | Plan C + Plan A | Hazır | Aktif değil |
| 19 | `TALKX_WAVE_19.md` | Plan C | Hazır | Aktif değil |

Boş şablon veya placeholder wave dosyaları oluşturulmaz. Her wave dosyası, kullanıcı o wave'in yazılmasını açıkça istediğinde hazırlanır ve o dosya tamamlandıktan sonra durulur.

## Hazırlık ve aktivasyon ayrımı

- **Hazır:** Wave dosyası yazılmış ve canonical planlarla tutarlı biçimde kontrol edilmiştir.
- **Aktif:** Kullanıcı ayrıca açıkça o wave'i başlatmıştır.
- Hazır bir wave, kendiliğinden aktif olmaz.
- Aktivasyonda plan, repo gerçeği ve önceki wave kapanışı yeniden doğrulanır.
- Aynı anda yalnız bir wave aktif olabilir.
- Wave 01–18 için önceki wave **AUTO-VERIFIED / COMMITTED / MANUAL-QA-DEFERRED** olduğunda teknik ön koşul sağlanır; sonraki wave yine yalnız kullanıcının ayrı açık talimatıyla başlar.
- Wave 16 ürün implementasyonu değil, **PAS / Post-acquisition Roadmap** kaydıdır.
- Wave 19 terminal **Sale Acceptance QA + Release Freeze** aşamasıdır.
- Canonical Plan A/B/C'de kanıtlanmayan veya deferred kriterler açık kalır; roadmap kapsamı silinmez ve yanlış biçimde tamamlanmış işaretlenmez.

## Her wave dosyasının zorunlu iskeleti

1. Durum ve yürütme sınırı
2. Sıralı Plan refs
3. Beklenen sonuç
4. Başlangıç fotoğrafı ve bağımlılık doğrulaması
5. Sıralı iş paketleri
6. Dosya/servis etki alanı
7. Açık kapsam dışı maddeler
8. Otomatik kanıt kapıları
9. Checkpoint/Wave 19 havuzuna taşınacak manuel QA
10. Risk, rollback ve canlı işlem yetkileri
11. Otomatik sonuç/evidence, tek commit kimliği ve ertelenmiş QA kaydı
12. “Sonraki wave başlatılmadı” koruması

## Mevcut durma noktası

Wave 01–06 Sale Release kapsamları auto-verified/committed/manual-QA-deferred kapanışındadır. Wave 07–19 hazır fakat aktif değildir; hiçbir wave aktif değildir. Sonraki uygulama adımı yalnız açık **“Wave 07'yi başlat”** talimatıdır.
