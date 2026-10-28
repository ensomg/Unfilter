# ADR 001 — Hot path: dedicated thread + SPSC halka kuyruk

**Durum:** Kabul (Faz 0)

**Karar:** Paket yolu (capture → engine → inject) tokio dışında, dedicated OS thread'lerinde çalışır. Thread'ler arası iletişim `rtrb` (wait-free SPSC ring buffer) ile, yalnızca buffer indeksi taşınarak yapılır.

**Gerekçe:**
- WinDivert `recv` bloklayan bir çağrıdır; async sarmalayıcı ek gecikme ve thread havuzu yükü getirir.
- SPSC yeterli: her aşama tek üretici, tek tüketici. MPMC (crossbeam) gereksiz CAS maliyeti ekler.
- `rtrb` küçük, bağımlılıksız, `unsafe`'i kendi içinde kapsüllenmiş.

**Sonuç:** Engine thread'i kontrol mesajlarını (strateji değişimi, config yenileme) ayrı bir `std::sync::mpsc` kanalından, paket döngüsünde bloklamadan (`try_recv`) okur.

**Alternatifler:** tokio + `spawn_blocking` (ret: gecikme ve bellek), tek thread (Faz 1 başlangıcında kabul edilebilir sadeleştirme, ölçümle ayrılır).
