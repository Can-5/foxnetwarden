# FoxNetwarden — Tasarım / Design

**Tarih:** 2026-11-18 · **Yazar:** OpenCode + Can-5 · **Durum:** kararlar işlendi — onay bekliyor (builder check 2026-11-18'de yapıldı, cevaplar aşağıda)

**FoxNetwarden — Linux masaüstü için local-first kişisel ağ güvenlik duvarı** *(Little Snitch / LuLu for Linux, fox-* el evinden).*

## Builder check kararları (kullanıcı cevapları, 2026-11-18)

1. **Alan adı engelleme** — alan → IP/CIDR çöz, nft set'e yaz, arka planda periyodik yeniden çözme. CDN'lerde kısmen kaçar; dürüst sınırlama.
2. **Arka plan** — tray + libnotify bildirimi; otomatik başlangıç ayarlarda aç/kapat (varsayılan kapalı). "Anında haberdar" sözü ancak tray'de çalışırken geçerli.
3. **Yetki** — HER engelleyici eylemde pkexec parolası (kullanıcı seçimi). Polkit oturum güveni yok.
4. **Kill switch** — her şeyi kes: established dahil, LAN/loopback/DNS/IPv6 dahil tüm giden trafik düşer. Allow kuralları kill switch'i delemez. Oturumluk (uygulama çıkışında geri alınır).
5. **DNS** — opt-in root'lu seçenek: systemd-resolved debug log (`resolvectl log-level debug`) journal'dan okunur; reboot'ta kapanır. Kapalıyken DNS ekranı "görünmez" dürüst modu gösterir.

Bunlara ek olarak makine kesifi (2026-11-18): **Fedora 45 (KDE Plasma)**, systemd-resolved aktif (stub, nameserver 127.0.0.53, DNS 192.168.1.1), nft mevcut (root gerekir), pkexec mevcut, DoH kullanan tarayıcılar resolved'i bypass eder (DNS görünürlüğünün sınırı). Paket önceliği: **.rpm (ana)** — Fedora'da native — + .deb + AppImage.

## Amaç ve neden

Makinemde hangi uygulamanın nereye bağlandığını görmek, beklenmedik bağlantılardan anında haberdar olmak, şüpheli olanları engellemek ve istersem tüm ağı tek tuşla kesmek istiyorum — hesabı olmayan, buluta konuşmayan, verisi yerelde kalan bir araç. Kullanıcı: Can-5 (Linux masaüstü, geliştirici).

## Faz 1 hedefleri

1. **Gerçek zamanlı ağ trafiği** — aktif bağlantılar listesi (yerel→uzak IP:port, süreç adı/pid, durum), periyodik yenileme, bağlantı hızı/sayısı.
2. **Uygulama bazlı internet izinleri** — gözlemleme + "şu uygulamaya izin ver / hedefe engelle" kuralları. Faz 1'de engelleme hedef/domain bazlı yapılır: domain → periyodik yeniden çözülen IP/CIDR nft set. Uygulama-adına-özel engelleme (cgroup eBPF) Faz 2.
3. **Şüpheli bağlantı tespiti** — yerel sezgisel kurallar: bilinen tracker/reklam alan adları, bilinen kötü amaçlı IP/alan blok listeleri (yerel blocklist dosyaları, çevrimdışı çalışır), anormal davranış (tek süreçten çok hedef, DNS dışı port 53 dışında DNS trafiği vb.).
4. **DNS ve IP izleme** — varsayılan: "görünmez" dürüst modu (DoH uyarısı). Ayarlardan açılan root'lu seçenek: systemd-resolved debug log journal'dan okunur (opt-in; reboot'ta kapanır). DNS + IP/port analizi; dış blok listeleri yerele kopyalanmaz — paket içinde statik.
5. **Firewall yönetimi** — nftables tablosu/kuralları görüntüleme/ekleme (engelle/izin ver), etkin
6. **Bağlantı geçmişi ve analiz** — SQLite'a kayıt; top hedefler, top uygulamalar, zaman çizelgesi, günlük sayılar.
7. **Tracker ve telemetri tespiti** — açık kaynak blocklist'ler (ör. hosts/ads listeleri) ile alan adı eşleme; yerel "suspicious" hissini UI'da turuncu olarak işaretle.
8. **Kill switch** — tek tuşla HERŞEYİ kes: yeni + established bağlantılar, LAN/loopback, DNS, IPv6 dahil tüm giden trafik düşer (nftables `drop` önceliği). Allow kuralları delmez. Oturumluk: uygulama çıkışında tablo geri alınır; crash'te `nft delete table inet foxnetwarden` ile elle temizlenir (README'de yazılı). UI'da büyük durum göstergesi.

## Hedef dışı / kapsam dışı

- Bulut servisi, hesap, telemetri, dışarıya veri gönderme.
- Windows/macOS desteği.
- eBPF tabanlı süreç-başına engelleme (Faz 2); uygulama bazlı izin = kuralların uygulamaya "atfedilmiş" görünümü + hedefe engelleme.
- Paket içeriğini inceleme / TLS çözme.

## Kısıtlar ve dürüst sınırlar

- **Root gerekir**: DNS debug log ve tüm nftables yazmaları pkexec ile parola ister — **kullanıcı kararı: her engelleyici eylemde parola**. Kök/parola yoksa salt-gözlem modu.
- Uygulama adı görünürlüğü `ss -tunp`'in iznine bağlıdır (aynı uid süreçleri görünür; diğer uid'ler `?` olur).
- Blocklist ilk açılışta pakete gömülü statik dosyadan yüklenir; internetten otomatik güncelleme Faz 2.
- GUI WebKit2GTK penceresi açılır; başsız ortamda Rust tarafı CLI/testlerle doğrulanır, pencere testi atlar.
- **Arka plan davranışı** (kullanıcı kararı): tray ikonu + şüpheli bağlantıda libnotify bildirimi; otomatik başlatma ayarda aç/kapa (varsayılan kapalı). Uygulama tray'deyken canlıyken bildirimler güvenir; pencere kapalıyken de izleme devam eder.
- **DoH sınırı**: tarayıcılar (Firefox/Chrome) DoH kullanır, resolved'i atlar; DNS ekranı bunu dürüstçe gösterir.

## Yaklaşımlar (değerlendirilen)

1. **A — Tauri v2 + Rust çekirdek + vanilla JS UI (seçilen)**: ev tarzı (Sextant/Kurgu/Fox Notes), hızlı, tek binary, paketlenebilir (.deb/.rpm/AppImage), kök çağrıları Rust tarafında.
2. **B — egui (FoxVault tarzı)**: saf Rust GUI, WebKit gerekmez ama UI zenginliği düşük; webview ekosistemi ev tarzına uyar.
3. **C — Electron**: ağır, Faz 1 için gereksiz.

## Mimari / parçalar

- `src-tauri/` — Rust: `collector` (ss/conntrack/`/proc` ayrıştırma), `dnslog` (resolved journal **opt-in debug log** ayrıştırıcı (`journalctl -u systemd-resolved`); kapalıysa "görünmez" modu), `firewall` (nftables sarmalayıcı: tablo `foxnetwarden`, zincirler `killswitch` (her şeyi drop) + `block`; pkexec her engelleyici çağrıda), `domainblock` (alan → periyodik IP/CIDR çözme → nft set), `db` (SQLite: bağlantı geçmişi, ayarlar, kurallar), `blocklist` (gömülü domain/ip listeleri eşleştirici, case-insensitive + subdomain wildcard), `analyzer` (sezgisel şüphe puanlaması), `tray` (tray + libnotify + otostart toggle ~/.config/autostart), Tauri komutları: `fw_status`, `live_connections`, `history_query`, `rule_add/remove`, `killswitch_set`, `blocklist_stats`, `top_talkers`, `dns_mode`.
- `web/` — UI: ana ekran = Canlı, Analiz, DNS, Kurallar (**constrained form**: blok/izin + hedef/CIDR/port — serbest nft metni YOK), Kill Switch, Ayarlar (yenileme hızı, blocklist, otostart, DNS debug log toggle).
- Gizlilik: hiçbir veri dışarı çıkmaz; dışa aktar = JSON.

## Test stratejisi

Rust tarafında `cargo test`: ss çıktısı ayrıştırıcı, DNS/IP/blocklist eşleştirici (exact + wildcard + case), şüphe puanlayıcı, kural doğrulayıcı (nft syntax string üretme), tarih/zaman sorguları. Entegrasyon: geçici nftables tablosu (root varsa), yoksa açıkça `SKIPPED (needs root)`. UI duman testi yok (headless); UI doğrulaması tarayıcıda `python3 -m http.server` ile yapılır, 0 konsol hatası hedefi. Build: `cargo tauri build`.

## Web sitesi

`site/` altında statik Cloudflare Pages'e uygun site, **TR+EN**: Hero (isim + tek cümle, charcoal+brass), özellik ızgarası (sekiz özelliği), mimari diyagramı, kurulum (.rpm öncelikli + .deb + AppImage indirme + kaynaktan derleme), gizlilik vurgusu, MIT. Deploy: Cloudflare Pages (hesap erişimi kullanıcıda; `wrangler pages` veya Git ile bağlanır).

## Faz 2 (not)

cgroup eBPF ile süreç başına engelleme, blocklist otomatik güncelleme, gerçek paket yakalama (opsiyonel pcap), rapor dışa aktar (PDF/JSON).

## İnşa sırası

1. Rust çekirdek (ayrıştırıcılar + DB + blocklist + enforcement: nft/pkexec/kill switch/domain-resolver) — test yeşil.
2. Tray + bildirim + otostart + Tauri kabuk + JS UI — tarayıcıda UI doğrulaması.
3. `cargo tauri build` — binary + paketler (.rpm öncelikli, .deb, AppImage).
4. Skill'leri kullanarak inceleme (code-review, security-review, test-master) — testler ve düzeltmeler.
5. Web sitesi (TR+EN) — Cloudflare Pages'e yönerge.

## Builder check notu

Taze mühendis gözden geçirmesi 2026-11-18'de yapıldı; 8 soru çıktı. 6'sı kullanıcıya soruldu ve cevapları "Builder check kararları" bölümüne işlendi; 2'si buildera bırakıldı (Kurallar = constrained form, salt kendi tablosu varsayılan görünür; paket önceliği .rpm — Fedora 45 doğrulandı).
