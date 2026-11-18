# FoxNetwarden

**Yerel, hesapsız, bulutsuz kişisel Linux ağ güvenlik duvarı.** Little Snitch / LuLu'nun Linux masaüstü için karşılığı — trafiğini gör, şüpheli bağlantıyı yakala, tek tuşla ağı kes.

**Local-first personal Linux firewall.** See what connects, spot the suspicious, cut the network with one switch. No account, no cloud, no telemetry.

---

## Ne yapar / What it does

Faz 1 (bu sürüm):

- **Canlı trafik** — `ss -tunp` ile aktif bağlantılar: yerel→uzak adres, süreç adı/PID, durum. Süreç adı görünmezse `?` (başka uid'in soketi).
- **Şüpheli bağlantı tespiti** — pakete gömülü statik tracker/malware listeleri + yerel sezgisel puanlama (0–100). Bilinen tracker +60, malware IP +90, çok hedefe konuşan süreç (top-talker) +30.
- **Firewall yönetimi** — nftables tablosu `foxnetwarden`; hedefe (IP/CIDR/domain/port) engelle/izin ver kuralları. Tüm ayrıcalıklı yazımlar `pkexec nft -f -` ile (şifre her işlemde sorulur, önbelleğe alınmaz).
- **Kill switch** — tek tuşla **her şeyi** kes: kurulmuş + yeni bağlantılar, LAN, DNS, IPv4 + IPv6; izin kuralları muaf değil. Temiz çıkışta kural geri alınır; **çökme/zorla kapatmada kural çekirdekte kalır** — `sudo nft delete table inet foxnetwarden` veya yeniden başlatma gerekir.
- **DNS izleme (isteğe bağlı)** — `systemd-resolved` debug journal'ını okur. Debug kapalıysa veya tarayıcı DoH kullanıyorsa **"görünmez mod"** olduğunu dürüstçe söyler.
- **Bağlantı geçmişi ve analiz** — SQLite (`~/.local/share/foxnetwarden/history.db`); en çok konuşulan hedefler/uygulamalar, zaman sıralı geçmiş.
- **Tracker/telemetri tespiti** — domain eşleştirme (tam + alt alan adı wildcard, büyük/küçük harf duyarsız).
- **Tray + bildirim + otostart** — sistem tepsisinden göster/kill switch/çıkış; kill switch açılışında libnotify bildirimi; otostart aç/kapat.

**Gizlilik:** hiçbir veri dışarı çıkmaz. Dışa aktarma yalnızca yerel JSON indirmedir. Hesap yok, telemetri yok, otomatik güncelleme yok.

## Kurulum / Install

Hazır paketler (Federal / RPM tabanlı sistemler için öncelikli):

```bash
# Fedora / RHEL
sudo dnf install dist/rpm/FoxNetwarden-1.0.0-1.x86_64.rpm
# Debian / Ubuntu
sudo dpkg -i dist/deb/FoxNetwarden_1.0.0_amd64.deb
# AppImage (daemon/sidecar gerektirmez)
chmod +x dist/appimage/FoxNetwarden_1.0.0_amd64.AppImage
./dist/appimage/FoxNetwarden_1.0.0_amd64.AppImage
```

Paketler ayrıca GitHub Releases sayfasında da yayınlanabilir (henüz yayınlanmadı).

## Kaynaktan derleme / Build from source

Gereksinimler: Rust (edition 2021), `cargo-tauri` v2, `webkit2gtk-4.1`, `gtk3`, `libsoup3`, `libappindicator3` (veya ayatana) **geliştirme** paketleri.

```bash
cargo install tauri-cli --version '^2'       # zaten kuruluysa atla
cd src-tauri
cargo test                                   # 28 passed, 1 ignored (root ister)
cargo tauri build --bundles rpm,deb,appimage
```

**Fedora notu:** bu makinede `libappindicator3.so.1` var ama `.pc` geliştirme dosyası yok, bu yüzden bundler `Can't detect any appindicator library` diye panikleyebilir. Geçici shim:

```bash
mkdir -p /tmp/opencode/pkgconfig
# /tmp/opencode/pkgconfig/appindicator3-0.1.pc:
#   Name: appindicator3
#   Version: 12.10.1
#   Libs: -L/usr/lib64 -lappindicator3
PKG_CONFIG_PATH=/tmp/opencode/pkgconfig cargo tauri build --bundles rpm,deb,appimage
```

Çıktı: `src-tauri/target/release/foxnetwarden` ve `src-tauri/target/release/bundle/{rpm,deb,appimage}/`.

## Çalıştırma / Run

```bash
src-tauri/target/release/foxnetwarden
```

Pencere açılır; ilk açılışta **gözlem modu** (salt okuma — root gerekmez). Engelleme/kurallar/kill switch için ilgili işlemde pkexec şifresi sorulur.

Tarayıcıda önizleme (UI geliştirme için, gerçek ağ verisi olmadan demo veri kullanır):

```bash
python3 -m http.server --bind 127.0.0.1 -d web 8794
# http://127.0.0.1:8794
```

## Dürüst sınırlar / Honest limitations

- **Root gerekir** gerçek engelleme ve kill switch için; kök yoksa uygulama salt-gözlem modunda çalışır, kural ekleme nazikçe hata verir.
- **Kill switch geri alma**: nftables kuralları çekirdekte yaşar; uygulama **temiz çıkışta** (tepsiden Çıkış) kill switch'i geri alır. **Çökme veya zorla kapatmada kural kalır** — `sudo nft delete table inet foxnetwarden` komutunu çalıştırın veya sistemi yeniden başlatın. Kurallar reboot ile silinir (kalıcı değil).
- **Uygulama-adına-özel engelleme yok** (Faz 2'de cgroup eBPF ile planlandı). Faz 1'de engelleme hedefe/dayalıdır; süreç adı yalnızca gösterim/atıf içindir.
- **Paket içeriği incelenmez, TLS çözülmez.** Trafigin hedefini/sürecini görürsün, içeriğini değil.
- **DoH/DoT** kullanan tarayıcılar DNS'i `systemd-resolved`'ı atlar → DNS izleme görünmez modda kalır (uygulama bunu açıkça belirtir).
- **Blocklist statik**, pakete gömülü; otomatik güncelleme yok (Faz 2).
- **`ss -tunp` başka uid'in süreç adlarını göstermez** (`?` görünür) — aynı kullanıcının süreçleri tam görünür.
- **Tarayıcı önizlemesi demo veri gösterir**; gerçek ağ verisi yalnızca Tauri masaüstü uygulamasında.
- Linux-only; Windows/macOS desteği yok.

## Proje yapısı / Layout

```
web/            vanilla JS + CSS arayüz (6 ekran)
src-tauri/src/  Rust çekirdek: collector, db, blocklist, analyzer,
                firewall, domainblock, dnslog, tray + Tauri komutları
src-tauri/tests/  birim + entegrasyon testleri
docs/superpowers/  tasarım belgesi + uygulama planı
site/           statik tanıtım sitesi (Cloudflare Pages)
```

## Lisans / License

MIT © 2026 Can-5.
