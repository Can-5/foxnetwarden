/* FoxNetwarden site — TR/EN switch (no dependencies) */
(function () {
  "use strict";
  var STRINGS = {
    tr: {
      "nav.features": "Özellikler", "nav.arch": "Mimari", "nav.install": "Kurulum", "nav.privacy": "Gizlilik",
      "hero.eyebrow": "Linux masaüstü için · açık kaynak · MIT",
      "hero.title": "Ağını gör. Şüpheliyi yakala. Tek tuşla kes.",
      "hero.lede": "FoxNetwarden, hangi uygulamanın nereye bağlandığını gerçek zamanlı gösteren, şüpheli trafiği yerel kurallarla işaretleyen ve tüm ağı anında kesebilen kişisel bir güvenlik duvarıdır. Hesap yok, bulut yok, telemetri yok.",
      "hero.cta": "Kuruluma başla",
      "hero.note": "Yerel çalışır · verin cihazından çıkmaz · root yalnızca engelleme için",
      "sec.features": "NE YAPAR", "sec.features.title": "Sekiz yetenek, tek pencere",
      "f.live.title": "Gerçek zamanlı trafik", "f.live.body": "Aktif bağlantılar: yerel→uzak adres, süreç, durum. Saniyeler içinde yenilenir.",
      "f.perm.title": "Uygulama izinleri", "f.perm.body": "Hedefe engelle / izin ver kuralları; uygulamaya atıf görünümü.",
      "f.susp.title": "Şüpheli tespiti", "f.susp.body": "Yerel blocklist + sezgisel puanlama (0–100), çevrimdışı çalışır.",
      "f.dns.title": "DNS & IP izleme", "f.dns.body": "systemd-resolved debug log'undan çözülen alan adları; DoH varsa dürüstçe \"görünmez\".",
      "f.fw.title": "Firewall yönetimi", "f.fw.body": "nftables tablosu; IP/CIDR/domain/port için engelle/izin ver.",
      "f.hist.title": "Geçmiş & analiz", "f.hist.body": "SQLite'a kayıt; en çok konuşulan hedefler ve uygulamalar.",
      "f.track.title": "Tracker tespiti", "f.track.body": "Gömülü listeyle reklam/izleme alan adlarını turuncu işaretle.",
      "f.kill.title": "Kill switch", "f.kill.body": "Tek tuşla her şeyi kes: kurulmuş+yeni, LAN, DNS, IPv4+IPv6.",
      "sec.arch": "MİMARİ", "sec.arch.title": "Yerel çekirdek, ince arayüz",
      "arch.core": "Çekirdek", "arch.core.body": "ss/conntrack ayrıştırıcı · SQLite · blocklist · analyzer · nftables/pkexec · DNS journal · tray",
      "arch.bridge": "Köprü", "arch.bridge.body": "On Tauri komutu; ayrıcalıklı işlemler Rust'ta, arayüzden yalnızca yetkili çağrı.",
      "arch.ui": "Arayüz", "arch.ui.body": "Altı ekran: Canlı, Analiz, DNS, Kurallar, Kill Switch, Ayarlar. Bağımlılık yok.",
      "arch.foot": "Hiçbir katman dışarı veri göndermez; dışa aktarma yalnızca yerel JSON'dur.",
      "sec.install": "KURULUM", "sec.install.title": "Üç paket, tek binary",
      "build.title": "KAYNAKTAN", "build.repo": "Depoyu gör ↗",
      "sec.privacy": "GİZLİLİK", "sec.privacy.title": "Verin yalnızca sende",
      "privacy.body": "FoxNetwarden hesap istemez, buluta bağlanmaz, telemetri göndermez. Trafiği yerel makinede okur, geçmişi yerel SQLite dosyasında tutar. Engelleme/root gerektiren işlemler pkexec ile kullanıcı onayına sunulur; şifre önbelleğe alınmaz.",
      "privacy.l1": "Açık kaynak · MIT lisans",
      "privacy.l2": "Blocklist statik ve pakete gömülü — otomatik indirme yok",
      "privacy.l3": "Kill switch oturumluktur; çökmede kural kalmaz (manuel: sudo nft delete table inet foxnetwarden)",
      "footer.made": "Yerel öncelikli yazılım."
    },
    en: {
      "nav.features": "Features", "nav.arch": "Architecture", "nav.install": "Install", "nav.privacy": "Privacy",
      "hero.eyebrow": "For Linux desktop · open source · MIT",
      "hero.title": "See your network. Catch the suspicious. Cut it with one switch.",
      "hero.lede": "FoxNetwarden shows in real time which app connects where, flags suspicious traffic with local rules, and can cut the entire network instantly. No account, no cloud, no telemetry.",
      "hero.cta": "Get started",
      "hero.note": "Runs locally · your data stays on your device · root only for blocking",
      "sec.features": "WHAT IT DOES", "sec.features.title": "Eight capabilities, one window",
      "f.live.title": "Real-time traffic", "f.live.body": "Active connections: local→remote address, process, state. Refreshed every second.",
      "f.perm.title": "App permissions", "f.perm.body": "Block/allow rules by target; per-app attribution view.",
      "f.susp.title": "Suspicious detection", "f.susp.body": "Local blocklist + heuristic scoring (0–100), works offline.",
      "f.dns.title": "DNS & IP monitoring", "f.dns.body": "Resolved domains from systemd-resolved debug log; honest \"invisible\" mode when DoH is used.",
      "f.fw.title": "Firewall management", "f.fw.body": "nftables table; block/allow for IP/CIDR/domain/port.",
      "f.hist.title": "History & analysis", "f.hist.body": "SQLite history; top targets and applications.",
      "f.track.title": "Tracker detection", "f.track.body": "Flags ad/tracking domains in orange using a vendored list.",
      "f.kill.title": "Kill switch", "f.kill.body": "Cut everything with one click: established+new, LAN, DNS, IPv4+IPv6.",
      "sec.arch": "ARCHITECTURE", "sec.arch.title": "Local core, thin interface",
      "arch.core": "Core", "arch.core.body": "ss/conntrack parser · SQLite · blocklist · analyzer · nftables/pkexec · DNS journal · tray",
      "arch.bridge": "Bridge", "arch.bridge.body": "Ten Tauri commands; privileged work in Rust, authorized calls only from UI.",
      "arch.ui": "Interface", "arch.ui.body": "Six screens: Live, Analysis, DNS, Rules, Kill Switch, Settings. Zero dependencies.",
      "arch.foot": "No layer sends data out; export is a local JSON download only.",
      "sec.install": "INSTALL", "sec.install.title": "Three packages, one binary",
      "build.title": "FROM SOURCE", "build.repo": "View repo ↗",
      "sec.privacy": "PRIVACY", "sec.privacy.title": "Your data stays yours",
      "privacy.body": "FoxNetwarden asks for no account, talks to no cloud, sends no telemetry. It reads traffic on your machine and keeps history in a local SQLite file. Blocking/root actions go through pkexec for your approval; passwords are never cached.",
      "privacy.l1": "Open source · MIT license",
      "privacy.l2": "Vendored static blocklist — no automatic downloads",
      "privacy.l3": "Kill switch is session-only; rules don't survive a crash (manual: sudo nft delete table inet foxnetwarden)",
      "footer.made": "Local-first software."
    }
  };

  function currentLang() {
    try { return localStorage.getItem("foxnw.site.lang") === "en" ? "en" : "tr"; }
    catch (_) { return "tr"; }
  }

  function apply(lang) {
    var dict = STRINGS[lang];
    document.documentElement.lang = lang;
    document.title = lang === "tr"
      ? "FoxNetwarden — ağ güvenlik duvarın"
      : "FoxNetwarden — your personal firewall";
    document.querySelectorAll("[data-i18n]").forEach(function (node) {
      var key = node.getAttribute("data-i18n");
      if (dict[key] !== undefined) node.textContent = dict[key];
    });
    document.querySelectorAll(".lang-btn").forEach(function (btn) {
      var active = btn.getAttribute("data-lang") === lang;
      btn.classList.toggle("is-active", active);
      btn.setAttribute("aria-pressed", active ? "true" : "false");
    });
    try { localStorage.setItem("foxnw.site.lang", lang); } catch (_) {}
  }

  document.querySelectorAll(".lang-btn").forEach(function (btn) {
    btn.addEventListener("click", function () { apply(btn.getAttribute("data-lang")); });
  });

  apply(currentLang());
})();
