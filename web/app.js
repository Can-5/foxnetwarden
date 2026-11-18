/* FoxNetwarden — UI control layer.
 * Masaüstünde Tauri komutlarını çağırır; tarayıcıda (statik sunucu) güvenli
 * bir örnek veriyle çalışır, böylece arayüz çevrimdışı doğrulanabilir.
 * Hiçbir veri dışarı gönderilmez. */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const isTauri = !!(
    window.__TAURI__ &&
    window.__TAURI__.core &&
    typeof window.__TAURI__.core.invoke === "function"
  );
  const invoke = isTauri
    ? (cmd, args) => window.__TAURI__.core.invoke(cmd, args || {})
    : () => Promise.reject(new Error("browser-mode"));

  const LS = {
    get(k, fallback) {
      try {
        const v = localStorage.getItem("foxnw." + k);
        return v === null ? fallback : JSON.parse(v);
      } catch (e) {
        return fallback;
      }
    },
    set(k, v) {
      try {
        localStorage.setItem("foxnw." + k, JSON.stringify(v));
      } catch (e) {
        /* depolama kapalı olabilir — sessizce devam et */
      }
    },
  };

  const settings = Object.assign(
    { refresh: 2000, blocklist: true, autostart: false, dns: false },
    LS.get("settings", {})
  );
  let killActive = false;
  let rules = LS.get("rules", []);
  let currentScreen = "live";
  let refreshTimer = null;
  let toastTimer = null;

  /* ---------- yardımcılar ---------- */

  function toast(msg, kind) {
    const el = $("toast");
    el.textContent = msg;
    el.dataset.kind = kind || "info";
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      el.hidden = true;
    }, 3600);
  }

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }

  function esc(s) {
    return String(s == null ? "" : s);
  }

  function clockTick() {
    const d = new Date();
    $("clock").textContent = d.toLocaleTimeString("tr-TR", { hour12: false });
  }

  /* ---------- tarayıcı modu örnek verisi ---------- */

  const DEMO_CONNS = [
    { pid: 99318, name: "firefox", local: "192.168.1.103:45098", remote: "34.107.243.93:443", state: "ESTAB", duration: 312 },
    { pid: 99318, name: "firefox", local: "192.168.1.103:45102", remote: "doubleclick.net:443", state: "ESTAB", duration: 98 },
    { pid: 27928, name: "opencode-cli", local: "192.168.1.103:42804", remote: "104.18.10.66:443", state: "ESTAB", duration: 1240 },
    { pid: 42, name: "systemd-resolve", local: "127.0.0.53:53", remote: "192.168.1.1:53", state: "ESTAB", duration: 5 },
    { pid: null, name: "?", local: "192.168.1.103:55514", remote: "google-analytics.com:443", state: "ESTAB", duration: 22 },
    { pid: 1102, name: "sshd", local: "0.0.0.0:22", remote: "0.0.0.0:*", state: "LISTEN", duration: 88200 },
    { pid: null, name: "?", local: "192.168.1.103:68", remote: "192.168.1.1:67", state: "ESTAB", duration: 3 },
  ];
  const DEMO_TALKERS = [
    { name: "firefox", count: 38 },
    { name: "opencode-cli", count: 21 },
    { name: "systemd-resolve", count: 12 },
    { name: "?", count: 9 },
  ];
  const DEMO_HISTORY = [
    { id: 5, pid: 99318, name: "firefox", local: "192.168.1.103:45098", remote: "34.107.243.93:443", state: "ESTAB", ts: "2026-11-18T14:02:11" },
    { id: 4, pid: 27928, name: "opencode-cli", local: "192.168.1.103:42804", remote: "104.18.10.66:443", state: "ESTAB", ts: "2026-11-18T14:01:48" },
    { id: 3, pid: 42, name: "systemd-resolve", local: "127.0.0.53:53", remote: "192.168.1.1:53", state: "ESTAB", ts: "2026-11-18T14:01:30" },
  ];
  const DEMO_DNS = [
    { timestamp: "14:02:11", domain: "doubleclick.net", query_type: "A" },
    { timestamp: "14:01:48", domain: "example.com", query_type: "AAAA" },
    { timestamp: "14:01:30", domain: "google-analytics.com", query_type: "A" },
  ];

  /* Tarayıcı modunda hafif şüphe puanı (Rust analyzer ile aynı eşikler). */
  const TRACKERS = ["doubleclick.net", "google-analytics.com", "googlesyndication.com", "facebook.net", "scorecardresearch.com"];
  const MALWARE = ["192.0.2.66", "192.0.2.123", "198.51.100.44", "203.0.113.77"];
  function hostOf(endpoint) {
    if (!endpoint) return "";
    if (endpoint[0] === "[") return endpoint.slice(1, endpoint.indexOf("]"));
    return endpoint.split(":")[0];
  }
  function suspicion(conn) {
    if (!settings.blocklist) return 0;
    const host = hostOf(conn.remote).toLowerCase();
    let score = 0;
    if (TRACKERS.some((t) => host === t || host.endsWith("." + t))) score += 60;
    if (MALWARE.indexOf(host) !== -1) score += 90;
    return Math.min(100, score);
  }
  function scoreChip(score) {
    if (score >= 80) return { cls: "chip chip-high", txt: "YÜKSEK " + score };
    if (score >= 40) return { cls: "chip chip-mid", txt: "ORTA " + score };
    if (score > 0) return { cls: "chip chip-low", txt: "DÜŞÜK " + score };
    return { cls: "chip chip-clean", txt: "TEMİZ" };
  }

  /* ---------- ekran gezinme ---------- */

  function showScreen(name) {
    currentScreen = name;
    document.querySelectorAll(".screen").forEach((s) => s.classList.remove("is-active"));
    const target = $("screen-" + name);
    if (target) target.classList.add("is-active");
    document.querySelectorAll(".nav-item[data-screen]").forEach((b) => {
      b.classList.toggle("is-active", b.dataset.screen === name);
    });
    if (name === "analysis") refreshAnalysis();
    if (name === "dns") refreshDns();
    if (name === "rules") refreshRules();
  }

  document.querySelectorAll(".nav-item[data-screen]").forEach((btn) => {
    btn.addEventListener("click", () => showScreen(btn.dataset.screen));
  });

  /* ---------- veri yükleme ---------- */

  async function loadConnections() {
    if (isTauri) {
      try {
        return await invoke("live_connections");
      } catch (e) {
        toast("Bağlantılar okunamadı: " + e, "error");
        return [];
      }
    }
    return DEMO_CONNS.map((c) => Object.assign({}, c));
  }

  function renderLive(conns) {
    const body = $("liveBody");
    body.textContent = "";
    if (!conns.length) {
      const tr = el("tr");
      const td = el("td", "empty", "Bağlantı yok.");
      td.colSpan = 5;
      tr.appendChild(td);
      body.appendChild(tr);
    } else {
      conns.forEach((c) => {
        const tr = el("tr");
        const name = el("td", null, esc(c.name));
        if (c.pid !== null && c.pid !== undefined) {
          const small = el("span", "panel-meta", " #" + c.pid);
          name.appendChild(small);
        }
        tr.appendChild(name);
        tr.appendChild(el("td", "mono", esc(c.local)));
        tr.appendChild(el("td", "mono", esc(c.remote)));
        tr.appendChild(el("td", null, el("span", "chip chip-state", esc(c.state))));
        const chip = scoreChip(suspicion(c));
        tr.appendChild(el("td", null, el("span", chip.cls, chip.txt)));
        body.appendChild(tr);
      });
    }
    const procs = new Set(conns.map((c) => c.name).filter((n) => n && n !== "?")).size;
    const susp = conns.filter((c) => suspicion(c) >= 40).length;
    $("statConns").textContent = conns.length;
    $("statProcs").textContent = procs;
    $("statSusp").textContent = susp;
    $("statBlocked").textContent = killActive ? conns.length : 0;
    $("navLiveCount").textContent = conns.length;
    $("liveMeta").textContent = isTauri ? "canlı · " + new Date().toLocaleTimeString("tr-TR") : "örnek veri · tarayıcı modu";
    $("modePill").dataset.mode = killActive ? "protect" : "observe";
    $("modePill").textContent = killActive ? "● KORUMA AKTİF" : "● SALT İZLEME";
  }

  async function refreshLive() {
    renderLive(await loadConnections());
  }

  function scheduleRefresh() {
    if (refreshTimer) clearInterval(refreshTimer);
    refreshTimer = setInterval(() => {
      if (currentScreen === "live" && $("autoRefresh").checked) refreshLive();
    }, settings.refresh);
  }

  /* ---------- analiz ---------- */

  async function loadTalkers() {
    if (isTauri) {
      try {
        return await invoke("top_talkers");
      } catch (e) {
        return [];
      }
    }
    return DEMO_TALKERS;
  }
  async function loadHistory() {
    if (isTauri) {
      try {
        return await invoke("history_query");
      } catch (e) {
        return [];
      }
    }
    return DEMO_HISTORY;
  }

  async function refreshAnalysis() {
    const talkers = await loadTalkers();
    const bars = $("talkerBars");
    bars.textContent = "";
    if (!talkers.length) {
      bars.appendChild(el("p", "empty", "Veri yok."));
    } else {
      const max = Math.max.apply(null, talkers.map((t) => t.count)) || 1;
      talkers.forEach((t) => {
        const row = el("div", "bar-row");
        row.appendChild(el("span", "bar-name", esc(t.name)));
        const track = el("div", "bar-track");
        const fill = el("div", "bar-fill");
        fill.style.width = Math.round((t.count / max) * 100) + "%";
        track.appendChild(fill);
        row.appendChild(track);
        row.appendChild(el("span", "bar-num", esc(t.count)));
        bars.appendChild(row);
      });
    }
    const hist = await loadHistory();
    const body = $("historyBody");
    body.textContent = "";
    if (!hist.length) {
      const tr = el("tr");
      const td = el("td", "empty", "Kayıt yok.");
      td.colSpan = 4;
      tr.appendChild(td);
      body.appendChild(tr);
    } else {
      hist.forEach((h) => {
        const tr = el("tr");
        tr.appendChild(el("td", "mono", esc(String(h.ts || "").replace("T", " ").slice(0, 19))));
        tr.appendChild(el("td", null, esc(h.name)));
        tr.appendChild(el("td", "mono", esc(h.remote)));
        tr.appendChild(el("td", null, el("span", "chip chip-state", esc(h.state))));
        body.appendChild(tr);
      });
    }
    const targets = new Set(hist.map((h) => h.remote)).size;
    $("histCount").textContent = hist.length;
    $("histTargets").textContent = targets;
  }

  /* ---------- DNS ---------- */

  async function loadDnsEvents() {
    if (isTauri) {
      try {
        const status = await invoke("dns_mode", { enabled: null });
        if (!status || !status.visible) return { visible: false, events: [], status: status };
        // dns_events komutu yok; status.count üzerinden görünürlük anlaşılır.
        return { visible: true, events: [], status: status };
      } catch (e) {
        return { visible: false, events: [], status: null };
      }
    }
    return {
      visible: !!settings.dns,
      events: settings.dns ? DEMO_DNS : [],
      status: { enabled: !!settings.dns, visible: !!settings.dns, count: settings.dns ? DEMO_DNS.length : 0 },
    };
  }

  async function refreshDns() {
    const data = await loadDnsEvents();
    $("dnsToggleBtn").textContent = settings.dns || (data.status && data.status.enabled) ? "DNS izlemeyi kapat" : "DNS izlemeyi aç";
    const notice = $("dnsNotice");
    notice.classList.toggle("is-live", !!data.visible);
    if (data.visible) {
      $("dnsNoticeTitle").textContent = "İzleme aktif";
      $("dnsNoticeBody").textContent = "systemd-resolved hata ayıklama günlüğü okunuyor. " + (data.status && data.status.count ? data.status.count + " sorgu bulundu." : "Henüz sorgu yok.");
    } else {
      $("dnsNoticeTitle").textContent = "Görünmez mod";
      $("dnsNoticeBody").textContent = "DNS sorguları şu an görünmüyor. Tarayıcılar DoH kullanıyorsa resolved bu trafiği göremez. İzlemeyi açmak için root yetkisiyle debug günlüğü okunur.";
    }
    const body = $("dnsBody");
    body.textContent = "";
    if (!data.events.length) {
      const tr = el("tr");
      const td = el("td", "empty", data.visible ? "Sorgu bulunamadı." : "İzleme kapalı.");
      td.colSpan = 4;
      tr.appendChild(td);
      body.appendChild(tr);
    } else {
      data.events.forEach((ev) => {
        const tr = el("tr");
        tr.appendChild(el("td", "mono", esc(ev.timestamp)));
        tr.appendChild(el("td", null, esc(ev.domain)));
        tr.appendChild(el("td", null, esc(ev.query_type)));
        const flagged = TRACKERS.some((t) => String(ev.domain).toLowerCase().endsWith(t));
        tr.appendChild(el("td", null, el("span", flagged ? "chip chip-mid" : "chip chip-clean", flagged ? "İZLENİYOR" : "TEMİZ")));
        body.appendChild(tr);
      });
    }
    $("dnsMeta").textContent = data.events.length + " kayıt";
  }

  $("dnsToggleBtn").addEventListener("click", async () => {
    const next = !(settings.dns || (lastDnsStatus && lastDnsStatus.enabled));
    settings.dns = next;
    LS.set("settings", settings);
    $("setDns").checked = next;
    if (isTauri) {
      try {
        const st = await invoke("dns_mode", { enabled: next });
        lastDnsStatus = st;
        toast(next ? "DNS izleme açıldı (oturumluk)." : "DNS izleme kapatıldı.", next ? "ok" : "info");
      } catch (e) {
        toast("DNS izleme değiştirilemedi: " + e, "error");
      }
    } else {
      toast(next ? "DNS izleme açıldı (örnek veri)." : "DNS izleme kapatıldı.", "info");
    }
    refreshDns();
  });
  let lastDnsStatus = null;

  /* ---------- kurallar ---------- */

  function renderRules() {
    const body = $("rulesBody");
    body.textContent = "";
    if (!rules.length) {
      const tr = el("tr");
      const td = el("td", "empty", "Kural yok.");
      td.colSpan = 4;
      tr.appendChild(td);
      body.appendChild(tr);
    } else {
      rules.forEach((r) => {
        const tr = el("tr");
        tr.appendChild(el("td", "mono", esc(r.id || r.handle || "—")));
        tr.appendChild(el("td", null, el("span", "chip " + (r.action === "block" ? "chip-high" : "chip-clean"), r.action === "block" ? "ENGELLE" : "İZİN VER")));
        tr.appendChild(el("td", "mono", esc(r.target)));
        const tdAct = el("td");
        const del = el("button", "icon-btn", "✕");
        del.type = "button";
        del.title = "Kuralı sil";
        del.setAttribute("aria-label", "Kuralı sil");
        del.addEventListener("click", () => removeRule(r));
        tdAct.appendChild(del);
        tr.appendChild(tdAct);
        body.appendChild(tr);
      });
    }
    $("ruleMeta").textContent = rules.length + " kural";
    $("navRuleCount").textContent = rules.length;
  }

  async function refreshRules() {
    if (isTauri) {
      // Aktif nft kurallarını okuyan komut yok; eklenenleri yerel listeden göster.
    }
    renderRules();
  }

  $("ruleForm").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const action = $("ruleAction").value;
    const target = $("ruleTarget").value.trim();
    const port = $("rulePort").value.trim();
    if (!target && !port) {
      toast("Hedef veya port girin.", "warn");
      return;
    }
    const fullTarget = port ? target + ":" + port : target;
    if (isTauri) {
      try {
        await invoke("rule_add", { target: fullTarget, action: action });
        rules.push({ id: "nft-" + Date.now(), action: action, target: fullTarget });
        LS.set("rules", rules);
        toast("Kural eklendi — pkexec şifresi onaylandı.", "ok");
      } catch (e) {
        toast("Kural eklenemedi: " + e, "error");
        return;
      }
    } else {
      rules.push({ id: "demo-" + Date.now(), action: action, target: fullTarget });
      LS.set("rules", rules);
      toast("Kural eklendi (örnek veri).", "info");
    }
    $("ruleTarget").value = "";
    $("rulePort").value = "";
    renderRules();
  });

  async function removeRule(r) {
    if (isTauri && r.id && r.id.indexOf("nft-") === 0) {
      try {
        await invoke("rule_remove", { id: r.id });
      } catch (e) {
        toast("Kural silinemedi: " + e, "error");
        return;
      }
    }
    rules = rules.filter((x) => x !== r);
    LS.set("rules", rules);
    renderRules();
    toast("Kural kaldırıldı.", "ok");
  }

  /* ---------- kill switch ---------- */

  function renderKill() {
    const stage = $("killStage");
    stage.dataset.active = killActive ? "true" : "false";
    $("ksPill").dataset.active = killActive ? "true" : "false";
    $("ksPill").textContent = killActive ? "KILL SWITCH: AKTİF" : "KILL SWITCH: KAPALI";
    $("killState").textContent = killActive ? "TÜM AĞ KESİLDİ" : "KORUMA AKTİF";
    $("killDesc").textContent = killActive
      ? "Giden trafik (IPv4/IPv6/DNS/LAN) bloklanıyor. İzin kuralları geçersiz."
      : "Ağ trafiği normal akıyor.";
    $("killBtn").textContent = killActive ? "AĞI GERİ AÇ" : "TÜM AĞI KES";
    $("modePill").dataset.mode = killActive ? "protect" : "observe";
    $("modePill").textContent = killActive ? "● KORUMA AKTİF" : "● SALT İZLEME";
  }

  $("killBtn").addEventListener("click", async () => {
    const next = !killActive;
    if (next && !window.confirm("Tüm ağ trafiği kesilecek (IPv4, IPv6, DNS, LAN). Devam edilsin mi?")) return;
    if (isTauri) {
      try {
        await invoke("killswitch_set", { active: next });
        killActive = next;
        renderKill();
        toast(next ? "Ağ kesildi. Çökerse: sudo nft delete table inet foxnetwarden" : "Ağ geri açıldı.", next ? "warn" : "ok");
      } catch (e) {
        toast("Kill switch değiştirilemedi: " + e, "error");
      }
    } else {
      killActive = next;
      renderKill();
      toast(next ? "Ağ kesildi (örnek veri)." : "Ağ geri açıldı.", next ? "warn" : "ok");
    }
    refreshLive();
  });

  /* ---------- ayarlar ---------- */

  function loadSettingsIntoForm() {
    $("setRefresh").value = String(settings.refresh);
    $("setBlocklist").checked = !!settings.blocklist;
    $("setAutostart").checked = !!settings.autostart;
    $("setDns").checked = !!settings.dns;
  }

  $("saveSettings").addEventListener("click", async () => {
    settings.refresh = Number($("setRefresh").value) || 2000;
    settings.blocklist = $("setBlocklist").checked;
    settings.autostart = $("setAutostart").checked;
    settings.dns = $("setDns").checked;
    LS.set("settings", settings);
    scheduleRefresh();
    if (isTauri) {
      if (settings.autostart) {
        try {
          await invoke("tray_toggle_autostart");
          toast("Başlangıçta çalıştırma açıldı.", "ok");
        } catch (e) {
          toast("Otostart ayarlanamadı: " + e, "error");
        }
      }
      try {
        await invoke("dns_mode", { enabled: settings.dns });
      } catch (e) {
        /* DNS izleme opisyonel */
      }
    } else {
      toast("Ayarlar kaydedildi (tarayıcı modu).", "ok");
    }
    refreshLive();
  });

  $("exportBtn").addEventListener("click", async () => {
    let data = [];
    if (isTauri) {
      try {
        data = await invoke("history_query");
      } catch (e) {
        toast("Geçmiş okunamadı: " + e, "error");
        return;
      }
    } else {
      data = DEMO_HISTORY;
    }
    const blob = new Blob([JSON.stringify({ app: "FoxNetwarden", exported: new Date().toISOString(), history: data }, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "foxnetwarden-history-" + new Date().toISOString().slice(0, 10) + ".json";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast("Geçmiş dışa aktarıldı.", "ok");
  });

  $("refreshBtn").addEventListener("click", () => {
    refreshLive();
    toast("Bağlantılar yenilendi.", "info");
  });

  /* ---------- başlatma ---------- */

  async function init() {
    clockTick();
    setInterval(clockTick, 1000);
    loadSettingsIntoForm();
    renderKill();
    renderRules();
    scheduleRefresh();
    await refreshLive();
  }

  init();
})();
