"use strict";
(() => {
  const POLL_MS = 5000; // the state poll
  const QUICK_MS = 1500; // follow-up polls after an action, so its effect shows quickly
  const WINDOW_S = 900; // the graph spans 15 minutes
  const CHART_W = 600;
  const CHART_H = 160;

  const $ = (id) => document.getElementById(id);
  const isTrue = (v) => ["true", "1", "yes", "on"].includes(String(v).trim().toLowerCase());

  const GROUPS = [
    { title: "Connection target", envs: ["SERVER", "COUNTRY", "CITY", "P2P", "SECURE_CORE", "TOR"] },
    {
      title: "Preferences",
      envs: ["NETSHIELD", "PORT_FORWARDING", "VPN_ACCELERATOR", "MODERATE_NAT", "IPV6", "CUSTOM_DNS", "ANONYMOUS_CRASH_REPORTS"],
    },
  ];
  const FIELDS = {
    SERVER: { label: "Server", placeholder: "NL#914", hint: "A server name. Overrides country and city." },
    COUNTRY: { label: "Country", placeholder: "NL or Netherlands", hint: "Connects to the fastest server there." },
    CITY: { label: "City", placeholder: "Amsterdam" },
    P2P: { label: "P2P servers" },
    SECURE_CORE: { label: "Secure Core" },
    TOR: { label: "Tor" },
    NETSHIELD: { label: "NetShield" },
    PORT_FORWARDING: { label: "Port forwarding", hint: "Needs a P2P server." },
    VPN_ACCELERATOR: { label: "VPN Accelerator" },
    MODERATE_NAT: { label: "Moderate NAT" },
    IPV6: { label: "IPv6" },
    CUSTOM_DNS: { label: "Custom DNS", placeholder: "on --dns 1.1.1.1,8.8.8.8", hint: "Or off." },
    ANONYMOUS_CRASH_REPORTS: { label: "Anonymous crash reports" },
  };
  const CHOICE_LABELS = {
    off: "Off",
    on: "On",
    "malware-only": "Malware only",
    "malware-ads-trackers": "Malware, ads & trackers",
  };

  const fields = {}; // env -> { setting, input, note, dirty, result }
  let built = false;
  let codeStep = false; // the sign-in asked for a 2FA code
  let timer = 0;
  let quick = 0;
  let last = null; // latest state

  // --- helpers ---

  function el(tag, text, cls) {
    const node = document.createElement(tag);
    if (text) node.textContent = text;
    if (cls) node.className = cls;
    return node;
  }

  function fmtBytes(n) {
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let i = 0;
    while (n >= 1024 && i < units.length - 1) {
      n /= 1024;
      i += 1;
    }
    return `${i === 0 || n >= 100 ? Math.round(n) : n.toFixed(n >= 10 ? 1 : 2)} ${units[i]}`;
  }
  const fmtRate = (n) => `${fmtBytes(n)}/s`;

  function setText(id, text) {
    $(id).textContent = text || "—";
  }

  function notice(text) {
    $("notice").hidden = !text;
    $("notice").textContent = text || "";
  }

  function message(id, text, cls) {
    const node = $(id);
    node.hidden = !text;
    node.textContent = text || "";
    node.className = `note ${cls || ""}`.trim();
  }

  async function api(path, body) {
    const init = { cache: "no-store", credentials: "same-origin" };
    if (body !== undefined) {
      init.method = "POST";
      init.headers = { "Content-Type": "application/json", "X-Requested-With": "protonvpn-webui" };
      init.body = JSON.stringify(body);
    }
    const res = await fetch(path, init);
    let data = {};
    try {
      data = await res.json();
    } catch (_) {
      // an error page that is not JSON: status alone tells enough
    }
    if (res.status === 401) showLogin();
    return { status: res.status, data };
  }

  // --- polling ---

  function schedule(ms) {
    clearTimeout(timer);
    timer = setTimeout(poll, ms);
  }

  function afterAction(polls = 2) {
    quick = polls;
    schedule(0);
  }

  async function poll() {
    if (document.hidden) return schedule(POLL_MS);
    try {
      const { status, data } = await api("/api/v1/state");
      if (status === 200) {
        notice("");
        showApp();
        render(data);
      } else if (status !== 401) {
        notice(`The container answered with an error (${status}). Retrying.`);
      }
    } catch (_) {
      notice("Cannot reach the container. Retrying.");
    }
    schedule(quick-- > 0 ? QUICK_MS : POLL_MS);
  }

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) schedule(0);
  });

  // --- views ---

  function showLogin() {
    if (!$("login").hidden) return;
    $("app").hidden = true;
    $("banner").hidden = true;
    $("logout").hidden = true;
    $("login").hidden = false;
    built = false;
    $("settings-form").replaceChildren();
    $("login-password").focus();
  }

  function showApp() {
    $("login").hidden = true;
    $("app").hidden = false;
  }

  function connectionState(s) {
    if (s.connected) return ["pill-on", "Connected"];
    if (!s.signed_in || s.user_disconnected) return ["pill-off", "Disconnected"];
    if (s.last_error) return ["pill-err", "Error"];
    return ["pill-wait", "Connecting…"];
  }

  function render(s) {
    last = s;
    $("logout").hidden = !s.auth_required;
    $("banner").hidden = !s.banner;

    const [cls, label] = connectionState(s);
    $("pill").className = `pill ${cls}`;
    if ($("pill").textContent !== label) $("pill").textContent = label; // a live region: announce changes only
    const where = $("where");
    where.replaceChildren();
    if (s.connected) {
      where.append(el("strong", s.server || "VPN server"), ` ${s.location ? "· " + s.location : ""}`);
    } else if (!s.signed_in) {
      where.textContent = "Sign in to connect.";
    } else if (s.user_disconnected) {
      where.textContent = "Disconnected on request. Connect to resume.";
    } else {
      where.textContent = s.last_error ? "The last attempt failed; retrying automatically." : "Waiting for the VPN to come up…";
    }
    setText("exit-ip", s.connected && s.exit_ip);
    setText("load", s.connected && s.load);
    setText("protocol", s.connected && s.protocol);
    message("last-error", s.connected ? "" : s.last_error, "error");

    $("connect").disabled = !s.signed_in || s.connected;
    $("connect").textContent = s.last_error && !s.user_disconnected && !s.connected ? "Retry now" : "Connect";
    $("disconnect").disabled = !s.signed_in || (!s.connected && s.user_disconnected);

    $("port").textContent = s.forwarded_port || "—";
    $("copy").disabled = !s.forwarded_port;
    const forwarding = s.settings.find((x) => x.env === "PORT_FORWARDING");
    message("port-note", s.connected && !s.forwarded_port ? (forwarding && isTrue(forwarding.value) ? "No port yet. It needs a P2P server." : "Port forwarding is off. Turn it on in Settings.") : "");

    renderAccount(s);
    renderTraffic(s);
    renderSettings(s);
  }

  function renderAccount(s) {
    if (s.signed_in) codeStep = false;
    $("acct-in").hidden = !s.signed_in;
    $("signin-form").hidden = s.signed_in || codeStep;
    $("code-form").hidden = s.signed_in || !codeStep;
    $("acct-name").textContent = s.account;
  }

  function renderTraffic(s) {
    const samples = s.traffic || [];
    const rates = [];
    for (let i = 1; i < samples.length; i += 1) {
      const dt = samples[i][0] - samples[i - 1][0];
      if (dt > 0) {
        rates.push({
          t: samples[i][0],
          down: Math.max(0, (samples[i][1] - samples[i - 1][1]) / dt),
          up: Math.max(0, (samples[i][2] - samples[i - 1][2]) / dt),
        });
      }
    }
    const tail = samples[samples.length - 1];
    const now = rates[rates.length - 1];
    setText("rx-rate", now && fmtRate(now.down));
    setText("tx-rate", now && fmtRate(now.up));
    $("rx-total").textContent = tail ? `${fmtBytes(tail[1])} since connect` : "";
    $("tx-total").textContent = tail ? `${fmtBytes(tail[2])} since connect` : "";

    $("chart-empty").hidden = rates.length > 1;
    const down = [];
    const up = [];
    let peak = 1024; // a floor, so an idle line sits at the bottom instead of dividing by zero
    for (const r of rates) peak = Math.max(peak, r.down, r.up);
    for (const r of rates) {
      const x = (CHART_W - ((now.t - r.t) / WINDOW_S) * CHART_W).toFixed(1);
      down.push(`${x},${(CHART_H - 4 - (r.down / peak) * (CHART_H - 12)).toFixed(1)}`);
      up.push(`${x},${(CHART_H - 4 - (r.up / peak) * (CHART_H - 12)).toFixed(1)}`);
    }
    $("line-down").setAttribute("points", rates.length > 1 ? down.join(" ") : "");
    $("line-up").setAttribute("points", rates.length > 1 ? up.join(" ") : "");
    $("peak").textContent = rates.length > 1 ? `Peak ${fmtRate(peak)}` : "";
    $("chart").setAttribute(
      "aria-label",
      now ? `Download ${fmtRate(now.down)}, upload ${fmtRate(now.up)}, over the last 15 minutes` : "No traffic data yet",
    );
  }

  // --- settings ---

  const valueOf = (f) => (f.setting.kind === "bool" ? String(f.input.checked) : f.input.value.trim());
  const serverValue = (f) => (f.setting.kind === "bool" ? String(isTrue(f.setting.value)) : f.setting.value);

  function setValue(f) {
    if (f.setting.kind === "bool") {
      f.input.checked = isTrue(f.setting.value);
      return;
    }
    if (f.setting.kind === "choice" && ![...f.input.options].some((o) => o.value === f.setting.value)) {
      const option = el("option", f.setting.value);
      option.value = f.setting.value;
      f.input.append(option); // a value set from the environment that the list does not know
    }
    f.input.value = f.setting.value;
  }

  function buildField(setting) {
    const meta = FIELDS[setting.env] || { label: setting.env };
    const id = `f-${setting.env}`;
    const row = el("div", "", "field");
    const note = el("p", "", "note");
    note.id = `${id}-note`;
    let input;
    if (setting.kind === "bool") {
      const label = el("label", "", "check");
      input = el("input");
      input.type = "checkbox";
      label.append(input, el("span", meta.label));
      row.append(label);
    } else {
      const label = el("label", meta.label);
      label.htmlFor = id;
      if (setting.kind === "choice") {
        input = el("select");
        for (const value of ["", ...setting.choices]) {
          const option = el("option", CHOICE_LABELS[value] || value || "Default");
          option.value = value;
          input.append(option);
        }
      } else {
        input = el("input");
        input.type = "text";
        input.autocomplete = "off";
        input.spellcheck = false;
        if (meta.placeholder) input.placeholder = meta.placeholder;
      }
      row.append(label, input);
    }
    input.id = id;
    input.setAttribute("aria-describedby", note.id);
    row.append(note);
    const f = { setting, input, note, meta, dirty: false, result: null };
    input.addEventListener(input.type === "text" ? "input" : "change", () => {
      f.dirty = valueOf(f) !== serverValue(f);
      f.result = null;
      renderNote(f);
      $("save").disabled = !Object.values(fields).some((x) => x.dirty);
    });
    fields[setting.env] = f;
    return row;
  }

  function buildSettings(list) {
    const byEnv = Object.fromEntries(list.map((s) => [s.env, s]));
    const form = $("settings-form");
    for (const group of GROUPS) {
      const set = el("fieldset");
      set.append(el("legend", group.title));
      const grid = el("div", "", "fields");
      const checks = el("div", "", "checks"); // the on/off switches share one row
      for (const env of group.envs) {
        if (byEnv[env]) (byEnv[env].kind === "bool" ? checks : grid).append(buildField(byEnv[env]));
      }
      if (checks.children.length) grid.append(checks);
      set.append(grid);
      form.append(set);
    }
    const actions = el("div", "", "form-actions");
    const save = el("button", "Save changes", "btn primary");
    save.id = "save";
    save.type = "submit";
    save.disabled = true;
    const status = el("p", "", "note");
    status.id = "save-status";
    status.setAttribute("role", "status");
    actions.append(save, status);
    form.append(actions);
    built = true;
  }

  function renderNote(f) {
    let text = f.meta.hint || "";
    let cls = "note";
    const err = last && last.settings_errors && last.settings_errors[f.setting.env];
    if (f.setting.locked) {
      text = "Set by container config";
    } else if (f.result) {
      [text, cls] = [f.result.text, f.result.ok ? "note ok" : "note error"];
      f.note.setAttribute("role", f.result.ok ? "status" : "alert");
    } else if (err) {
      [text, cls] = [err, "note error"];
    }
    f.note.className = cls;
    f.note.textContent = text;
  }

  function renderSettings(s) {
    if (!built) buildSettings(s.settings);
    for (const setting of s.settings) {
      const f = fields[setting.env];
      if (!f) continue;
      f.setting = setting;
      f.input.disabled = setting.locked;
      if (setting.locked) f.dirty = false;
      if (!f.dirty) setValue(f);
      renderNote(f);
    }
    $("save").disabled = !Object.values(fields).some((x) => x.dirty);
  }

  async function saveSettings(event) {
    event.preventDefault();
    const pending = Object.values(fields).filter((f) => f.dirty && !f.setting.locked);
    if (!pending.length) return;
    $("save").disabled = true;
    let failed = 0;
    for (const f of pending) {
      const { data } = await api("/api/v1/settings", { env: f.setting.env, value: valueOf(f) });
      f.result = { ok: Boolean(data.ok), text: data.error || data.message || (data.ok ? "Saved" : "Not saved") };
      if (data.ok) f.dirty = false;
      else failed += 1;
      renderNote(f);
    }
    $("save-status").textContent = failed ? `${failed} of ${pending.length} not saved. See the messages above.` : `Saved ${pending.length} ${pending.length === 1 ? "setting" : "settings"}.`;
    afterAction();
  }

  // --- actions ---

  async function run(button, task) {
    button.disabled = true;
    try {
      await task();
    } catch (_) {
      notice("Cannot reach the container. Try again.");
    } finally {
      button.disabled = false;
      afterAction();
    }
  }

  async function copyPort() {
    const text = $("port").textContent;
    let ok = false;
    if (navigator.clipboard && window.isSecureContext) {
      ok = await navigator.clipboard.writeText(text).then(() => true, () => false);
    }
    if (!ok) {
      // a page served over plain HTTP is not a secure context and has no clipboard API
      const box = el("textarea", "", "offscreen");
      box.value = text;
      document.body.append(box);
      box.select();
      ok = document.execCommand("copy");
      box.remove();
    }
    $("copied").textContent = ok ? "Copied" : "Select the number and copy it";
    setTimeout(() => ($("copied").textContent = ""), 2000);
  }

  async function signIn(event) {
    event.preventDefault();
    const button = event.submitter;
    button.disabled = true;
    message("acct-msg", "Signing in…", "");
    try {
      const { data } = await api("/api/v1/signin", { username: $("signin-user").value.trim(), password: $("signin-password").value });
      $("signin-password").value = "";
      handleStep(data);
    } catch (_) {
      message("acct-msg", "Cannot reach the container. Try again.", "error");
    }
    button.disabled = false;
  }

  async function sendCode(event) {
    event.preventDefault();
    const button = event.submitter;
    button.disabled = true;
    message("acct-msg", "Checking the code…", "");
    try {
      const { data } = await api("/api/v1/signin/code", { code: $("signin-code").value.trim() });
      $("signin-code").value = "";
      handleStep(data);
    } catch (_) {
      message("acct-msg", "Cannot reach the container. Try again.", "error");
    }
    button.disabled = false;
  }

  function handleStep(data) {
    if (data.state === "need_code") {
      codeStep = true;
      // the first ask has no message; a message means the CLI refused the last code and asks again
      message("acct-msg", data.message || "Enter the code from your authenticator app (or a recovery code).", data.message ? "error" : "");
      if (last) renderAccount(last);
      $("signin-code").focus();
      return;
    }
    codeStep = false;
    if (last) renderAccount(last);
    if (data.state === "done") {
      message("acct-msg", data.message || "Signed in.", "ok");
      afterAction(4); // the supervisor needs a moment to notice the session and connect
    } else {
      message("acct-msg", data.error || "Sign-in failed.", "error");
    }
  }

  async function login(event) {
    event.preventDefault();
    const button = event.submitter;
    button.disabled = true;
    try {
      const { status, data } = await api("/api/v1/login", { password: $("login-password").value });
      if (status === 200) {
        $("login-password").value = "";
        message("login-msg", "", "");
        showApp();
        afterAction();
      } else {
        message("login-msg", data.error || "Login failed.", "error");
      }
    } catch (_) {
      message("login-msg", "Cannot reach the container. Try again.", "error");
    }
    button.disabled = false;
  }

  // --- wiring ---

  $("login-form").addEventListener("submit", login);
  $("signin-form").addEventListener("submit", signIn);
  $("code-form").addEventListener("submit", sendCode);
  $("settings-form").addEventListener("submit", saveSettings);
  $("connect").addEventListener("click", (e) => run(e.currentTarget, () => api("/api/v1/connect", {})));
  $("disconnect").addEventListener("click", (e) => run(e.currentTarget, () => api("/api/v1/disconnect", {})));
  $("copy").addEventListener("click", copyPort);
  $("banner-dismiss").addEventListener("click", (e) =>
    run(e.currentTarget, async () => {
      await api("/api/v1/banner/dismiss", {});
      $("banner").hidden = true;
    }),
  );
  $("signout").addEventListener("click", (e) =>
    run(e.currentTarget, async () => {
      const { data } = await api("/api/v1/signout", {});
      message("acct-msg", data.ok ? "Signed out." : data.error || "Sign-out failed.", data.ok ? "ok" : "error");
    }),
  );
  $("logout").addEventListener("click", async () => {
    await api("/api/v1/logout", {});
    showLogin();
  });

  poll();
})();
