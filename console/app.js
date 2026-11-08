const app = document.getElementById("app");
let CONFIG = null;
let currentListItems = [];
let currentListStatus = "unclaimed";
let currentListFilter = "";
let currentDetailEvents = [];
let currentDetailUsername = "";

async function init() {
  CONFIG = await fetch("config.json").then((r) => r.json());

  const params = new URLSearchParams(window.location.search);
  const idToken = getValidIdToken();

  if (idToken) {
    renderDashboard(idToken);
    return;
  }

  if (params.has("code")) {
    await handleCallback(params);
    return;
  }

  redirectToLogin();
}

// ---- auth ----

function getRedirectUri() {
  return window.location.origin + "/";
}

function base64UrlDecode(segment) {
  // JWT segments are base64url (RFC 4648 §5), not plain base64: atob() alone
  // chokes on '-'/'_' and on missing padding, so convert first.
  const base64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  return atob(padded);
}

function getValidIdToken() {
  const idToken = sessionStorage.getItem("id_token");
  if (!idToken) return null;
  try {
    const payload = JSON.parse(base64UrlDecode(idToken.split(".")[1]));
    if (payload.exp * 1000 < Date.now()) return null;
    return idToken;
  } catch {
    return null;
  }
}

function base64UrlEncode(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function randomString(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

async function sha256Base64Url(input) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return base64UrlEncode(digest);
}

async function redirectToLogin() {
  const codeVerifier = randomString(64);
  const state = randomString(32);
  const codeChallenge = await sha256Base64Url(codeVerifier);

  sessionStorage.setItem("pkce_code_verifier", codeVerifier);
  sessionStorage.setItem("oauth_state", state);

  const url = new URL(CONFIG.cognitoDomain + "/oauth2/authorize");
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", CONFIG.cognitoClientId);
  url.searchParams.set("redirect_uri", getRedirectUri());
  url.searchParams.set("scope", "openid email profile");
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("state", state);

  window.location.href = url.toString();
}

async function handleCallback(params) {
  const code = params.get("code");
  const state = params.get("state");
  const expectedState = sessionStorage.getItem("oauth_state");
  const codeVerifier = sessionStorage.getItem("pkce_code_verifier");

  if (!codeVerifier || state !== expectedState) {
    app.innerHTML = "<p>Login state mismatch - please try logging in again.</p>";
    sessionStorage.clear();
    setTimeout(redirectToLogin, 1500);
    return;
  }

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: CONFIG.cognitoClientId,
    code,
    redirect_uri: getRedirectUri(),
    code_verifier: codeVerifier,
  });

  const resp = await fetch(CONFIG.cognitoDomain + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!resp.ok) {
    app.innerHTML = "<p>Login failed exchanging the authorization code. Please try again.</p>";
    sessionStorage.clear();
    return;
  }

  const tokens = await resp.json();
  sessionStorage.setItem("id_token", tokens.id_token);
  sessionStorage.removeItem("pkce_code_verifier");
  sessionStorage.removeItem("oauth_state");

  window.history.replaceState(null, "", getRedirectUri());
  renderDashboard(tokens.id_token);
}

function logout() {
  sessionStorage.clear();
  const url = new URL(CONFIG.cognitoDomain + "/logout");
  url.searchParams.set("client_id", CONFIG.cognitoClientId);
  url.searchParams.set("logout_uri", getRedirectUri());
  window.location.href = url.toString();
}

// ---- api ----

async function api(idToken, method, path, body) {
  const resp = await fetch(CONFIG.apiBaseUrl.replace(/\/$/, "") + path, {
    method,
    headers: {
      Authorization: "Bearer " + idToken,
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  if (resp.status === 401) {
    sessionStorage.clear();
    redirectToLogin();
    throw new Error("session expired");
  }

  const data = await resp.json();
  if (!resp.ok) {
    throw new Error(data.error || `request failed (${resp.status})`);
  }
  return data;
}

// ---- rendering ----

async function withLoading(button, loadingText, fn) {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = loadingText;
  try {
    return await fn();
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

function formatActor(actor) {
  // `actor` is server-derived (Cognito claims / STS caller identity), never
  // client-supplied - see trippycreds/actor.py - but still escaped like any
  // other rendered value, defensively.
  if (!actor) return "-";
  return actor.email ? `${actor.email} (${actor.type})` : `${actor.id} (${actor.type})`;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[c]);
}

// ---- export ----

function downloadBlob(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function toCsv(rows, columns) {
  // Some of these fields (notably user_agent) are attacker-controlled -
  // whoever uses a leaked key sets their own User-Agent string. Without this,
  // a crafted value starting with =/+/-/@ could execute as a formula when the
  // exported file is later opened in Excel/Sheets ("CSV injection").
  const cellToString = (v) => {
    if (v === null || v === undefined) return "";
    // actor fields (created_by/claimed_by/deleted_by) are objects, not strings.
    return typeof v === "object" ? JSON.stringify(v) : String(v);
  };
  const neutralizeFormula = (v) => {
    const str = cellToString(v);
    return /^[=+\-@]/.test(str) ? `'${str}` : str;
  };
  const escapeCell = (v) => `"${neutralizeFormula(v).replace(/"/g, '""')}"`;
  const lines = [columns.join(",")];
  for (const row of rows) {
    lines.push(columns.map((col) => escapeCell(row[col])).join(","));
  }
  return lines.join("\r\n");
}

function exportRows(rows, columns, baseName, format) {
  if (format === "csv") {
    downloadBlob(`${baseName}.csv`, toCsv(rows, columns), "text/csv");
  } else {
    downloadBlob(`${baseName}.json`, JSON.stringify(rows, null, 2), "application/json");
  }
}

const LIST_EXPORT_COLUMNS = [
  "iam_username",
  "access_key_id",
  "status",
  "created_at",
  "created_by",
  "claimed_at",
  "claimed_by",
  "deleted_at",
  "deleted_by",
  "placement_description",
  "placed_by",
  "environment",
  "trigger_count",
  "last_triggered_at",
];

const EVENT_EXPORT_COLUMNS = [
  "occurred_at",
  "event_name",
  "source_ip",
  "user_agent",
  "error_code",
  "aws_region",
  "is_manual_test",
];

async function renderDashboard(idToken, status = "unclaimed") {
  app.innerHTML = `
    <header>
      <div class="brand">
        <h1>TrippyCreds</h1>
        <span class="tagline">Mint, manage, and audit AWS credential canaries.</span>
      </div>
      <button id="logout-btn">Log out</button>
    </header>

    <section id="banner"></section>

    <section class="actions">
      <form id="claim-form">
        <h2>Claim a canary</h2>
        <input name="placement_description" placeholder="Placement description" required />
        <input name="placed_by" placeholder="Placed by" required />
        <input name="environment" placeholder="Environment" required />
        <button type="submit">Claim</button>
      </form>

      <div class="pool-mgmt">
        <h2>Pool management</h2>
        <div class="stat-row" id="pool-stats">
          <div class="stat"><span class="stat-value" id="stat-total">–</span><span class="stat-label">Total</span></div>
          <div class="stat"><span class="stat-value" id="stat-unclaimed">–</span><span class="stat-label">Unclaimed</span></div>
          <div class="stat"><span class="stat-value" id="stat-claimed">–</span><span class="stat-label">Claimed</span></div>
          <div class="stat"><span class="stat-value" id="stat-deleted">–</span><span class="stat-label">Deleted</span></div>
        </div>

        <div class="pool-mgmt-actions">
          <form id="batch-create-form">
            <h3>Batch-create</h3>
            <input name="count" type="number" min="1" max="100" value="5" required />
            <button type="submit">Create</button>
          </form>

          <div class="purge-box">
            <h3>Purge unclaimed pool</h3>
            <button id="purge-dry-run-btn">Preview purge</button>
            <div id="purge-preview"></div>
          </div>
        </div>
      </div>
    </section>

    <section>
      <div class="tabs">
        <button class="tab-btn" data-status="unclaimed">Unclaimed</button>
        <button class="tab-btn" data-status="claimed">Claimed</button>
        <button class="tab-btn" data-status="deleted">Deleted</button>
        <input type="search" id="list-filter-input" placeholder="Filter by access key, username, placement…" />
        <span class="export-toolbar">
          Export: <button class="link-btn" id="list-export-csv-btn">CSV</button> ·
          <button class="link-btn" id="list-export-json-btn">JSON</button>
        </span>
      </div>
      <div id="list"></div>
    </section>

    <section class="trusted-principals">
      <h2>Trusted principals (service API)</h2>
      <p class="tagline">AWS principals trusted to claim canaries directly via the cross-account service API, no operator in the loop.</p>
      <div class="trusted-principals-layout">
        <form id="register-principal-form">
          <h3>Register</h3>
          <input name="principal_arn" placeholder="Principal ARN (IAM role or user)" required />
          <input name="label" placeholder="Label" required />
          <input name="environment" placeholder="Restrict to environment (optional)" />
          <button type="submit">Register</button>
        </form>
        <div id="trusted-principals-list"><p>Loading…</p></div>
      </div>
    </section>

    <section id="detail"></section>
  `;

  document.getElementById("logout-btn").addEventListener("click", logout);

  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => loadList(idToken, btn.dataset.status));
  });

  document.getElementById("list-filter-input").addEventListener("input", (e) => {
    currentListFilter = e.target.value;
    renderListTable(idToken);
  });

  document.getElementById("claim-form").addEventListener("submit", (e) => onClaimSubmit(e, idToken));
  document.getElementById("batch-create-form").addEventListener("submit", (e) => onBatchCreateSubmit(e, idToken));
  document.getElementById("purge-dry-run-btn").addEventListener("click", (e) => onPurgePreview(idToken, e.target));
  document
    .getElementById("register-principal-form")
    .addEventListener("submit", (e) => onRegisterPrincipalSubmit(e, idToken));

  document.getElementById("list-export-csv-btn").addEventListener("click", () =>
    exportRows(currentListItems, LIST_EXPORT_COLUMNS, `canaries-${currentListStatus}`, "csv")
  );
  document.getElementById("list-export-json-btn").addEventListener("click", () =>
    exportRows(currentListItems, LIST_EXPORT_COLUMNS, `canaries-${currentListStatus}`, "json")
  );

  await Promise.all([loadList(idToken, status), refreshPoolStats(idToken), loadTrustedPrincipals(idToken)]);
}

function setBanner(html, kind = "info") {
  document.getElementById("banner").innerHTML = html ? `<div class="banner ${kind}">${html}</div>` : "";
}

async function refreshPoolStats(idToken) {
  try {
    const [unclaimed, claimed, deleted] = await Promise.all([
      api(idToken, "GET", "/canaries?status=unclaimed"),
      api(idToken, "GET", "/canaries?status=claimed"),
      api(idToken, "GET", "/canaries?status=deleted"),
    ]);
    const unclaimedCount = unclaimed.items.length;
    const claimedCount = claimed.items.length;
    const deletedCount = deleted.items.length;
    document.getElementById("stat-total").textContent = unclaimedCount + claimedCount;
    document.getElementById("stat-unclaimed").textContent = unclaimedCount;
    document.getElementById("stat-claimed").textContent = claimedCount;
    document.getElementById("stat-deleted").textContent = deletedCount;
  } catch (err) {
    // Non-critical - the lists below still work even if the summary fails to load.
    document.getElementById("pool-stats").innerHTML = `<p class="error">${escapeHtml(err.message)}</p>`;
  }
}

async function loadList(idToken, status) {
  document.querySelectorAll(".tab-btn").forEach((b) => b.classList.toggle("active", b.dataset.status === status));
  document.getElementById("detail").innerHTML = "";

  const listEl = document.getElementById("list");
  listEl.innerHTML = "<p>Loading…</p>";

  try {
    const { items } = await api(idToken, "GET", `/canaries?status=${status}`);
    currentListItems = items;
    currentListStatus = status;
    renderListTable(idToken);
  } catch (err) {
    listEl.innerHTML = `<p class="error">${escapeHtml(err.message)}</p>`;
  }
}

function matchesListFilter(item, query) {
  if (!query) return true;
  const haystacks = [
    item.iam_username,
    item.access_key_id,
    item.placement_description,
    item.placed_by,
    item.environment,
    formatActor(item.created_by),
    formatActor(item.claimed_by),
    formatActor(item.deleted_by),
  ];
  return haystacks.some((v) => String(v ?? "").toLowerCase().includes(query));
}

function renderListTable(idToken) {
  const listEl = document.getElementById("list");

  if (currentListItems.length === 0) {
    listEl.innerHTML = "<p>No canaries.</p>";
    return;
  }

  const query = currentListFilter.trim().toLowerCase();
  const items = currentListItems.filter((item) => matchesListFilter(item, query));

  if (items.length === 0) {
    listEl.innerHTML = "<p>No canaries match your filter.</p>";
    return;
  }

  const status = currentListStatus;
  const rows = items
    .map(
      (item) => `
      <tr class="row" data-access-key-id="${escapeHtml(item.access_key_id)}">
        <td><code>${escapeHtml(item.iam_username)}</code></td>
        <td><code>${escapeHtml(item.access_key_id)}</code></td>
        <td>${escapeHtml(
          item.status === "claimed"
            ? item.placement_description
            : item.status === "deleted"
              ? item.deleted_at
              : item.created_at
        )}</td>
        <td>${escapeHtml(item.trigger_count ?? 0)}</td>
      </tr>`
    )
    .join("");

  listEl.innerHTML = `
    <table>
      <thead>
        <tr><th>Username</th><th>Access key</th><th>${
          status === "claimed" ? "Placement" : status === "deleted" ? "Deleted" : "Created"
        }</th><th>Triggers</th></tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;

  listEl.querySelectorAll(".row").forEach((row) => {
    row.addEventListener("click", () => loadDetail(idToken, row.dataset.accessKeyId));
  });
}

async function loadDetail(idToken, accessKeyId) {
  const detailEl = document.getElementById("detail");
  detailEl.innerHTML = "<p>Loading…</p>";

  try {
    const item = await api(idToken, "GET", `/canaries/${encodeURIComponent(accessKeyId)}`);
    const events = item.events || [];
    currentDetailEvents = events;
    currentDetailUsername = item.iam_username;

    const eventCards = events
      .map((e) => {
        const succeeded = !e.error_code;
        return `
        <div class="event-card">
          <div class="event-card-header">
            <span class="event-name">${escapeHtml(e.event_name)}</span>
            <span class="badge-group">
              ${e.is_manual_test ? '<span class="result-badge test">manual test</span>' : ""}
              <span class="result-badge ${succeeded ? "ok" : "denied"}">${succeeded ? "succeeded" : escapeHtml(e.error_code)}</span>
            </span>
          </div>
          <div class="event-card-time">${escapeHtml(e.occurred_at)}</div>
          <div class="event-card-body">
            <div><span class="label">Source IP</span> ${escapeHtml(e.source_ip)}</div>
            <div><span class="label">Region</span> ${escapeHtml(e.aws_region)}</div>
          </div>
          <div class="event-card-agent"><span class="label">User agent</span> ${escapeHtml(e.user_agent)}</div>
        </div>`;
      })
      .join("");

    detailEl.innerHTML = `
      <div class="detail-section-header">
        <h2>${escapeHtml(item.iam_username)}</h2>
        <button id="test-trigger-btn" class="link-btn">Test trigger</button>
      </div>
      <div id="test-trigger-status"></div>
      <dl>
        <dt>Access key</dt><dd><code>${escapeHtml(item.access_key_id)}</code></dd>
        <dt>Status</dt><dd>${escapeHtml(item.status)}</dd>
        <dt>Placement</dt><dd>${escapeHtml(item.placement_description || "-")}</dd>
        <dt>Placed by</dt><dd>${escapeHtml(item.placed_by || "-")}</dd>
        <dt>Environment</dt><dd>${escapeHtml(item.environment || "-")}</dd>
        <dt>Created by</dt><dd>${escapeHtml(formatActor(item.created_by))}</dd>
        <dt>Claimed by</dt><dd>${escapeHtml(formatActor(item.claimed_by))}</dd>
        ${
          item.status === "deleted"
            ? `<dt>Deleted by</dt><dd>${escapeHtml(formatActor(item.deleted_by))}</dd>`
            : ""
        }
        <dt>Distinct actions seen</dt><dd>${escapeHtml((item.distinct_actions_seen || []).join(", ") || "none yet")}</dd>
        <dt>Last triggered</dt><dd>${escapeHtml(item.last_triggered_at || "never")}</dd>
      </dl>
      <div class="detail-section-header">
        <h3>Trigger timeline</h3>
        ${
          events.length > 0
            ? `<span class="export-toolbar">
                Export: <button class="link-btn" id="event-export-csv-btn">CSV</button> ·
                <button class="link-btn" id="event-export-json-btn">JSON</button>
              </span>`
            : ""
        }
      </div>
      ${events.length === 0 ? "<p>No triggers recorded yet.</p>" : `<div class="event-cards">${eventCards}</div>`}
    `;

    if (events.length > 0) {
      document.getElementById("event-export-csv-btn").addEventListener("click", () =>
        exportRows(currentDetailEvents, EVENT_EXPORT_COLUMNS, `${currentDetailUsername}-events`, "csv")
      );
      document.getElementById("event-export-json-btn").addEventListener("click", () =>
        exportRows(currentDetailEvents, EVENT_EXPORT_COLUMNS, `${currentDetailUsername}-events`, "json")
      );
    }

    document
      .getElementById("test-trigger-btn")
      .addEventListener("click", (e) => onTestTrigger(idToken, accessKeyId, e.target));
  } catch (err) {
    detailEl.innerHTML = `<p class="error">${escapeHtml(err.message)}</p>`;
  }
}

async function onTestTrigger(idToken, accessKeyId, button) {
  const statusEl = document.getElementById("test-trigger-status");

  await withLoading(button, "Triggering…", async () => {
    try {
      const result = await api(idToken, "POST", `/canaries/${encodeURIComponent(accessKeyId)}/test-trigger`, {});
      statusEl.innerHTML = `<div class="banner info">
        Test triggered as <code>${escapeHtml(result.caller_identity_arn)}</code>,
        initiated by ${escapeHtml(formatActor(result.triggered_by))}.
        This is a manual pipeline check, not a real detection - refreshing in a few seconds
        to show it land in the timeline below, marked "manual test".
      </div>`;
      setTimeout(() => loadDetail(idToken, accessKeyId), 8000);
    } catch (err) {
      statusEl.innerHTML = `<p class="error">${escapeHtml(err.message)}</p>`;
    }
  });
}

async function onClaimSubmit(e, idToken) {
  e.preventDefault();
  const form = e.target;
  const button = form.querySelector('button[type="submit"]');
  const body = {
    placement_description: form.placement_description.value,
    placed_by: form.placed_by.value,
    environment: form.environment.value,
  };

  await withLoading(button, "Claiming…", async () => {
    try {
      const item = await api(idToken, "POST", "/canaries/claim", body);
      setBanner(
        `<strong>Claimed ${escapeHtml(item.iam_username)}.</strong> This secret is shown once and never again:<br/>
         access_key_id: <code>${escapeHtml(item.access_key_id)}</code><br/>
         secret_access_key: <code>${escapeHtml(item.secret_access_key)}</code><br/>
         <button id="download-creds-btn" class="link-btn">Download credentials.json</button>`,
        "warning"
      );
      document.getElementById("download-creds-btn").addEventListener("click", () =>
        downloadBlob(`${item.iam_username}-credentials.json`, JSON.stringify(item, null, 2), "application/json")
      );
      form.reset();
      await Promise.all([loadList(idToken, "claimed"), refreshPoolStats(idToken)]);
    } catch (err) {
      setBanner(escapeHtml(err.message), "error");
    }
  });
}

async function onBatchCreateSubmit(e, idToken) {
  e.preventDefault();
  const form = e.target;
  const button = form.querySelector('button[type="submit"]');
  const count = parseInt(form.count.value, 10);

  await withLoading(button, "Creating…", async () => {
    try {
      const { items } = await api(idToken, "POST", "/canaries/batch-create", { count });
      setBanner(`Created ${items.length} canary user(s).`, "info");
      await Promise.all([loadList(idToken, "unclaimed"), refreshPoolStats(idToken)]);
    } catch (err) {
      setBanner(escapeHtml(err.message), "error");
    }
  });
}

// ---- trusted principals (service API) ----

async function loadTrustedPrincipals(idToken) {
  const listEl = document.getElementById("trusted-principals-list");
  listEl.innerHTML = "<p>Loading…</p>";
  try {
    const { items } = await api(idToken, "GET", "/trusted-principals");
    renderTrustedPrincipalsTable(idToken, items);
  } catch (err) {
    listEl.innerHTML = `<p class="error">${escapeHtml(err.message)}</p>`;
  }
}

function renderTrustedPrincipalsTable(idToken, items) {
  const listEl = document.getElementById("trusted-principals-list");

  if (items.length === 0) {
    listEl.innerHTML = "<p>No trusted principals registered.</p>";
    return;
  }

  const rows = items
    .map(
      (item) => `
      <tr>
        <td><code>${escapeHtml(item.principal_arn)}</code></td>
        <td>${escapeHtml(item.label)}</td>
        <td>${escapeHtml((item.allowed_actions || []).join(", "))}</td>
        <td>${escapeHtml(item.environment || "any")}</td>
        <td><span class="result-badge ${item.enabled ? "ok" : "denied"}">${item.enabled ? "enabled" : "disabled"}</span></td>
        <td>${
          item.enabled
            ? `<button class="link-btn disable-principal-btn" data-arn="${escapeHtml(item.principal_arn)}">Disable</button>`
            : ""
        }</td>
      </tr>`
    )
    .join("");

  listEl.innerHTML = `
    <table>
      <thead>
        <tr><th>Principal ARN</th><th>Label</th><th>Actions</th><th>Environment</th><th>Status</th><th></th></tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;

  listEl.querySelectorAll(".disable-principal-btn").forEach((btn) => {
    btn.addEventListener("click", () => onDisablePrincipal(idToken, btn.dataset.arn, btn));
  });
}

async function onRegisterPrincipalSubmit(e, idToken) {
  e.preventDefault();
  const form = e.target;
  const button = form.querySelector('button[type="submit"]');
  const body = {
    principal_arn: form.principal_arn.value,
    label: form.label.value,
  };
  if (form.environment.value) body.environment = form.environment.value;

  await withLoading(button, "Registering…", async () => {
    try {
      await api(idToken, "POST", "/trusted-principals", body);
      form.reset();
      await loadTrustedPrincipals(idToken);
    } catch (err) {
      setBanner(escapeHtml(err.message), "error");
    }
  });
}

async function onDisablePrincipal(idToken, principalArn, button) {
  await withLoading(button, "Disabling…", async () => {
    try {
      await api(idToken, "POST", "/trusted-principals/disable", { principal_arn: principalArn });
      await loadTrustedPrincipals(idToken);
    } catch (err) {
      setBanner(escapeHtml(err.message), "error");
    }
  });
}

// Mirrors iam_lifecycle.DEFAULT_PURGE_BATCH_LIMIT - the dry-run preview lists
// the *entire* unclaimed pool, but a real purge only ever processes this many
// per call (API Gateway's 30s integration cap), so the preview count and what
// one "Confirm delete" click actually removes can differ for a large pool.
const PURGE_BATCH_LIMIT = 25;

async function onPurgePreview(idToken, button) {
  const previewEl = document.getElementById("purge-preview");

  await withLoading(button, "Checking…", async () => {
    try {
      const { items } = await api(idToken, "POST", "/canaries/purge-unclaimed", { dry_run: true });
      if (items.length === 0) {
        previewEl.innerHTML = "<p>Nothing to purge.</p>";
        return;
      }
      const batchNote =
        items.length > PURGE_BATCH_LIMIT
          ? `<p>${items.length} unclaimed canary user(s) in the pool. Each confirm deletes up to
             ${PURGE_BATCH_LIMIT} at a time, so this will take about
             ${Math.ceil(items.length / PURGE_BATCH_LIMIT)} confirms to clear the pool.</p>`
          : `<p>Would delete ${items.length} unclaimed canary user(s):</p>`;
      previewEl.innerHTML = `
        ${batchNote}
        <ul>${items.map((i) => `<li><code>${escapeHtml(i.iam_username)}</code></li>`).join("")}</ul>
        <button id="purge-confirm-btn">Confirm delete${items.length > PURGE_BATCH_LIMIT ? " (first batch)" : ""}</button>
      `;
      document.getElementById("purge-confirm-btn").addEventListener("click", (e) => onPurgeConfirm(idToken, e.target));
    } catch (err) {
      previewEl.innerHTML = `<p class="error">${escapeHtml(err.message)}</p>`;
    }
  });
}

async function onPurgeConfirm(idToken, button) {
  const previewEl = document.getElementById("purge-preview");

  await withLoading(button, "Deleting…", async () => {
    try {
      const { items, remaining_unclaimed } = await api(idToken, "POST", "/canaries/purge-unclaimed", {
        dry_run: false,
      });
      previewEl.innerHTML =
        `<p>Deleted ${items.length} unclaimed canary user(s). Their records remain under the "Deleted" tab.</p>` +
        (remaining_unclaimed > 0
          ? `<p>${remaining_unclaimed} unclaimed canary user(s) still remain (purge processes a bounded batch per click) -
             <button id="purge-continue-btn" class="link-btn">continue purging</button></p>`
          : "");
      if (remaining_unclaimed > 0) {
        document.getElementById("purge-continue-btn").addEventListener("click", (e) => onPurgeConfirm(idToken, e.target));
      }
      await Promise.all([loadList(idToken, "unclaimed"), refreshPoolStats(idToken)]);
    } catch (err) {
      previewEl.innerHTML = `<p class="error">${escapeHtml(err.message)}</p>`;
    }
  });
}

init();
