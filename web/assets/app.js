const state = {
  user: null,
  page: 1,
  perPage: 9,
  category: "",
  currentContent: null,
  accountTab: "overview",
  catalogTimer: null,
  catalogController: null,
  catalogRequest: 0,
  csrfToken: "",
};

const API_BASE = (
  document.querySelector('meta[name="modstation-api"]')?.content ||
  window.MODSTATION_API_URL ||
  ""
).replace(/\/+$/, "");

function apiUrl(path) {
  return /^https?:\/\//i.test(path) ? path : `${API_BASE}${path}`;
}

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const mainSections = [$(".hero"), $(".trust-strip"), $(".catalog-section"), $(".creator-banner")];

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);
}

function csrfToken() {
  if (state.csrfToken) return state.csrfToken;
  const entry = document.cookie.split("; ").find((cookie) => cookie.startsWith("modstation_csrf="));
  return entry ? decodeURIComponent(entry.slice("modstation_csrf=".length)) : "";
}

async function api(url, options = {}) {
  const headers = new Headers(options.headers || {});
  const method = (options.method || "GET").toUpperCase();
  if (options.body && !(options.body instanceof FormData)) headers.set("Content-Type", "application/json");
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    const token = csrfToken();
    if (token) headers.set("X-CSRF-Token", token);
  }
  const response = await fetch(apiUrl(url), { ...options, headers, credentials: "include" });
  if (!response.ok) {
    let message = `A solicitação falhou (${response.status}).`;
    try {
      const payload = await response.json();
      message = typeof payload.detail === "string" ? payload.detail : message;
    } catch { /* The response may be an empty or non-JSON error. */ }
    throw new Error(message);
  }
  if (response.headers.get("content-type")?.includes("application/json")) return response.json();
  return response;
}

function toast(message, error = false) {
  const node = document.createElement("div");
  node.className = `toast${error ? " error" : ""}`;
  node.textContent = message;
  $("#toast-region").append(node);
  window.setTimeout(() => node.remove(), 4200);
}

function setUser(user) {
  state.user = user;
  if (!user) state.csrfToken = "";
  const signedIn = Boolean(user);
  $("#account-menu").hidden = !signedIn;
  $$('[data-action="open-login"], [data-action="open-register"]').forEach((button) => {
    button.hidden = signedIn;
  });
  if (user) {
    $("#account-trigger").textContent = user.username;
    $("#account-trigger").setAttribute("aria-label", `Menu da conta de ${user.username}`);
  }
}

async function restoreSession() {
  try {
    setUser(await api("/api/auth/me"));
    const csrf = await api("/api/auth/csrf", { method: "POST" });
    state.csrfToken = csrf.csrf_token;
  } catch {
    setUser(null);
  }
}

function formatNumber(number) {
  return new Intl.NumberFormat("pt-BR", { notation: number > 9999 ? "compact" : "standard" }).format(number || 0);
}

function categoryLabel(category) {
  return ({
    mods: "MOD", maps: "MAP", "resource-packs": "RESOURCE", shaders: "SHADER", addons: "ADD-ON",
  })[category] || String(category || "CONTENT").toUpperCase().slice(0, 12);
}

function cardMarkup(item, index) {
  const glyphs = ["✳", "⌘", "◈", "⟡", "△", "◉"];
  const edition = item.edition === "both" ? "JAVA + BEDROCK" : item.edition.toUpperCase();
  const developer = item.developer?.display_name || item.developer?.username || "Desenvolvedor";
  const cover = item.images?.[0]?.url ? apiUrl(item.images[0].url) : "";
  return `
    <article class="content-card">
      <a href="#content/${encodeURIComponent(item.slug)}" aria-label="Ver ${escapeHtml(item.name)}">
        <div class="card-art">
          ${cover ? `<img class="card-cover" src="${escapeHtml(cover)}" alt="" loading="lazy">` : ""}
          <span class="edition-badge">${escapeHtml(edition)}</span>
          <span class="card-art-glyph" aria-hidden="true">${glyphs[index % glyphs.length]}</span>
          <span class="card-art-label"><span>${escapeHtml(categoryLabel(item.category))}</span> / MODSTATION</span>
        </div>
        <div class="card-body">
          <div class="card-heading">
            <h3 class="card-title">${escapeHtml(item.name)}</h3>
            <span class="rating-value">★ ${Number(item.average_rating || 0).toFixed(1)}</span>
          </div>
          <p class="card-description">${escapeHtml(item.description)}</p>
          <div class="card-meta">
            <span class="developer-line"><span class="developer-avatar">${escapeHtml(developer.slice(0, 1).toUpperCase())}</span>${escapeHtml(developer)}${item.developer?.identity_verified ? '<span class="verified-mark" title="Identidade verificada">◆</span>' : ""}</span>
            <span class="card-downloads">↓ ${formatNumber(item.download_count)}</span>
          </div>
        </div>
      </a>
    </article>`;
}

async function loadCatalog() {
  state.catalogController?.abort();
  const controller = new AbortController();
  state.catalogController = controller;
  const requestId = ++state.catalogRequest;
  const params = new URLSearchParams({
    page: String(state.page),
    per_page: String(state.perPage),
    sort: $("#sort-filter").value,
  });
  const query = $("#search-query").value.trim();
  const edition = $("#edition-filter").value;
  const version = $("#version-filter").value.trim();
  const verified = $("#verified-filter").value;
  if (query) params.set("q", query);
  if (edition) params.set("edition", edition);
  if (version) params.set("minecraft_version", version);
  if (verified) params.set("verified_developer", verified);
  if (state.category) params.set("category", state.category);
  $("#catalog-count").textContent = "Carregando catálogo…";
  $("#content-grid").innerHTML = "";
  $("#empty-state").hidden = true;
  $("#pagination").hidden = true;
  try {
    const page = await api(`/api/contents?${params}`, { signal: controller.signal });
    if (requestId !== state.catalogRequest) return;
    $("#catalog-count").textContent = `${formatNumber(page.total)} ${page.total === 1 ? "criação aprovada" : "criações aprovadas"}`;
    $("#results-note").textContent = page.total ? `${page.total} RESULTADO${page.total === 1 ? "" : "S"}` : "";
    $("#content-grid").innerHTML = page.items.map(cardMarkup).join("");
    $("#empty-state").hidden = page.items.length > 0;
    $("#empty-title").textContent = query || state.category || edition || version || verified
      ? "Nenhuma criação encontrada."
      : "Ainda não há criações publicadas.";
    $("#empty-copy").textContent = query || state.category || edition || version || verified
      ? "Tente ajustar a busca ou os filtros. O catálogo exibe somente publicações aprovadas."
      : "O catálogo mostra apenas conteúdos aprovados. Volte mais tarde ou seja a primeira pessoa a publicar.";
    const hasPages = page.pages > 1;
    $("#pagination").hidden = !hasPages;
    $("#page-label").textContent = `Página ${page.page} de ${page.pages}`;
    $("#previous-page").disabled = page.page <= 1;
    $("#next-page").disabled = page.page >= page.pages;
  } catch (error) {
    if (error.name === "AbortError" || requestId !== state.catalogRequest) return;
    $("#catalog-count").textContent = "Catálogo indisponível";
    $("#empty-state").hidden = false;
    $("#empty-title").textContent = "Não foi possível carregar o catálogo.";
    $("#empty-copy").textContent = error.message;
  }
}

function showScreen(screen, scroll = true) {
  const browse = screen === "browse";
  mainSections.forEach((section) => { section.hidden = !browse; });
  $("#content-page").hidden = screen !== "content";
  $("#account-page").hidden = screen !== "account";
  if (scroll) window.scrollTo({ top: 0, behavior: "smooth" });
}

async function openContent(slug) {
  showScreen("content");
  $("#content-page").innerHTML = '<p class="form-hint">Carregando publicação aprovada…</p>';
  try {
    const content = await api(`/api/contents/${encodeURIComponent(slug)}`);
    state.currentContent = content;
    const edition = content.edition === "both" ? "Java + Bedrock" : content.edition.toUpperCase();
    const releases = content.files.map((file) => `
      <div class="release-row">
        <div><span class="release-name">${escapeHtml(file.name)}</span><span class="release-meta">${escapeHtml(file.version)} · ${formatBytes(file.size_bytes)} · ${escapeHtml(file.sha256.slice(0, 12))}…</span></div>
        <a class="button button-outline button-small" href="${escapeHtml(apiUrl(file.download_url))}">Baixar <span aria-hidden="true">↓</span></a>
      </div>`).join("");
    $("#content-page").innerHTML = `
      <a class="back-link" href="#discover">← Voltar ao catálogo</a>
      <div class="detail-layout">
        <div class="detail-main">
          <div class="detail-hero">${content.images?.[0] ? `<img class="detail-cover" src="${escapeHtml(apiUrl(content.images[0].url))}" alt="" loading="lazy">` : ""}<div class="detail-hero-copy">
            <div class="eyebrow">${escapeHtml(categoryLabel(content.category))} · ${escapeHtml(edition)}</div>
            <h1>${escapeHtml(content.name)}</h1>
            <span class="form-hint">Minecraft ${escapeHtml(content.minecraft_version)}</span>
          </div></div>
          <div class="detail-body">
            <div class="detail-description">${escapeHtml(content.description)}</div>
            ${content.dependencies?.length ? `<h3 class="detail-section-title">Dependências</h3><p class="detail-description">${escapeHtml(content.dependencies.join(", "))}</p>` : ""}
            ${content.credits ? `<h3 class="detail-section-title">Créditos</h3><p class="detail-description">${escapeHtml(content.credits)}</p>` : ""}
            ${content.changelog ? `<h3 class="detail-section-title">Notas da versão</h3><p class="detail-description">${escapeHtml(content.changelog)}</p>` : ""}
            <h3 class="detail-section-title">Arquivos aprovados <span>${content.files.length} disponível(is)</span></h3>
            ${releases || '<p class="form-hint">Nenhum arquivo aprovado disponível no momento.</p>'}
            <div class="rating-input">
              <label class="form-label" for="rating-score">Sua avaliação</label>
              <select id="rating-score" aria-label="Nota de 1 a 5">
                <option value="5">★★★★★</option><option value="4">★★★★</option><option value="3">★★★</option><option value="2">★★</option><option value="1">★</option>
              </select>
              <button class="button button-outline button-small" data-action="rate-content" data-content-id="${content.id}">Avaliar</button>
              <button class="button button-outline button-small" data-action="favorite-content" data-content-id="${content.id}">Salvar favorito</button>
            </div>
            <h3 class="detail-section-title">Conversa <span>${content.rating_count} avaliação(ões) · ${content.average_rating.toFixed(1)} ★</span></h3>
            <div class="comments-list" id="comments-list"><p class="form-hint">Carregando conversa…</p></div>
            <form class="comment-form" id="comment-form" data-content-id="${content.id}">
              <label class="form-label" for="comment-body">Deixe um comentário</label>
              <textarea id="comment-body" name="body" minlength="2" maxlength="2000" required placeholder="Compartilhe sua experiência com respeito."></textarea>
              <button class="button button-primary button-small" type="submit">Publicar comentário</button>
            </form>
          </div>
        </div>
        <aside class="detail-side">
          <div class="eyebrow eyebrow-muted">Publicado por</div>
          <a class="developer-card" href="#developer/${encodeURIComponent(content.developer.username)}">
            <span class="developer-avatar">${escapeHtml(content.developer.display_name.slice(0, 1).toUpperCase())}</span>
            <span><strong>${escapeHtml(content.developer.display_name)} ${content.developer.identity_verified ? '<span class="verified-mark">◆</span>' : ""}</strong><small class="form-hint">@${escapeHtml(content.developer.username)}</small></span>
          </a>
          <div class="trust-score"><strong>${content.trust.score}<small class="trust-total"> / 100</small></strong><small>MTS · ${escapeHtml(content.trust.level)}. Indicador transparente, não substitui análise.</small></div>
          <div class="detail-stat"><span>Edição</span><strong>${escapeHtml(edition)}</strong></div>
          <div class="detail-stat"><span>Categoria</span><strong>${escapeHtml(content.category)}</strong></div>
          <div class="detail-stat"><span>Licença</span><strong>${escapeHtml(content.license)}</strong></div>
          <div class="detail-stat"><span>Downloads</span><strong>${formatNumber(content.download_count)}</strong></div>
          <button class="report-link" data-action="report-content" data-content-id="${content.id}">Denunciar esta publicação</button>
        </aside>
      </div>`;
    await loadComments(content.id);
  } catch (error) {
    $("#content-page").innerHTML = `<a class="back-link" href="#discover">← Voltar ao catálogo</a><div class="inline-error">${escapeHtml(error.message)}</div>`;
  }
}

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  return `${(bytes / (1024 ** index)).toFixed(index ? 1 : 0)} ${units[index]}`;
}

async function loadComments(contentId) {
  const comments = await api(`/api/contents/${contentId}/comments`);
  const container = $("#comments-list");
  if (!comments.length) {
    container.innerHTML = '<p class="form-hint">Ainda não há comentários. Comece uma conversa.</p>';
    return;
  }
  const commentNodes = new Map(comments.map((comment) => [comment.id, { ...comment, children: [] }]));
  const roots = [];
  for (const comment of comments) {
    const node = commentNodes.get(comment.id);
    const parent = commentNodes.get(comment.parent_id);
    if (parent) parent.children.push(node);
    else roots.push(node);
  }
  const renderComment = (comment) => `
    <article class="comment-item" id="comment-${comment.id}">
      <div class="comment-heading"><strong>@${escapeHtml(comment.username)}</strong><span>${new Date(comment.created_at).toLocaleDateString("pt-BR")}</span></div>
      <p>${escapeHtml(comment.body)}</p>
      <button class="text-button" data-action="reply-comment" data-comment-id="${comment.id}" data-content-id="${contentId}">Responder</button>
      <button class="text-button" data-action="report-comment" data-comment-id="${comment.id}">Denunciar</button>
      ${comment.children.length ? `<div class="comment-replies" aria-label="Respostas">${comment.children.map((child) => renderComment(child, depth + 1)).join("")}</div>` : ""}
    </article>`;
  container.innerHTML = roots.map((comment) => renderComment(comment)).join("");
}

function modalForm(title, description, fields, submitText, switchText = "", switchAction = "") {
  $("#auth-content").innerHTML = `
    <h2>${escapeHtml(title)}</h2><p class="modal-intro">${escapeHtml(description)}</p>
    <form class="stacked-form" id="auth-form">
      ${fields}
      <div id="auth-error"></div>
      <button class="button button-primary" type="submit">${escapeHtml(submitText)} <span aria-hidden="true">↗</span></button>
    </form>
    ${switchText ? `<p class="modal-switch">${escapeHtml(switchText)} <button class="text-button" data-action="${escapeHtml(switchAction)}">Clique aqui</button></p>` : ""}`;
}

function openAuth(kind) {
  const modal = $("#auth-modal");
  if (!modal.open) modal.showModal();
  if (kind === "register") {
    modalForm("Entre para explorar.", "Crie sua conta ModStation. Você começa como membro da comunidade.", `
      <div class="form-field"><label for="auth-username">Nome de usuário</label><input id="auth-username" name="username" minlength="3" maxlength="32" pattern="[A-Za-z0-9_]+" autocomplete="username" required></div>
      <div class="form-field"><label for="auth-email">E-mail</label><input id="auth-email" name="email" type="email" autocomplete="email" required></div>
      <div class="form-field"><label for="auth-password">Senha</label><input id="auth-password" name="password" type="password" minlength="12" maxlength="128" autocomplete="new-password" required><small>Use pelo menos 12 caracteres.</small></div>`,
      "Criar conta", "Já tem uma conta?", "open-login");
  } else if (kind === "forgot") {
    modalForm("Recuperar acesso.", "Enviaremos instruções ao e-mail, quando a recuperação estiver configurada.", `
      <div class="form-field"><label for="auth-email">E-mail da conta</label><input id="auth-email" name="email" type="email" autocomplete="email" required></div>`,
      "Enviar instruções", "Lembrou sua senha?", "open-login");
  } else if (kind === "reset") {
    modalForm("Defina uma nova senha.", "Use o token de uso único recebido por e-mail.", `
      <div class="form-field"><label for="auth-token">Token de redefinição</label><input id="auth-token" name="token" minlength="32" maxlength="200" required></div>
      <div class="form-field"><label for="auth-password">Nova senha</label><input id="auth-password" name="password" type="password" minlength="12" maxlength="128" autocomplete="new-password" required></div>
      <input type="hidden" name="action" value="password_reset">`,
      "Redefinir senha", "Voltar para entrar", "open-login");
  } else if (kind === "verify") {
    modalForm("Verifique seu e-mail.", "Cole o token enviado ao seu endereço de e-mail.", `
      <div class="form-field"><label for="auth-token">Token de verificação</label><input id="auth-token" name="token" minlength="32" maxlength="200" required></div>`,
      "Verificar e-mail");
  } else {
    modalForm("Bem-vindo de volta.", "Acesse seus favoritos, publicações e conversas.", `
      <div class="form-field"><label for="auth-email">E-mail</label><input id="auth-email" name="email" type="email" autocomplete="email" required></div>
      <div class="form-field"><label for="auth-password">Senha</label><input id="auth-password" name="password" type="password" autocomplete="current-password" required></div>`,
      "Entrar", "Ainda não tem uma conta?", "open-register");
    $(".modal-links")?.remove();
    $("#auth-form").insertAdjacentHTML("afterend", '<div class="modal-links"><button type="button" data-action="open-forgot">Esqueci minha senha</button><button type="button" data-action="open-verify">Tenho um token de verificação</button><button type="button" data-action="request-verification">Pedir novo e-mail</button></div>');
  }
  $("#auth-form").addEventListener("submit", submitAuthForm, { once: true });
}

async function submitAuthForm(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form));
  const submitButton = $("button[type=submit]", form);
  submitButton.disabled = true;
  try {
    if (data.username) {
      const registered = await api("/api/auth/register", { method: "POST", body: JSON.stringify(data) });
      if (registered.verification_email_sent) {
        $("#auth-error").innerHTML = '<div class="inline-success">Conta criada. Verifique o token enviado ao seu e-mail e depois entre.</div>';
        return;
      }
      const session = await api("/api/auth/login", { method: "POST", body: JSON.stringify({ email: data.email, password: data.password }) });
      state.csrfToken = session.csrf_token;
      $("#auth-modal").close();
      await restoreSession();
      toast("Conta criada. Bem-vindo ao ModStation.");
      return;
    }
    if (data.token) {
      if (data.action === "password_reset") {
        await api("/api/auth/password-reset/confirm", {
          method: "POST",
          body: JSON.stringify({ token: data.token, password: data.password }),
        });
        $("#auth-modal").close();
        toast("Senha redefinida. Entre novamente com a nova senha.");
        openAuth("login");
        return;
      }
      await api("/api/auth/verify-email", { method: "POST", body: JSON.stringify(data) });
      $("#auth-modal").close();
      toast("E-mail verificado. Agora você pode solicitar acesso de desenvolvedor.");
      return;
    }
    if (data.password === undefined) {
      await api("/api/auth/password-reset/request", { method: "POST", body: JSON.stringify(data) });
      $("#auth-error").innerHTML = '<div class="inline-success">Se a conta existir, as instruções foram enviadas. <button class="text-button" type="button" data-action="open-reset">Tenho o token</button></div>';
      return;
    }
    const session = await api("/api/auth/login", { method: "POST", body: JSON.stringify(data) });
    state.csrfToken = session.csrf_token;
    $("#auth-modal").close();
    await restoreSession();
    toast("Sessão iniciada.");
    if (location.hash === "#account") await openAccount("overview");
  } catch (error) {
    $("#auth-error").innerHTML = `<div class="inline-error">${escapeHtml(error.message)}</div>`;
  } finally {
    submitButton.disabled = false;
  }
}

function ensureSignedIn() {
  if (state.user) return true;
  openAuth("login");
  toast("Entre ou crie uma conta para continuar.");
  return false;
}

async function openAccount(tab = "overview") {
  if (!ensureSignedIn()) return;
  state.accountTab = tab;
  showScreen("account");
  $("#account-page").innerHTML = '<p class="form-hint">Carregando painel…</p>';
  const role = state.user.role;
  const nav = [
    ["overview", "Visão geral"],
    ...(role === "developer" ? [["publications", "Publicações"], ["profile", "Perfil público"]] : []),
    ...(role === "user" ? [["apply", "Tornar-se desenvolvedor"]] : []),
    ["activity", "Downloads e favoritos"],
    ["settings", "Configurações"],
    ["notifications", "Notificações"],
    ...(role === "moderator" || role === "admin" ? [["moderation", "Moderação"]] : []),
    ...(role === "admin" ? [["administration", "Administração"], ["security", "Segurança e análises"], ["audit", "Auditoria"]] : []),
  ];
  $("#account-page").innerHTML = `
    <div class="account-heading"><div><div class="eyebrow eyebrow-muted">Área da comunidade</div><h1>Olá, ${escapeHtml(state.user.username)}.</h1></div><span class="status-badge">${escapeHtml(role)}</span></div>
    <div class="dashboard-grid">
      <nav class="dashboard-nav" aria-label="Seções da conta">${nav.map(([key, label]) => `<button class="${tab === key ? "active" : ""}" data-action="account-tab" data-tab="${key}">${label}</button>`).join("")}</nav>
      <div class="dashboard-content" id="dashboard-content"></div>
    </div>`;
  await loadAccountTab(tab);
}

async function loadAccountTab(tab) {
  state.accountTab = tab;
  $$(".dashboard-nav button").forEach((button) => button.classList.toggle("active", button.dataset.tab === tab));
  const content = $("#dashboard-content");
  if (!content) return;
  content.innerHTML = '<p class="form-hint">Carregando…</p>';
  try {
    if (tab === "overview") {
      const [downloads, favorites] = await Promise.all([
        api("/api/account/downloads"),
        api("/api/account/favorites"),
      ]);
      content.innerHTML = `
        <section class="dashboard-card"><h2>Seu espaço na comunidade</h2><p>Conta criada em ${new Date(state.user.created_at || Date.now()).toLocaleDateString("pt-BR")} · e-mail ${state.user.email_verified ? "verificado" : "ainda não verificado"}.</p>
          <div class="dashboard-stats"><div class="stat-card"><strong>${downloads.length}</strong><small>Downloads registrados</small></div><div class="stat-card"><strong>${favorites.length}</strong><small>Favoritos</small></div><div class="stat-card"><strong>${escapeHtml(state.user.role)}</strong><small>Nível de acesso</small></div></div>
        </section><section class="dashboard-card"><h2>Histórico recente</h2>${historyMarkup(downloads.slice(0, 5))}</section>`;
    } else if (tab === "apply") {
      content.innerHTML = `
        <section class="dashboard-card"><h2>Perfil de desenvolvedor</h2>
          <p>Seu papel só muda após a validação do e-mail. A confiança é conquistada com o histórico; não concede exceções à análise de arquivos.</p>
          ${state.user.email_verified ? "" : '<div class="inline-error">Seu e-mail ainda não está verificado. Use “Tenho um token de verificação” no menu de entrada após configurar a entrega de e-mail.</div>'}
          <form class="stacked-form" id="developer-form">
            <div class="form-field"><label for="developer-name">Nome público</label><input id="developer-name" name="display_name" minlength="2" maxlength="80" required></div>
            <div class="form-field"><label for="developer-bio">Sobre você</label><textarea id="developer-bio" name="bio" maxlength="1000"></textarea></div>
            <div class="form-field"><label for="developer-site">Site (opcional)</label><input id="developer-site" name="website" type="url" placeholder="https://"></div>
            <button class="button button-primary" type="submit">Criar perfil de desenvolvedor</button>
          </form>
        </section>`;
    } else if (tab === "publications") {
      const [contents, stats, reports] = await Promise.all([
        api("/api/developer/contents"),
        api("/api/developer/stats"),
        api("/api/developer/reports"),
      ]);
      content.innerHTML = `
        <section class="dashboard-card"><h2>Seu painel de desenvolvedor</h2>
          <div class="dashboard-stats"><div class="stat-card"><strong>${stats.publications}</strong><small>Publicações</small></div><div class="stat-card"><strong>${stats.published}</strong><small>Publicadas</small></div><div class="stat-card"><strong>${stats.downloads}</strong><small>Downloads</small></div><div class="stat-card"><strong>${stats.reports_open}</strong><small>Denúncias em aberto</small></div></div>
        </section>
        <section class="dashboard-card"><h2>Nova publicação</h2>
          <form class="stacked-form" id="content-create-form">
            <div class="form-grid">
              <div class="form-field"><label for="content-name">Nome</label><input id="content-name" name="name" minlength="3" maxlength="120" required></div>
              <div class="form-field"><label for="content-category">Categoria</label><select id="content-category" name="category"><option value="mods">Mods</option><option value="maps">Mapas</option><option value="resource-packs">Resource packs</option><option value="shaders">Shaders</option><option value="addons">Add-ons</option></select></div>
              <div class="form-field"><label for="content-edition">Edição</label><select id="content-edition" name="edition"><option value="java">Java</option><option value="bedrock">Bedrock</option><option value="both">Ambas</option></select></div>
              <div class="form-field"><label for="content-version">Versão Minecraft</label><input id="content-version" name="minecraft_version" maxlength="64" required placeholder="Ex.: 1.21"></div>
              <div class="form-field"><label for="content-license">Licença</label><input id="content-license" name="license" maxlength="80" required placeholder="Ex.: MIT, All Rights Reserved"></div>
              <div class="form-field"><label for="content-dependencies">Dependências</label><input id="content-dependencies" name="dependencies" maxlength="1000" placeholder="Lista separada por vírgula"></div>
            </div>
            <div class="form-field"><label for="content-description">Descrição (mínimo 30 caracteres)</label><textarea id="content-description" name="description" minlength="30" maxlength="5000" required></textarea></div>
            <div class="form-field"><label for="content-credits">Créditos</label><textarea id="content-credits" name="credits" maxlength="1000"></textarea></div>
            <div class="form-field"><label for="content-changelog">Notas da versão</label><textarea id="content-changelog" name="changelog" maxlength="2000"></textarea></div>
            <button class="button button-primary" type="submit">Criar rascunho</button>
          </form>
        </section>
        <section class="dashboard-card"><h2>Publicações e versões</h2>${developerContentMarkup(contents)}</section>
        <section class="dashboard-card"><h2>Denúncias relacionadas às suas criações</h2>${reports.length ? `<div class="dashboard-list">${reports.map((report) => `<div class="dashboard-list-item"><span><strong>${escapeHtml(report.content_name || "Comentário")}</strong><small>${escapeHtml(report.reason)} · ${new Date(report.created_at).toLocaleDateString("pt-BR")}</small></span>${statusBadge(report.status)}</div>`).join("")}</div>` : "<p>Não há denúncias relacionadas às suas criações.</p>"}</section>`;
    } else if (tab === "profile") {
      const me = await api("/api/auth/me");
      const profile = me.developer_profile || {};
      content.innerHTML = `
        <section class="dashboard-card"><h2>Perfil público</h2>
          <form class="stacked-form" id="profile-form">
            <div class="form-field"><label for="profile-name">Nome público</label><input id="profile-name" name="display_name" value="${escapeHtml(profile.display_name || "")}" minlength="2" maxlength="80" required></div>
            <div class="form-field"><label for="profile-bio">Sobre você</label><textarea id="profile-bio" name="bio" maxlength="1000">${escapeHtml(profile.bio || "")}</textarea></div>
            <div class="form-field"><label for="profile-website">Site</label><input id="profile-website" name="website" type="url" value="${escapeHtml(profile.website || "")}" placeholder="https://"></div>
            <button class="button button-primary" type="submit">Salvar perfil</button>
          </form>
        </section>`;
    } else if (tab === "activity") {
      const [downloads, favorites] = await Promise.all([
        api("/api/account/downloads"),
        api("/api/account/favorites"),
      ]);
      content.innerHTML = `
        <section class="dashboard-card"><h2>Histórico de downloads</h2>${historyMarkup(downloads)}</section>
        <section class="dashboard-card"><h2>Favoritos</h2>${favorites.length ? `<div class="dashboard-list">${favorites.map((item) => `<a class="dashboard-list-item" href="#content/${encodeURIComponent(item.slug)}"><span><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.category)} · ${escapeHtml(item.edition)}</small></span><span class="status-badge">Abrir ↗</span></a>`).join("")}</div>` : '<p>Você ainda não salvou publicações.</p>'}</section>`;
    } else if (tab === "notifications") {
      const items = await api("/api/account/notifications");
      content.innerHTML = `<section class="dashboard-card"><h2>Notificações</h2>${items.length ? `<div class="dashboard-list">${items.map((item) => `<div class="dashboard-list-item"><span><strong>${escapeHtml(item.message)}</strong><small>${new Date(item.created_at).toLocaleString("pt-BR")}</small></span>${item.read ? '<span class="status-badge">Lida</span>' : `<button class="button button-outline compact-button" data-action="notification-read" data-id="${item.id}">Marcar como lida</button>`}</div>`).join("")}</div>` : "<p>Você não tem notificações.</p>"}</section>`;
    } else if (tab === "settings") {
      content.innerHTML = `
        <section class="dashboard-card"><h2>Segurança da conta</h2>
          <p>Identificador: @${escapeHtml(state.user.username)} · e-mail ${state.user.email_verified ? "verificado" : "não verificado"}.</p>
          ${state.user.email_verified ? "" : '<button class="button button-outline button-small" data-action="resend-verification">Enviar verificação por e-mail</button>'}
          <form class="stacked-form" id="password-change-form">
            <div class="form-field"><label for="current-password">Senha atual</label><input id="current-password" name="current_password" type="password" autocomplete="current-password" required></div>
            <div class="form-field"><label for="new-password">Nova senha</label><input id="new-password" name="new_password" type="password" minlength="12" maxlength="128" autocomplete="new-password" required><small>Use pelo menos 12 caracteres.</small></div>
            <button class="button button-primary" type="submit">Alterar senha e revogar outras sessões</button>
          </form>
        </section>`;
    } else if (tab === "moderation") {
      await renderModeration(content);
    } else if (tab === "administration") {
      await renderAdminOverview(content);
    } else if (tab === "security") {
      await renderSecurity(content);
    } else if (tab === "audit") {
      await renderAudit(content);
    }
  } catch (error) {
    content.innerHTML = `<div class="inline-error">${escapeHtml(error.message)}</div>`;
  }
}

function historyMarkup(downloads) {
  if (!downloads.length) return "<p>Nenhum download registrado ainda.</p>";
  return `<div class="dashboard-list">${downloads.map((item) => `<div class="dashboard-list-item"><span><strong>${escapeHtml(item.content)}</strong><small>Versão ${escapeHtml(item.version)} · ${new Date(item.downloaded_at).toLocaleDateString("pt-BR")}</small></span><span class="status-badge">Download</span></div>`).join("")}</div>`;
}

function statusBadge(value) {
  const label = ({
    queued: "Aguardando análise", scanning: "Em análise", approved: "Aprovado",
    suspicious: "Suspeito", rejected: "Reprovado", quarantined: "Quarentena",
    inconclusive: "Inconclusivo", pending: "Em moderação", published: "Publicado",
    draft: "Rascunho", resolved: "Resolvido", open: "Aberto", dismissed: "Descartado",
    reviewing: "Em revisão", suspended: "Suspenso",
  })[value] || value;
  return `<span class="status-badge status-${escapeHtml(value)}">${escapeHtml(label)}</span>`;
}

function developerContentMarkup(contents) {
  if (!contents.length) return '<p>Você ainda não criou publicações.</p>';
  return `<div class="dashboard-list">${contents.map((item) => `
    <article class="dashboard-list-item">
      <span><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.edition)} · ${escapeHtml(item.minecraft_version)} · ${statusBadge(item.status)}</small>
        ${item.files.map((file) => `<small>${escapeHtml(file.file_type)} ${escapeHtml(file.name)} · MSE ${statusBadge(file.scan_status)} · Revisão ${statusBadge(file.review_status)} · ${escapeHtml(file.sha256.slice(0, 12))}…</small>`).join("")}
      </span>
      <span class="dashboard-actions">
        <button class="button button-outline compact-button" data-action="edit-content" data-id="${item.id}">Editar</button>
        <label class="button button-outline compact-button" for="release-${item.id}">Enviar arquivo</label>
        <input id="release-${item.id}" type="file" accept=".jar,.zip,.mcpack,.mcaddon,.mctemplate" hidden data-upload-content="${item.id}">
        <label class="button button-outline compact-button" for="image-${item.id}">Adicionar imagem PNG</label>
        <input id="image-${item.id}" type="file" accept="image/png,.png" hidden data-upload-image="${item.id}">
        ${item.files.some((file) => file.scan_status === "approved") && ["draft", "rejected"].includes(item.status) ? `<button class="button button-primary compact-button" data-action="submit-content" data-id="${item.id}">Enviar para revisão</button>` : ""}
      </span>
    </article>`).join("")}</div>`;
}

async function renderModeration(container) {
  const [contents, reports, releases] = await Promise.all([
    api("/api/admin/contents"),
    api("/api/admin/reports"),
    api("/api/admin/files/pending-review"),
  ]);
  container.innerHTML = `
    <section class="dashboard-card"><h2>Publicações aguardando revisão</h2>
      ${contents.length ? `<div class="dashboard-list">${contents.map((item) => `<article class="dashboard-list-item">
        <span><strong>${escapeHtml(item.name)}</strong><small>@${escapeHtml(item.owner)} · ${escapeHtml(item.category)} · ${escapeHtml(item.edition)}</small>${item.files.map((file) => `<small>${escapeHtml(file.file_type)} · ${escapeHtml(file.name)} · MSE ${statusBadge(file.scan_status)} · Revisão ${statusBadge(file.review_status)} · ${escapeHtml(file.sha256.slice(0, 12))}…</small>`).join("")}</span>
        <span class="dashboard-actions"><button class="button button-primary compact-button" data-action="moderate-content" data-id="${item.id}" data-status="published">Aprovar</button><button class="button button-outline compact-button" data-action="moderate-content" data-id="${item.id}" data-status="rejected">Rejeitar</button></span>
      </article>`).join("")}</div>` : "<p>Nenhuma publicação aguarda revisão.</p>"}
    </section>
    <section class="dashboard-card"><h2>Versões aprovadas pelo MSE aguardando revisão humana</h2>
      ${releases.length ? `<div class="dashboard-list">${releases.map((release) => `<article class="dashboard-list-item">      <span><strong>${escapeHtml(release.content_name)} · ${escapeHtml(release.version)} ${release.file_type === "image" ? "· Imagem" : ""}</strong><small>@${escapeHtml(release.owner)} · ${escapeHtml(release.name)} · ${escapeHtml(release.sha256.slice(0, 16))}…</small></span><span class="dashboard-actions"><button class="button button-primary compact-button" data-action="review-release" data-id="${release.id}" data-status="approved">Aprovar ${release.file_type === "image" ? "imagem" : "versão"}</button><button class="button button-outline compact-button" data-action="review-release" data-id="${release.id}" data-status="rejected">Rejeitar</button></span></article>`).join("")}</div>` : "<p>Nenhuma versão aguarda revisão humana.</p>"}
    </section>
    <section class="dashboard-card"><h2>Denúncias</h2>${reportMarkup(reports)}</section>`;
}

function reportMarkup(reports) {
  if (!reports.length) return "<p>Não há denúncias abertas.</p>";
  return `<div class="dashboard-list">${reports.map((report) => `<article class="dashboard-list-item">
    <span><strong>${escapeHtml(report.reason)} · ${escapeHtml(report.content_name || `Comentário ${report.comment_id}`)}</strong><small>${escapeHtml(report.details || "Sem detalhes")} · ${statusBadge(report.status)}</small></span>
    <span class="dashboard-actions"><button class="button button-outline compact-button" data-action="resolve-report" data-id="${report.id}">Resolver</button><button class="button button-outline compact-button" data-action="dismiss-report" data-id="${report.id}">Descartar</button></span>
  </article>`).join("")}</div>`;
}

async function renderAdminOverview(container) {
  const [stats, users] = await Promise.all([
    api("/api/admin/overview"),
    api("/api/admin/users"),
  ]);
  container.innerHTML = `
    <section class="dashboard-card"><h2>Visão geral da plataforma</h2><div class="dashboard-stats">
      ${Object.entries({ "Contas": stats.users, "Desenvolvedores": stats.developers, "Publicações pendentes": stats.contents_pending, "Denúncias em aberto": stats.reports_open, "Arquivos isolados": stats.files_quarantined, "Downloads": stats.downloads }).map(([label, count]) => `<div class="stat-card"><strong>${formatNumber(count)}</strong><small>${label}</small></div>`).join("")}
    </div></section>
    <section class="dashboard-card"><h2>Contas e permissões</h2><div class="data-table-wrap"><table class="data-table"><thead><tr><th>Usuário</th><th>E-mail</th><th>Papel</th><th>Acesso</th></tr></thead><tbody>
      ${users.map((user) => `<tr><td>${escapeHtml(user.username)}</td><td>${escapeHtml(user.email)}</td><td><select aria-label="Papel de ${escapeHtml(user.username)}" data-action="change-role" data-id="${user.id}"><option value="user" ${user.role === "user" ? "selected" : ""}>Usuário</option><option value="developer" ${user.role === "developer" ? "selected" : ""}>Desenvolvedor</option><option value="moderator" ${user.role === "moderator" ? "selected" : ""}>Moderador</option></select></td><td>${user.active ? `<span class="dashboard-actions">${user.role === "developer" ? `<button class="button button-outline compact-button" data-action="verify-identity" data-id="${user.id}">Reverificar identidade</button>` : ""}<button class="button button-outline compact-button" data-action="deactivate-user" data-id="${user.id}">Desativar</button></span>` : statusBadge("suspended")}</td></tr>`).join("")}
    </tbody></table></div></section>`;
}

async function renderSecurity(container) {
  const scans = await api("/api/admin/security/scans");
  container.innerHTML = `<section class="dashboard-card"><h2>Histórico MSE</h2><p>Resultados internos ficam restritos à equipe de segurança. Uma análise inconclusiva nunca libera downloads.</p>
    ${scans.length ? `<div class="dashboard-list">${scans.map((scan) => {
      const file = scan.results?.results || {};
      const details = Object.entries(file).map(([engine, result]) => `${engine}: ${typeof result === "object" ? result.status || result.reason || "resultado registrado" : "resultado registrado"}`).join(" · ");
      return `<article class="dashboard-list-item"><span><strong>Arquivo #${scan.file_id} · ${escapeHtml(scan.sha256.slice(0, 16))}… · ${statusBadge(scan.status)}</strong><small>${escapeHtml(details)}</small><small>${scan.review_note ? escapeHtml(scan.review_note) : "Sem revisão humana"}</small></span>
        <span class="dashboard-actions"><button class="button button-outline compact-button" data-action="rescan-file" data-id="${scan.file_id}">Reanalisar</button>${scan.status === "suspicious" ? `<button class="button button-outline compact-button" data-action="false-positive" data-id="${scan.id}">Revisar falso positivo</button>` : ""}</span>
      </article>`;
    }).join("")}</div>` : "<p>Não há análises registradas.</p>"}
    </section>`;
}

async function renderAudit(container) {
  const records = await api("/api/admin/audit");
  container.innerHTML = `<section class="dashboard-card"><h2>Trilha de auditoria</h2>
    ${records.length ? `<div class="data-table-wrap"><table class="data-table"><thead><tr><th>Quando</th><th>Ator</th><th>Ação</th><th>Alvo</th><th>Detalhes</th></tr></thead><tbody>${records.map((item) => `<tr><td>${new Date(item.created_at).toLocaleString("pt-BR")}</td><td>${item.actor_id ?? "Sistema"}</td><td>${escapeHtml(item.action)}</td><td>${escapeHtml(item.target_type)} #${escapeHtml(item.target_id)}</td><td>${escapeHtml(item.details)}</td></tr>`).join("")}</tbody></table></div>` : "<p>Não há eventos registrados.</p>"}
    </section>`;
}

async function handleClick(event) {
  const button = event.target.closest("[data-action]");
  if (!button) return;
  const action = button.dataset.action;
  try {
    if (action === "open-login") openAuth("login");
    else if (action === "open-register") openAuth("register");
    else if (action === "open-forgot") openAuth("forgot");
    else if (action === "open-verify") openAuth("verify");
    else if (action === "open-reset") openAuth("reset");
    else if (action === "close-modal") $("#auth-modal").close();
    else if (action === "publish") {
      if (!ensureSignedIn()) return;
      if (state.user.role === "developer") {
        location.hash = "#account";
        await openAccount("publications");
      } else {
        location.hash = "#account";
        await openAccount("apply");
      }
    } else if (action === "account-menu") {
      $("#account-dropdown").hidden = !$("#account-dropdown").hidden;
    } else if (action === "logout") {
      await api("/api/auth/logout", { method: "POST" });
      setUser(null);
      $("#account-dropdown").hidden = true;
      toast("Você saiu da sua conta.");
      location.hash = "#discover";
    } else if (action === "resend-verification") {
      await api("/api/auth/verification-email", {
        method: "POST",
        body: JSON.stringify({ email: state.user.email }),
      });
      toast("Se a conta puder ser verificada, enviaremos as instruções.");
    } else if (action === "request-verification") {
      const email = window.prompt("Informe o e-mail da sua conta:");
      if (!email) return;
      await api("/api/auth/verification-email", { method: "POST", body: JSON.stringify({ email }) });
      toast("Se a conta puder ser verificada, enviaremos as instruções.");
    } else if (action === "account-tab") {
      await loadAccountTab(button.dataset.tab);
    } else if (action === "rate-content") {
      ensureSignedIn();
      if (!state.user) return;
      await api(`/api/contents/${button.dataset.contentId}/rating`, { method: "PUT", body: JSON.stringify({ score: Number($("#rating-score").value) }) });
      toast("Avaliação registrada.");
      await openContent(state.currentContent.slug);
    } else if (action === "favorite-content") {
      ensureSignedIn();
      if (!state.user) return;
      const result = await api(`/api/contents/${button.dataset.contentId}/favorite`, { method: "PUT" });
      toast(result.saved ? "Adicionado aos favoritos." : "Removido dos favoritos.");
    } else if (action === "report-content") {
      if (!ensureSignedIn()) return;
      const reason = window.prompt("Motivo da denúncia (ex.: malware, direitos autorais, abuso):");
      if (!reason) return;
      await api("/api/reports", { method: "POST", body: JSON.stringify({ content_id: Number(button.dataset.contentId), reason }) });
      toast("Denúncia enviada para revisão.");
    } else if (action === "report-comment") {
      if (!ensureSignedIn()) return;
      const reason = window.prompt("Motivo da denúncia:");
      if (!reason) return;
      await api("/api/reports", { method: "POST", body: JSON.stringify({ comment_id: Number(button.dataset.commentId), reason }) });
      toast("Denúncia enviada para revisão.");
    } else if (action === "reply-comment") {
      if (!ensureSignedIn()) return;
      $("#reply-form")?.remove();
      button.insertAdjacentHTML("afterend", `
        <form class="reply-form" id="reply-form" data-content-id="${Number(button.dataset.contentId)}" data-comment-id="${Number(button.dataset.commentId)}">
          <label class="sr-only" for="reply-body">Sua resposta</label>
          <textarea id="reply-body" name="body" minlength="2" maxlength="2000" required placeholder="Escreva uma resposta…"></textarea>
          <button class="button button-primary button-small" type="submit">Responder</button>
          <button class="text-button" type="button" data-action="cancel-reply">Cancelar</button>
        </form>`);
      $("#reply-body")?.focus();
    } else if (action === "cancel-reply") {
      button.closest("#reply-form")?.remove();
    } else if (action === "submit-content") {
      await api(`/api/contents/${button.dataset.id}/submit`, { method: "POST" });
      toast("Publicação enviada para revisão.");
      await loadAccountTab("publications");
    } else if (action === "edit-content") {
      const contents = await api("/api/developer/contents");
      const item = contents.find((entry) => entry.id === Number(button.dataset.id));
      if (!item) throw new Error("Publicação não encontrada.");
      const form = $("#content-create-form");
      if (!form) throw new Error("Formulário de publicação não está disponível.");
      form.dataset.editId = item.id;
      for (const [name, value] of Object.entries({
        name: item.name, description: item.description, category: item.category,
        edition: item.edition, minecraft_version: item.minecraft_version, license: item.license,
        dependencies: (item.dependencies || []).join(", "), credits: item.credits,
        changelog: item.changelog,
      })) {
        const field = form.elements.namedItem(name);
        if (field) field.value = value || "";
      }
      $("button[type=submit]", form).textContent = "Salvar alterações";
      form.scrollIntoView({ behavior: "smooth", block: "center" });
    } else if (action === "moderate-content") {
      const note = action === "moderate-content" && button.dataset.status === "rejected" ? (window.prompt("Motivo da rejeição:") || "") : "";
      if (button.dataset.status === "rejected" && !note.trim()) return;
      await api(`/api/admin/contents/${button.dataset.id}/review`, { method: "POST", body: JSON.stringify({ status: button.dataset.status, note }) });
      toast(button.dataset.status === "published" ? "Publicação aprovada." : "Publicação rejeitada.");
      await loadAccountTab("moderation");
    } else if (action === "review-release") {
      const note = window.prompt("Registre o motivo da decisão (mínimo 8 caracteres):");
      if (!note || note.trim().length < 8) return;
      await api(`/api/admin/files/${button.dataset.id}/review`, {
        method: "POST",
        body: JSON.stringify({ status: button.dataset.status, note }),
      });
      toast(button.dataset.status === "approved" ? "Versão aprovada para distribuição." : "Versão rejeitada.");
      await loadAccountTab("moderation");
    } else if (action === "resolve-report" || action === "dismiss-report") {
      const resolution = window.prompt("Registre a resolução:");
      if (!resolution) return;
      const confirmed = action === "resolve-report" && window.confirm("A denúncia foi confirmada como violação?");
      await api(`/api/admin/reports/${button.dataset.id}/review`, {
        method: "POST",
        body: JSON.stringify({ status: action === "resolve-report" ? "resolved" : "dismissed", resolution, confirmed_violation: confirmed }),
      });
      toast("Denúncia atualizada.");
      await loadAccountTab("moderation");
    } else if (action === "rescan-file") {
      await api(`/api/admin/security/files/${button.dataset.id}/rescan`, { method: "POST" });
      toast("Reanálise enfileirada.");
      await loadAccountTab("security");
    } else if (action === "false-positive") {
      const note = window.prompt("Explique por que este alerta YARA é um falso positivo (mínimo 8 caracteres):");
      if (!note || note.trim().length < 8) return;
      await api(`/api/admin/security/scans/${button.dataset.id}/review`, {
        method: "POST",
        body: JSON.stringify({ decision: "approve_false_positive", note }),
      });
      toast("Revisão registrada. A publicação ainda precisa de aprovação de moderação.");
      await loadAccountTab("security");
    } else if (action === "deactivate-user") {
      if (!window.confirm("Desativar esta conta e revogar suas sessões?")) return;
      await api(`/api/admin/users/${button.dataset.id}/deactivate`, { method: "POST" });
      toast("Conta desativada.");
      await loadAccountTab("administration");
    } else if (action === "verify-identity") {
      const note = window.prompt("Registre as evidências da análise de identidade (mínimo 8 caracteres):");
      if (!note || note.trim().length < 8) return;
      const verified = window.confirm("A identidade do desenvolvedor foi verificada?");
      await api(`/api/admin/developers/${button.dataset.id}/identity`, {
        method: "PATCH",
        body: JSON.stringify({ verified, note }),
      });
      toast(verified ? "Identidade de desenvolvedor verificada." : "Verificação removida.");
      await loadAccountTab("administration");
    } else if (action === "notification-read") {
      await api(`/api/account/notifications/${button.dataset.id}/read`, { method: "POST" });
      await loadAccountTab("notifications");
    }
  } catch (error) {
    toast(error.message, true);
  }
}

async function handleSubmit(event) {
  const form = event.target;
  if (form.id === "search-form") {
    event.preventDefault();
    state.page = 1;
    await loadCatalog();
  } else if (form.id === "comment-form") {
    event.preventDefault();
    if (!ensureSignedIn()) return;
    const data = new FormData(form);
    await api(`/api/contents/${form.dataset.contentId}/comments`, { method: "POST", body: JSON.stringify({ body: data.get("body") }) });
    form.reset();
    await loadComments(Number(form.dataset.contentId));
    toast("Comentário publicado.");
  } else if (form.id === "reply-form") {
    event.preventDefault();
    if (!ensureSignedIn()) return;
    const body = new FormData(form).get("body");
    const contentId = Number(form.dataset.contentId);
    await api(`/api/contents/${contentId}/comments`, {
      method: "POST",
      body: JSON.stringify({ body, parent_id: Number(form.dataset.commentId) }),
    });
    await loadComments(contentId);
    toast("Resposta publicada.");
  } else if (form.id === "developer-form") {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(form));
    const payload = { ...data, website: data.website || null };
    const result = await api("/api/auth/developer", { method: "POST", body: JSON.stringify(payload) });
    await restoreSession();
    toast(`Perfil de desenvolvedor criado: ${result.display_name}.`);
    await openAccount("publications");
  } else if (form.id === "profile-form") {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(form));
    await api("/api/auth/profile", { method: "PATCH", body: JSON.stringify({ ...data, website: data.website || null }) });
    toast("Perfil atualizado.");
  } else if (form.id === "password-change-form") {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(form));
    await api("/api/auth/password", { method: "PATCH", body: JSON.stringify(data) });
    form.reset();
    toast("Senha alterada; outras sessões foram revogadas.");
  } else if (form.id === "content-create-form") {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(form));
    data.dependencies = data.dependencies ? data.dependencies.split(",").map((item) => item.trim()).filter(Boolean) : [];
    delete data["content-dependencies"];
    const editId = form.dataset.editId;
    const created = await api(editId ? `/api/contents/${editId}` : "/api/contents", {
      method: editId ? "PATCH" : "POST",
      body: JSON.stringify(data),
    });
    delete form.dataset.editId;
    $("button[type=submit]", form).textContent = "Criar rascunho";
    toast(editId ? "Alterações salvas." : "Rascunho criado. Envie uma versão para análise.");
    await loadAccountTab("publications");
    const uploadInput = document.createElement("div");
    uploadInput.className = "inline-success";
    uploadInput.textContent = `Rascunho “${created.name}” criado. Selecione um arquivo na lista abaixo para iniciar a análise.`;
    $("#dashboard-content").prepend(uploadInput);
  }
}

async function handleChange(event) {
  const target = event.target;
  if (target.id === "edition-filter" || target.id === "sort-filter" || target.id === "verified-filter") {
    state.page = 1;
    await loadCatalog();
  } else if (target.matches("[data-upload-content], [data-upload-image]")) {
    if (!ensureSignedIn()) {
      target.value = "";
      return;
    }
    const file = target.files?.[0];
    if (!file) return;
    const isImage = target.matches("[data-upload-image]");
    const version = isImage ? "" : window.prompt("Informe a versão deste arquivo:", "1.0.0");
    if (!isImage && !version) {
      target.value = "";
      return;
    }
    const body = new FormData();
    body.append("upload", file);
    try {
      const contentId = isImage ? target.dataset.uploadImage : target.dataset.uploadContent;
      const result = await api(`/api/contents/${contentId}/${isImage ? "images" : `files?version=${encodeURIComponent(version)}`}`, { method: "POST", body });
      toast(`Upload recebido. Análise: ${result.scan_status}.`);
      await loadAccountTab("publications");
    } catch (error) {
      toast(error.message, true);
    } finally {
      target.value = "";
    }
  } else if (target.matches('[data-action="change-role"]')) {
    try {
      await api(`/api/admin/users/${target.dataset.id}/role`, { method: "PATCH", body: JSON.stringify({ role: target.value }) });
      toast("Permissão atualizada.");
    } catch (error) {
      toast(error.message, true);
      await loadAccountTab("administration");
    }
  }
}

async function routeChanged() {
  const hash = location.hash;
  if (hash.startsWith("#content/")) {
    await openContent(decodeURIComponent(hash.slice("#content/".length)));
  } else if (hash === "#account") {
    await openAccount(state.accountTab);
  } else if (hash.startsWith("#developer/")) {
    await openDeveloper(decodeURIComponent(hash.slice("#developer/".length)));
  } else {
    showScreen("browse", false);
    if (hash === "#discover") $("#discover").scrollIntoView({ behavior: "smooth" });
  }
}

async function openDeveloper(username) {
  showScreen("account");
  $("#account-page").innerHTML = '<p class="form-hint">Carregando perfil público…</p>';
  try {
    const profile = await api(`/api/developers/${encodeURIComponent(username)}`);
    $("#account-page").innerHTML = `
      <a class="back-link" href="#discover">← Voltar ao catálogo</a>
      <section class="dashboard-card"><div class="eyebrow eyebrow-muted">Desenvolvedor ModStation</div><h1>${escapeHtml(profile.display_name)} ${profile.identity_verified ? '<span class="verified-mark">◆</span>' : ""}</h1>
        <p>@${escapeHtml(profile.username)} · ${escapeHtml(profile.bio || "Este desenvolvedor ainda não adicionou uma biografia.")}</p>
        <div class="trust-score"><strong>${profile.trust.score} / 100</strong><small>MTS · ${escapeHtml(profile.trust.level)} · ${profile.trust.criteria.approved_publications} publicação(ões) aprovadas · ${profile.trust.criteria.account_age_days} dias de conta</small></div>
      </section>
      <section class="dashboard-card"><h2>Publicações</h2><div class="content-grid">${profile.contents.map(cardMarkup).join("") || "<p>Este perfil ainda não tem publicações disponíveis.</p>"}</div></section>`;
  } catch (error) {
    $("#account-page").innerHTML = `<a class="back-link" href="#discover">← Voltar ao catálogo</a><div class="inline-error">${escapeHtml(error.message)}</div>`;
  }
}

document.addEventListener("click", (event) => {
  handleClick(event);
  const category = event.target.closest("[data-category]");
  if (category) {
    state.category = category.dataset.category;
    state.page = 1;
    $$(".category-pill").forEach((item) => item.classList.toggle("active", item === category));
    loadCatalog();
  }
});
document.addEventListener("submit", (event) => {
  handleSubmit(event).catch((error) => toast(error.message, true));
});
document.addEventListener("change", (event) => {
  handleChange(event);
});
document.addEventListener("input", (event) => {
  if (event.target.matches("#search-query, #version-filter")) {
    window.clearTimeout(state.catalogTimer);
    state.catalogTimer = window.setTimeout(() => {
      state.page = 1;
      loadCatalog();
    }, 250);
  }
});
$("#previous-page").addEventListener("click", () => { state.page -= 1; loadCatalog(); });
$("#next-page").addEventListener("click", () => { state.page += 1; loadCatalog(); });
window.addEventListener("hashchange", routeChanged);
$("#auth-modal").addEventListener("click", (event) => {
  if (event.target === $("#auth-modal")) $("#auth-modal").close();
});

async function start() {
  await restoreSession();
  await loadCatalog();
  if (location.hash) await routeChanged();
}

start();
