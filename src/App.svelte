<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";
  import { open } from "@tauri-apps/plugin-dialog";
  import { onMount } from "svelte";
  import * as m from "./lib/paraglide/messages.js";
  import { getLocale, locales, setLocale } from "./lib/paraglide/runtime.js";
  import { localeMetadata } from "./lib/locales.js";
  import type { AppInfo } from "./lib/bindings/AppInfo.js";
  import type { JobSnapshot } from "./lib/bindings/JobSnapshot.js";
  import type { JobEvent } from "./lib/bindings/JobEvent.js";
  import type { JobState } from "./lib/bindings/JobState.js";
  import type { RouteDecision } from "./lib/bindings/RouteDecision.js";
  import type { SourceKind } from "./lib/bindings/SourceKind.js";
  import type { CoreUpdateInfo } from "./lib/bindings/CoreUpdateInfo.js";
  import type { SftpTrustInfo } from "./lib/bindings/SftpTrustInfo.js";

  const hasDesktopBackend = "__TAURI_INTERNALS__" in window;

  let mediaUrl = $state("");
  let destination = $state("");
  let route = $state<RouteDecision | null>(null);
  let jobs = $state<JobSnapshot[]>([]);
  let appInfo = $state<AppInfo | null>(null);
  let availablePacks = $state<AvailablePack[]>([]);
  let installingPack = $state("");
  let busy = $state(false);
  let notice = $state("");
  let error = $state("");
  let currentLocale = $state(getLocale());
  let coreUpdate = $state<CoreUpdateInfo | null>(null);
  let updatingCore = $state(false);
  let trustByJob = $state<Record<string, SftpTrustInfo>>({});

  const isBetaLocale = $derived(localeMetadata[currentLocale].review === "beta");
  const direction = $derived(localeMetadata[currentLocale].direction);

  onMount(() => {
    updateDocumentLanguage();
    if (!hasDesktopBackend) {
      notice = m.backend_unavailable();
      return;
    }
    let active = { value: true };
    let unlisten = { value: undefined as UnlistenFn | undefined };
    void (async () => {
      try {
        unlisten.value = await listen<JobEvent>("job-event", ({ payload }) => {
          if (active.value) applyJobEvent(payload);
        });
        [appInfo, jobs] = await Promise.all([
          invoke<AppInfo>("get_app_info"),
          invoke<JobSnapshot[]>("list_jobs"),
        ]);
        await invoke("acknowledge_ui_ready");
        await Promise.all([refreshPacks(), checkCoreUpdate()]);
      } catch (reason) {
        error = readableError(reason);
      }
    })();
    return () => {
      active.value = false;
      unlisten.value?.();
    };
  });

  function applyJobEvent(event: JobEvent): void {
    if (event.type === "removed") {
      jobs = jobs.filter((job) => job.id !== event.id);
      return;
    }
    if (event.type === "progress") {
      jobs = jobs.map((job) => job.id === event.id ? {
        ...job,
        downloaded_bytes: event.downloaded_bytes,
        total_bytes: event.total_bytes,
        speed_bytes_per_second: event.speed_bytes_per_second,
        progress: event.total_bytes && event.total_bytes > 0
          ? Math.min(1, event.downloaded_bytes / event.total_bytes)
          : job.progress,
      } : job);
      return;
    }
    void refreshJobs().catch((reason) => {
      error = readableError(reason);
    });
  }

  async function refreshJobs(): Promise<void> {
    if (!hasDesktopBackend) return;
    jobs = await invoke<JobSnapshot[]>("list_jobs");
  }

  function updateDocumentLanguage(): void {
    document.documentElement.lang = currentLocale;
    document.documentElement.dir = direction;
  }

  function changeLocale(event: Event): void {
    const value = (event.currentTarget as HTMLSelectElement).value;
    if (!locales.includes(value as (typeof locales)[number])) return;
    currentLocale = value as (typeof locales)[number];
    setLocale(currentLocale, { reload: false });
    updateDocumentLanguage();
  }

  async function chooseDestination(): Promise<void> {
    if (!hasDesktopBackend) {
      notice = m.backend_unavailable();
      return;
    }
    const selection = await open({ directory: true, multiple: false });
    if (typeof selection === "string") destination = selection;
  }

  async function analyze(): Promise<void> {
    error = "";
    notice = "";
    route = null;
    if (!mediaUrl.trim()) {
      error = m.validation_url();
      return;
    }
    if (/^(magnet:)|\.torrent(?:$|[?#])/i.test(mediaUrl.trim())) {
      error = m.unsupported_p2p();
      return;
    }
    if (!hasDesktopBackend) {
      notice = m.backend_unavailable();
      return;
    }
    busy = true;
    try {
      route = await invoke<RouteDecision>("classify_source", {
        source: { type: "url", value: mediaUrl.trim() },
      });
    } catch (reason) {
      error = readableError(reason);
    } finally {
      busy = false;
    }
  }

  async function addJob(): Promise<void> {
    if (!route) await analyze();
    if (!route) return;
    if (!destination.trim()) {
      error = m.validation_destination();
      return;
    }
    busy = true;
    error = "";
    try {
      const job = await invoke<JobSnapshot>("create_job", {
        spec: {
          source: { type: "url", value: mediaUrl.trim() },
          destination: destination.trim(),
          preferred_kind: route.source_kind,
          selected_format: null,
          subtitle_languages: [],
          selected_playlist_entries: null,
          overwrite: false,
        },
      });
      jobs = [job, ...jobs];
      notice = m.job_added();
      mediaUrl = "";
      route = null;
    } catch (reason) {
      error = readableError(reason);
    } finally {
      busy = false;
    }
  }

  function readableError(reason: unknown): string {
    if (typeof reason === "string") return m.error_generic();
    if (reason && typeof reason === "object" && "code" in reason) {
      const code = String((reason as { code: unknown }).code);
      if (code === "pack.trust_root_missing") return m.pack_feed_unavailable();
      if (code.startsWith("pack.")) return m.pack_install_failed();
      if (code.startsWith("input.")) return m.validation_url();
      if (code.startsWith("storage.")) return m.storage_error();
    }
    return m.error_generic();
  }

  async function refreshPacks(): Promise<void> {
    if (!hasDesktopBackend) return;
    try {
      availablePacks = await invoke<AvailablePack[]>("list_available_packs");
    } catch (reason) {
      notice = readableError(reason);
    }
  }

  async function installPack(pack: AvailablePack): Promise<void> {
    installingPack = pack.packId;
    error = "";
    try {
      await invoke("install_pack", { packId: pack.packId, targetName: pack.targetName });
      notice = m.pack_install_complete({ pack: pack.packId });
      await refreshPacks();
    } catch (reason) {
      error = readableError(reason);
    } finally {
      installingPack = "";
    }
  }

  async function checkCoreUpdate(): Promise<void> {
    if (!hasDesktopBackend) return;
    try {
      coreUpdate = await invoke<CoreUpdateInfo | null>("check_for_core_update");
    } catch (reason) {
      notice = readableError(reason);
    }
  }

  async function applyCoreUpdate(): Promise<void> {
    if (!coreUpdate || updatingCore) return;
    if (!window.confirm(m.update_confirm({ version: coreUpdate.version }))) return;
    updatingCore = true;
    error = "";
    try {
      const prepared = await invoke<{ status: { transactionId: string } }>("prepare_core_update", {
        targetName: coreUpdate.targetName,
      });
      await invoke("download_core_update", { transactionId: prepared.status.transactionId });
      notice = m.update_restarting();
      await invoke("apply_core_update", { transactionId: prepared.status.transactionId });
    } catch (reason) {
      error = readableError(reason);
      updatingCore = false;
    }
  }

  async function jobAction(command: "pause_job" | "resume_job" | "retry_job" | "cancel_job", id: string): Promise<void> {
    error = "";
    try {
      await invoke(command, { id });
      await refreshJobs();
    } catch (reason) {
      error = readableError(reason);
    }
  }

  async function loadSftpTrust(id: string): Promise<void> {
    try {
      const trust = await invoke<SftpTrustInfo>("sftp_trust_status", { id });
      trustByJob = { ...trustByJob, [id]: trust };
    } catch (reason) {
      error = readableError(reason);
    }
  }

  async function choosePrivateKey(id: string): Promise<void> {
    const selection = await open({ directory: false, multiple: false });
    if (typeof selection !== "string") return;
    const input = document.getElementById(`key-${id}`) as HTMLInputElement | null;
    if (input) input.value = selection;
  }

  async function submitSelection(job: JobSnapshot, event: SubmitEvent): Promise<void> {
    event.preventDefault();
    const form = event.currentTarget as HTMLFormElement;
    const data = new FormData(form);
    error = "";
    try {
      if (job.plan?.auth_requirements.length) {
        const trust = trustByJob[job.id];
        if (!trust) {
          await loadSftpTrust(job.id);
          return;
        }
        const confirmed = trust.state === "match"
          || data.get("confirmHostKey") === "yes";
        if (!confirmed) {
          error = m.sftp_confirmation_required();
          return;
        }
        const credentialKind = String(data.get("credentialKind") || "password");
        await invoke("authorize_sftp_job", {
          id: job.id,
          authorization: {
            trustAction: trust.state === "unknown" ? "trust" : trust.state === "mismatch" ? "replace" : "match",
            credentialKind,
            username: String(data.get("username") || ""),
            password: credentialKind === "password" ? String(data.get("password") || "") : null,
            keyPath: credentialKind === "private_key" ? String(data.get("keyPath") || "") : null,
            passphrase: credentialKind === "private_key" ? String(data.get("passphrase") || "") || null : null,
          },
        });
      }
      const playlistMode = String(data.get("playlistMode") || "all");
      const selectedEntries = data.getAll("playlistEntry").map(Number).filter(Number.isSafeInteger);
      const updated = await invoke<JobSnapshot>("complete_job_selection", {
        id: job.id,
        selection: {
          format: data.get("format") ? String(data.get("format")) : null,
          subtitleLanguages: data.getAll("subtitle").map(String),
          selectedPlaylistEntries: playlistMode === "selected" ? selectedEntries : null,
        },
      });
      jobs = jobs.map((candidate) => candidate.id === updated.id ? updated : candidate);
    } catch (reason) {
      error = readableError(reason);
    }
  }

  interface AvailablePack {
    targetName: string;
    packId: string;
    version: string;
    target: string;
    securitySequence: number;
    size: number;
    installed: boolean;
  }

  function formatBytes(bytes: number): string {
    if (!Number.isFinite(bytes) || bytes < 0) return "—";
    const units = ["B", "KiB", "MiB", "GiB"];
    let value = bytes;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit += 1;
    }
    return `${new Intl.NumberFormat(currentLocale, { maximumFractionDigits: unit === 0 ? 0 : 1 }).format(value)} ${units[unit]}`;
  }

  function stateLabel(state: JobState): string {
    switch (state) {
      case "probing": return m.status_probing();
      case "queued": return m.status_queued();
      case "preparing": return m.status_preparing();
      case "downloading": return m.status_downloading();
      case "post_processing": return m.status_post_processing();
      case "paused": return m.status_paused();
      case "interrupted": return m.status_interrupted();
      case "completed": return m.status_completed();
      case "failed": return m.status_failed();
      case "canceled": return m.status_canceled();
      case "awaiting_selection": return m.analyze_action();
    }
  }

  function eta(job: JobSnapshot): string | null {
    if (!job.total_bytes || !job.speed_bytes_per_second || job.speed_bytes_per_second <= 0) return null;
    const seconds = Math.max(0, Math.ceil((job.total_bytes - job.downloaded_bytes) / job.speed_bytes_per_second));
    const minutes = Math.floor(seconds / 60);
    return minutes > 0 ? `${minutes}m ${seconds % 60}s` : `${seconds}s`;
  }

  function kindLabel(kind: SourceKind): string {
    switch (kind) {
      case "site_media": return m.source_site_media();
      case "live": return m.source_live();
      case "gallery": return m.source_gallery();
      case "manifest": return m.source_manifest();
      case "direct_file": return m.source_direct_file();
      case "metalink": return m.source_metalink();
    }
  }
</script>

<svelte:head>
  <title>{m.app_name()}</title>
</svelte:head>

{#key currentLocale}
<div class="app-shell" dir={direction}>
  <header class="topbar">
    <a class="brand" href="#top" aria-label={m.app_name()}>
      <span class="brand-mark" aria-hidden="true"><i></i><i></i><i></i></span>
      <span>
        <strong>{m.app_name()}</strong>
        <small>{m.tagline()}</small>
      </span>
    </a>
    <div class="header-actions">
      {#if appInfo}
        <span class="mode-chip">{appInfo.portable ? m.portable_mode() : m.installed_mode()}</span>
      {/if}
      {#if isBetaLocale}<span class="beta-chip">{m.translation_beta()}</span>{/if}
      <label class="locale-picker">
        <span class="sr-only">{m.language_label()}</span>
        <select value={currentLocale} onchange={changeLocale}>
          {#each locales as locale}
            <option value={locale}>{localeMetadata[locale].autonym}</option>
          {/each}
        </select>
      </label>
    </div>
  </header>

  <main id="top">
    {#if coreUpdate}
      <section class="update-banner" aria-live="polite">
        <div>
          <strong>{m.update_available({ version: coreUpdate.version })}</strong>
          <span>{coreUpdate.unsigned ? m.update_unsigned_notice() : ""}</span>
        </div>
        {#if coreUpdate.automaticApplySupported}
          <button class="primary-button" type="button" onclick={applyCoreUpdate} disabled={updatingCore}>
            {updatingCore ? m.update_preparing() : m.update_action()}
          </button>
        {:else}
          <a class="primary-button" href="https://github.com/horexdev/free-media-downloader/releases" target="_blank" rel="noreferrer">
            {m.update_manual_action()}
          </a>
        {/if}
      </section>
    {/if}
    <section class="hero" aria-labelledby="hero-title">
      <div class="eyebrow"><span></span> Web media · Live · Galleries · Files</div>
      <h1 id="hero-title">{m.tagline()}</h1>
      <p>{m.privacy_notice()}</p>

      <div class="composer">
        <div class="field media-field">
          <label for="media-url">{m.input_label()}</label>
          <div class="input-wrap">
            <span class="link-icon" aria-hidden="true">↗</span>
            <input
              id="media-url"
              type="url"
              bind:value={mediaUrl}
              placeholder={m.input_placeholder()}
              autocomplete="off"
              spellcheck="false"
              oninput={() => { route = null; error = ""; }}
              onkeydown={(event) => event.key === "Enter" && analyze()}
            />
            <button class="analyze-button" type="button" onclick={analyze} disabled={busy}>
              {m.analyze_action()}
            </button>
          </div>
        </div>

        <div class="field destination-field">
          <label for="destination">{m.destination_label()}</label>
          <button id="destination" class="destination-button" type="button" onclick={chooseDestination}>
            <span aria-hidden="true">⌁</span>
            <span class:placeholder={!destination}>{destination || m.destination_placeholder()}</span>
          </button>
        </div>

        {#if route}
          <div class="route-preview">
            <div>
              <span class="route-kind">{kindLabel(route.source_kind)}</span>
              <strong>{route.engines.join(" → ")}</strong>
              <small>{m.required_packs({ packs: route.required_packs.join(", ") })}</small>
            </div>
            <button class="primary-button" type="button" onclick={addJob} disabled={busy}>
              {m.add_action()} <span aria-hidden="true">→</span>
            </button>
          </div>
        {/if}

        {#if error}<p class="message error" role="alert">{error}</p>{/if}
        {#if notice}<p class="message notice" role="status">{notice}</p>{/if}
      </div>
    </section>

    <section class="dashboard" aria-labelledby="downloads-title">
      <div class="section-heading">
        <div>
          <span class="section-index">01</span>
          <h2 id="downloads-title">{m.downloads_title()}</h2>
        </div>
        <span class="queue-count">{jobs.length.toLocaleString(currentLocale)}</span>
      </div>

      {#if jobs.length === 0}
        <div class="empty-state">
          <div class="empty-graphic" aria-hidden="true"><span>↓</span></div>
          <div>
            <h3>{m.downloads_empty_title()}</h3>
            <p>{m.downloads_empty_body()}</p>
          </div>
        </div>
      {:else}
        <div class="job-list">
          {#each jobs as job (job.id)}
            <article class="job-card">
              <div class="job-status" data-state={job.state}></div>
              <div class="job-copy">
                <h3>{job.plan?.title || job.spec.source.value}</h3>
                <p>{job.plan ? kindLabel(job.plan.source_kind) : m.status_probing()}</p>
                {#if job.plan?.required_packs.length}
                  <small>{m.required_packs({ packs: job.plan.required_packs.join(", ") })}</small>
                {/if}
                {#if job.downloaded_bytes > 0}
                  <div class="job-progress" aria-hidden="true">
                    <span style:width={`${Math.max(0, Math.min(100, job.progress * 100))}%`}></span>
                  </div>
                  <small>
                    {formatBytes(job.downloaded_bytes)}
                    {#if job.total_bytes} / {formatBytes(job.total_bytes)}{/if}
                    {#if job.speed_bytes_per_second} · {formatBytes(job.speed_bytes_per_second)}/s{/if}
                    {#if eta(job)} · ETA {eta(job)}{/if}
                  </small>
                {/if}
                {#if job.state === "awaiting_selection" && job.plan}
                  <form class="selection-form" onsubmit={(event) => submitSelection(job, event)}>
                    {#if job.plan.formats.length > 1}
                      <label>{m.selection_format()}
                        <select name="format" required>
                          {#each job.plan.formats as format}
                            <option value={format.id}>{format.label}{format.container ? ` · ${format.container}` : ""}</option>
                          {/each}
                        </select>
                      </label>
                    {/if}
                    {#if job.plan.subtitles.length}
                      <fieldset>
                        <legend>{m.selection_subtitles()}</legend>
                        {#each job.plan.subtitles as language}
                          <label class="check-option"><input type="checkbox" name="subtitle" value={language} /> {language}</label>
                        {/each}
                      </fieldset>
                    {/if}
                    {#if job.plan.playlist_entries.length}
                      <fieldset>
                        <legend>{m.selection_playlist()}</legend>
                        <label class="check-option"><input type="radio" name="playlistMode" value="all" checked /> {m.playlist_all()}</label>
                        <label class="check-option"><input type="radio" name="playlistMode" value="selected" /> {m.playlist_selected()}</label>
                        <div class="playlist-options">
                          {#each job.plan.playlist_entries as entry}
                            <label class="check-option"><input type="checkbox" name="playlistEntry" value={entry.index} /> {entry.index}. {entry.title}</label>
                          {/each}
                        </div>
                      </fieldset>
                    {/if}
                    {#if job.plan.auth_requirements.length}
                      {#if trustByJob[job.id]}
                        {@const trust = trustByJob[job.id]}
                        <fieldset class:danger-field={trust.state === "mismatch"}>
                          <legend>{m.sftp_host_key()}</legend>
                          <p>{trust.host}:{trust.port} · {trust.algorithm}</p>
                          <code>{trust.fingerprintSha256}</code>
                          {#if trust.state !== "match"}
                            <label class="check-option">
                              <input type="checkbox" name="confirmHostKey" value="yes" />
                              {trust.state === "unknown" ? m.sftp_trust_unknown() : m.sftp_replace_key()}
                            </label>
                          {/if}
                          <label>{m.sftp_auth_method()}
                            <select name="credentialKind">
                              <option value="password">{m.sftp_password()}</option>
                              <option value="private_key">{m.sftp_private_key()}</option>
                            </select>
                          </label>
                          <label>{m.sftp_username()}<input name="username" autocomplete="username" required /></label>
                          <label>{m.sftp_password()}<input name="password" type="password" autocomplete="current-password" /></label>
                          <label>{m.sftp_private_key()}<span class="inline-input"><input id={`key-${job.id}`} name="keyPath" autocomplete="off" /><button type="button" onclick={() => choosePrivateKey(job.id)}>{m.choose_action()}</button></span></label>
                          <label>{m.sftp_passphrase()}<input name="passphrase" type="password" autocomplete="off" /></label>
                        </fieldset>
                      {:else}
                        <button class="secondary-button" type="button" onclick={() => loadSftpTrust(job.id)}>{m.sftp_configure()}</button>
                      {/if}
                    {/if}
                    <button class="primary-button" type="submit" disabled={job.plan.auth_requirements.length > 0 && !trustByJob[job.id]}>{m.selection_continue()}</button>
                  </form>
                {/if}
              </div>
              <div class="job-controls">
                <span class="state-chip">{stateLabel(job.state)}</span>
                {#if ["queued", "preparing", "downloading"].includes(job.state)}
                  <button type="button" onclick={() => jobAction("pause_job", job.id)}>{m.pause_action()}</button>
                {/if}
                {#if ["paused", "interrupted"].includes(job.state)}
                  <button type="button" onclick={() => jobAction("resume_job", job.id)}>{m.resume_action()}</button>
                {/if}
                {#if job.state === "failed"}
                  <button type="button" onclick={() => jobAction("retry_job", job.id)}>{m.retry_action()}</button>
                {/if}
                {#if !["completed", "failed", "canceled"].includes(job.state)}
                  <button type="button" class="danger-button" onclick={() => jobAction("cancel_job", job.id)}>{m.cancel_action()}</button>
                {/if}
              </div>
            </article>
          {/each}
        </div>
      {/if}
    </section>

    <aside class="pack-note">
      <span class="section-index">02</span>
      <div><h2>{m.packs_title()}</h2><p>{m.packs_notice()}</p></div>
      <div class="pack-dots" aria-hidden="true"><i></i><i></i><i></i><i></i></div>
    </aside>
    {#if availablePacks.length}
      <section class="job-list" aria-label={m.packs_title()}>
        {#each availablePacks as pack (pack.targetName)}
          <article class="job-card">
            <div class="job-copy"><h3>{pack.packId}</h3><p>{pack.version} · {pack.target} · {formatBytes(pack.size)}</p></div>
            {#if pack.installed}
              <span class="state-chip">{m.pack_installed()}</span>
            {:else}
              <button class="primary-button" type="button" onclick={() => installPack(pack)} disabled={installingPack !== ""}>
                {installingPack === pack.packId ? m.pack_installing() : m.pack_install_action()}
              </button>
            {/if}
          </article>
        {/each}
      </section>
    {/if}
  </main>
</div>
{/key}
