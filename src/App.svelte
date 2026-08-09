<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import { onMount } from "svelte";
  import * as m from "./lib/paraglide/messages.js";
  import { getLocale, locales, setLocale } from "./lib/paraglide/runtime.js";
  import { localeMetadata } from "./lib/locales.js";
  import type { AppInfo } from "./lib/bindings/AppInfo.js";
  import type { JobSnapshot } from "./lib/bindings/JobSnapshot.js";
  import type { JobState } from "./lib/bindings/JobState.js";
  import type { RouteDecision } from "./lib/bindings/RouteDecision.js";
  import type { SourceKind } from "./lib/bindings/SourceKind.js";

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

  const isBetaLocale = $derived(localeMetadata[currentLocale].review === "beta");
  const direction = $derived(localeMetadata[currentLocale].direction);

  onMount(async () => {
    updateDocumentLanguage();
    if (!hasDesktopBackend) {
      notice = m.backend_unavailable();
      return;
    }
    try {
      [appInfo, jobs] = await Promise.all([
        invoke<AppInfo>("get_app_info"),
        invoke<JobSnapshot[]>("list_jobs"),
      ]);
      await invoke("acknowledge_ui_ready");
      await refreshPacks();
    } catch (reason) {
      error = readableError(reason);
    }
  });

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

  interface AvailablePack {
    targetName: string;
    packId: string;
    version: string;
    target: string;
    securitySequence: number;
    installed: boolean;
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
              </div>
              <span class="state-chip">{stateLabel(job.state)}</span>
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
            <div class="job-copy"><h3>{pack.packId}</h3><p>{pack.version} · {pack.target}</p></div>
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
