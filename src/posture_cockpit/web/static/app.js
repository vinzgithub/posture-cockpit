// Copyright © 2026 Vincent Fournet · SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Small improvements on top of pages that already work without JavaScript:
//   - plan: switch tasks and DNS hosts without reloading the page;
//   - copy buttons;
//   - a spinner on buttons that start a scan or a check (they take a few seconds);
//   - a confirmation before destructive actions (data-confirm).
"use strict";

(function () {
  const csrf = document.querySelector('meta[name="csrf"]')?.content || "";

  // ------------------------------------------------------------ plan: tasks
  // Task cards are links to ?task=<id>; here they show the matching panel directly.
  function showTask(id, scroll) {
    const panels = document.querySelectorAll("[data-panel]");
    if (!panels.length) return false;
    let found = false;
    panels.forEach((panel) => {
      const match = panel.dataset.panel === id;
      panel.hidden = !match;
      found = found || match;
    });
    if (!found) return false;
    document.querySelectorAll(".task-card[data-task]").forEach((card) => {
      if (card.dataset.task === id) card.setAttribute("aria-current", "true");
      else card.removeAttribute("aria-current");
    });
    const url = new URL(window.location.href);
    url.searchParams.set("task", id);
    url.hash = "";
    history.replaceState(null, "", url);
    // On a phone the panel is below the list: bring it into view.
    if (scroll && window.matchMedia("(max-width: 960px)").matches) {
      document.getElementById("task")?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
    return true;
  }

  document.addEventListener("click", (event) => {
    const link = event.target.closest("a[data-task]");
    if (!link || event.metaKey || event.ctrlKey || event.shiftKey) return;
    if (showTask(link.dataset.task, true)) event.preventDefault();
  });

  // -------------------------------------------------------- plan: DNS host
  // One choice for the whole domain: every panel switches, and the server remembers it.
  document.addEventListener("click", (event) => {
    const button = event.target.closest("form[data-dns-host] button[name='dns_host']");
    if (!button) return;
    event.preventDefault();
    const host = button.value;
    document.querySelectorAll("form[data-dns-host] button[name='dns_host']").forEach((b) => {
      b.setAttribute("aria-pressed", b.value === host ? "true" : "false");
    });
    document.querySelectorAll("ol[data-host]").forEach((list) => {
      list.hidden = list.dataset.host !== host;
    });
    const form = button.form;
    const body = new FormData(form);
    body.set("dns_host", host);
    fetch(form.action, { method: "POST", body, headers: { "X-CSRF-Token": csrf } }).catch(() => {});
  });

  // ------------------------------------------------------------ copy buttons
  const copiedLabel = document.documentElement.lang === "fr" ? "Copié ✓" : "Copied ✓";

  async function copy(button, text) {
    try {
      await navigator.clipboard.writeText(text);
    } catch (e) {
      return; // clipboard refused (plain HTTP, old browser): the text stays selectable
    }
    const label = button.textContent;
    button.textContent = copiedLabel;
    button.classList.add("is-copied");
    setTimeout(() => {
      button.textContent = label;
      button.classList.remove("is-copied");
    }, 1800);
  }

  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-copy], [data-copy-from]");
    if (!button) return;
    const source = button.dataset.copyFrom ? document.getElementById(button.dataset.copyFrom) : null;
    copy(button, source ? source.textContent : button.dataset.copy);
  });

  // ------------------------------------------------- confirmations and spinners
  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-confirm]");
    if (button && !window.confirm(button.dataset.confirm)) event.preventDefault();
  });

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!form.matches("[data-busy]")) return;
    const button = form.querySelector("[data-busy-label]");
    if (!button) return;
    // Disable after the submission has started, or the browser would not send the form.
    setTimeout(() => {
      button.disabled = true;
      const spinner = document.createElement("span");
      spinner.className = "spinner";
      spinner.setAttribute("aria-hidden", "true");
      const label = button.querySelector("strong") || button;
      label.textContent = button.dataset.busyLabel;
      button.prepend(spinner);
    }, 0);
  });
})();
