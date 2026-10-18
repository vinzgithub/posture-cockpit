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
    // The language switch comes back to this task, not to the first one.
    const back = document.querySelector("form.lang-switch input[name='back']");
    if (back) back.value = url.pathname + url.search;
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

  // Schedule fields: progressively enhance the server-rendered form.
  // When JavaScript is unavailable, every control stays visible and usable.
  document.querySelectorAll("[data-schedule-form]").forEach((form) => {
    const frequency = form.querySelector('select[name="frequency"]');
    if (!frequency) return;
    function syncScheduleFields() {
      const current = frequency.value;
      form.querySelectorAll("[data-schedule-field]").forEach((field) => {
        const kind = field.dataset.scheduleField;
        const visible = kind === "time" ? current !== "off"
          : kind === "weekday" ? current === "weekly"
          : kind === "monthday" ? current === "monthly" : true;
        field.hidden = !visible;
      });
    }
    frequency.addEventListener("change", syncScheduleFields);
    syncScheduleFields();
  });

  // ------------------------------------------------------------ copy buttons
  // navigator.clipboard only exists in secure contexts (HTTPS, localhost): at
  // http://192.168.x.x it is undefined. The older copy command still works there
  // when it runs during the click. If both fail, the value is selected on the page
  // and a message says how to copy it by hand. The text never leaves the page.
  const fr = document.documentElement.lang === "fr";
  const copiedLabel = fr ? "Copié ✓" : "Copied ✓";
  const manualText = fr
    ? "Copie automatique impossible ici : le texte est sélectionné, copiez-le avec Ctrl+C (sur mobile : appui long, puis Copier)."
    : "Automatic copy is not available here: the text is selected, copy it with Ctrl+C (on a phone: long press, then Copy).";

  function commandCopy(text) {
    const focused = document.activeElement;
    const area = document.createElement("textarea");
    area.value = text;
    area.readOnly = true;
    area.className = "copy-buffer";
    document.body.append(area);
    area.select();
    area.setSelectionRange(0, text.length);
    let done = false;
    try {
      done = document.execCommand("copy");
    } catch (e) {
      done = false;
    }
    area.remove();
    if (focused && focused.focus) focused.focus();
    return done;
  }

  function selectText(node) {
    const range = document.createRange();
    range.selectNodeContents(node);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
  }

  function report(button, done, shown) {
    const old = button.parentElement.querySelector(".copy-status");
    if (old) old.remove();
    if (!button.dataset.label) button.dataset.label = button.textContent;
    clearTimeout(Number(button.dataset.timer || 0));
    if (!done) {
      button.textContent = button.dataset.label;
      button.classList.remove("is-copied");
      if (shown) selectText(shown);
      const status = document.createElement("p");
      status.className = "copy-status";
      status.setAttribute("role", "status");
      status.textContent = manualText;
      button.after(status);
      return;
    }
    button.textContent = copiedLabel;
    button.classList.add("is-copied");
    button.dataset.timer = String(setTimeout(() => {
      button.textContent = button.dataset.label;
      button.classList.remove("is-copied");
    }, 1800));
  }

  async function copy(button, text, shown) {
    let done;
    if (window.isSecureContext && navigator.clipboard) {
      try {
        await navigator.clipboard.writeText(text);
        done = true;
      } catch (e) {
        done = commandCopy(text); // refused, in a frame without the permission for instance
      }
    } else {
      done = commandCopy(text); // plain HTTP: no clipboard API, still inside the click
    }
    report(button, done, shown);
  }

  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-copy], [data-copy-from]");
    if (!button) return;
    const source = button.dataset.copyFrom ? document.getElementById(button.dataset.copyFrom) : null;
    // What a person can select by hand: the source, or the value shown next to the button.
    const shown = source || button.parentElement.querySelector("code");
    copy(button, source ? source.textContent : button.dataset.copy, shown);
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
