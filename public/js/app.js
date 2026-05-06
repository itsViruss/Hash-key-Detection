function setStatus(element, text, type) {
  if (!element) {
    return;
  }
  element.textContent = text;
  element.className = `status-pill ${type}`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function copyText(text, successElement, successMessage) {
  if (!text || text === "-") {
    return;
  }

  navigator.clipboard.writeText(text).then(() => {
    if (successElement && successMessage) {
      successElement.textContent = successMessage;
    }
  });
}

function applyTheme(theme) {
  const body = document.body;
  const toggleLabel = document.getElementById("theme-toggle-label");
  const toggleIcon = document.getElementById("theme-toggle-icon");

  if (!body) {
    return;
  }

  const resolvedTheme = theme === "light" ? "light" : "dark";
  body.dataset.theme = resolvedTheme;

  if (toggleLabel && toggleIcon) {
    if (resolvedTheme === "light") {
      toggleIcon.textContent = "☀️";
      toggleLabel.textContent = "Light Mode";
    } else {
      toggleIcon.textContent = "🌙";
      toggleLabel.textContent = "Dark Mode";
    }
  }
}

function initThemeToggle() {
  const toggle = document.getElementById("theme-toggle");
  const savedTheme = localStorage.getItem("hash-simulator-theme") || "dark";

  applyTheme(savedTheme);

  if (!toggle) {
    return;
  }

  toggle.addEventListener("click", () => {
    const nextTheme = document.body.dataset.theme === "light" ? "dark" : "light";
    localStorage.setItem("hash-simulator-theme", nextTheme);
    applyTheme(nextTheme);
  });
}

function renderLogs(rows) {
  const tableBody = document.getElementById("logs-table");
  if (!tableBody) {
    return;
  }

  if (!rows.length) {
    tableBody.innerHTML = `<tr><td colspan="4">No secure transfer logs yet.</td></tr>`;
    return;
  }

  tableBody.innerHTML = rows
    .map(
      (row) => `
        <tr>
          <td>${row.filename}</td>
          <td>${row.algorithm}</td>
          <td>${new Date(row.timestamp).toLocaleString()}</td>
          <td><span class="table-badge ${row.result === "File Safe" ? "safe" : "danger"}">${row.result}</span></td>
        </tr>
      `
    )
    .join("");
}

async function loadLogs() {
  const response = await fetch("/api/logs");
  const data = await response.json();
  renderLogs(data.logs || []);
}

async function loadCollisionDemo() {
  const collisionContainer = document.getElementById("collision-content");
  if (!collisionContainer) {
    return;
  }

  const response = await fetch("/api/collision-demo");
  const data = await response.json();
  collisionContainer.innerHTML = `
    <div class="info-banner warning-banner">${data.note}</div>
    <div class="collision-entry">
      <h3>${data.file_a.name}</h3>
      <p><strong>Content</strong></p>
      <code>${data.file_a.content}</code>
      <p><strong>MD5</strong></p>
      <code>${data.file_a.md5}</code>
      <p><strong>SHA-256</strong></p>
      <code>${data.file_a.sha256}</code>
    </div>
    <div class="collision-entry">
      <h3>${data.file_b.name}</h3>
      <p><strong>Content</strong></p>
      <code>${data.file_b.content}</code>
      <p><strong>MD5</strong></p>
      <code>${data.file_b.md5}</code>
      <p><strong>SHA-256</strong></p>
      <code>${data.file_b.sha256}</code>
    </div>
  `;
}

function buildHashDiff(leftHash, rightHash) {
  const left = leftHash || "";
  const right = rightHash || "";
  const limit = Math.max(left.length, right.length, 1);
  let changedCount = 0;
  let leftHtml = "";
  let rightHtml = "";

  for (let index = 0; index < limit; index += 1) {
    const leftChar = left[index] ?? "";
    const rightChar = right[index] ?? "";
    const changed = leftChar !== rightChar;

    if (changed) {
      changedCount += 1;
    }

    leftHtml += `<span class="hash-char ${changed ? "changed" : ""}">${escapeHtml(leftChar || ".")}</span>`;
    rightHtml += `<span class="hash-char ${changed ? "changed" : ""}">${escapeHtml(rightChar || ".")}</span>`;
  }

  return { leftHtml, rightHtml, changedCount };
}

function setTransferProgress(progressRatio) {
  const packet = document.getElementById("transfer-packet");
  const progressBar = document.getElementById("transfer-progress-bar");
  const progressShell = document.querySelector(".transfer-progress-shell");

  if (!packet || !progressBar || !progressShell) {
    return;
  }

  const clamped = Math.max(0, Math.min(1, progressRatio));
  const shellWidth = progressShell.clientWidth;
  const packetWidth = packet.offsetWidth || 42;
  const leftPosition = packetWidth / 2 + clamped * Math.max(shellWidth - packetWidth, 0);

  progressShell.dataset.progress = String(clamped);
  progressBar.style.width = `${clamped * 100}%`;
  packet.style.left = `${leftPosition}px`;
}

function runTransferPacket(stage) {
  const states = {
    sending: document.getElementById("transfer-state-sending"),
    delivered: document.getElementById("transfer-state-delivered"),
    verified: document.getElementById("transfer-state-verified"),
  };

  const progressMap = {
    sender: 0,
    sending: 0.52,
    delivered: 1,
    verified: 1,
  };
  setTransferProgress(progressMap[stage] ?? 0);

  Object.values(states).forEach((element) => {
    if (element) {
      element.classList.remove("active-state");
    }
  });

  if (stage === "sending" && states.sending) {
    states.sending.classList.add("active-state");
  }
  if (stage === "delivered" && states.delivered) {
    states.delivered.classList.add("active-state");
  }
  if (stage === "verified" && states.verified) {
    states.verified.classList.add("active-state");
  }
}

function setFlowStage(stage, packetLabel) {
  const packet = document.getElementById("file-packet");
  const stages = {
    sender: document.getElementById("flow-sender"),
    attacker: document.getElementById("flow-attacker"),
    receiver: document.getElementById("flow-receiver"),
  };

  if (!packet || !stages.sender || !stages.attacker || !stages.receiver) {
    return;
  }

  packet.className = `file-packet at-${stage}`;
  packet.textContent = packetLabel || "FILE";

  Object.entries(stages).forEach(([key, element]) => {
    element.classList.toggle("active", key === stage);
  });
}

function updateStepList(progress) {
  const stepOrder = ["loaded", "inspected", "modified", "sent", "verified"];
  const items = Array.from(document.querySelectorAll(".step-item"));
  const firstPending = stepOrder.find((key) => !progress[key]);

  items.forEach((item) => {
    const key = item.dataset.step;
    item.classList.remove("pending", "active", "done");

    if (progress[key]) {
      item.classList.add("done");
      return;
    }

    if (firstPending === key) {
      item.classList.add("active");
    } else {
      item.classList.add("pending");
    }
  });
}

function renderTerminalHistory(history) {
  const historyElement = document.getElementById("terminal-history");
  if (!historyElement) {
    return;
  }

  if (!history || !history.length) {
    historyElement.innerHTML = `<div class="terminal-line system">Educational simulator booted. Select a file and type <code>load file</code> to start.</div>`;
    return;
  }

  historyElement.innerHTML = history
    .map((entry) => {
      const commandLine = `<div class="terminal-line command"><span class="terminal-prompt">&gt;</span> ${escapeHtml(entry.command)}</div>`;
      const outputClass = entry.kind || "info";
      const outputLine = `<div class="terminal-line output ${outputClass}"><pre>${escapeHtml(entry.output)}</pre></div>`;
      return `${commandLine}${outputLine}`;
    })
    .join("");

  historyElement.scrollTop = historyElement.scrollHeight;
}

function appendTerminalError(command, message) {
  const historyElement = document.getElementById("terminal-history");
  if (!historyElement) {
    return;
  }

  historyElement.insertAdjacentHTML(
    "beforeend",
    `
      <div class="terminal-line command"><span class="terminal-prompt">&gt;</span> ${escapeHtml(command)}</div>
      <div class="terminal-line output error"><pre>${escapeHtml(message)}</pre></div>
    `
  );
  historyElement.scrollTop = historyElement.scrollHeight;
}

function updateTerminalMode(data) {
  const shell = document.getElementById("lab-shell");
  const label = document.getElementById("lab-mode-label");
  const copy = document.getElementById("lab-mode-copy");

  if (!shell || !label || !copy) {
    return;
  }

  const packetLabel = data.filename ? data.filename.slice(0, 8).toUpperCase() : "FILE";
  setFlowStage(data.stage || "sender", packetLabel);

  shell.classList.toggle("mitm-mode", Boolean(data.modified));
  shell.classList.toggle("safe-mode", !data.modified);

  if (!data.progress.loaded) {
    label.textContent = "Idle Terminal";
    copy.textContent = "The file has not been loaded yet. The sender, attacker, and receiver are waiting for commands.";
    return;
  }

  if (data.progress.verified) {
    label.textContent = data.safe ? "Receiver Accepted File" : "Receiver Detected Tampering";
    copy.textContent = data.safe
      ? "Verification succeeded because the receiver hash matched the sender hash."
      : "Verification failed because the receiver hash no longer matched the sender hash.";
    return;
  }

  if (data.stage === "attacker") {
    label.textContent = "Attacker Terminal Active";
    copy.textContent = data.modified
      ? "The attacker has changed the working copy. Hashes should now differ from the sender's original fingerprint."
      : "The attacker has access to the file but has not changed it yet.";
    return;
  }

  if (data.stage === "receiver") {
    label.textContent = "Receiver Waiting to Verify";
    copy.textContent = "The file reached the receiver. Run verify to compare sender and receiver hashes.";
    return;
  }

  label.textContent = "Sender Loaded File";
  copy.textContent = "The sender hash is locked in. Inspect or tamper with the working copy from the terminal.";
}

function initHashTool() {
  const form = document.getElementById("hash-form");
  if (!form) {
    return;
  }

  const status = document.getElementById("hash-status");
  const hashValue = document.getElementById("hash-value");
  const algorithmLabel = document.getElementById("hash-algorithm-label");
  const fileSize = document.getElementById("hash-file-size");
  const securityIndicator = document.getElementById("hash-security-indicator");
  const copyButton = document.getElementById("copy-hash-button");

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    setStatus(status, "Generating hash...", "neutral");

    const response = await fetch(form.dataset.endpoint, {
      method: "POST",
      body: new FormData(form),
    });
    const data = await response.json();

    if (!response.ok) {
      setStatus(status, "Hash generation failed", "danger");
      hashValue.textContent = data.error || "Unexpected error.";
      return;
    }

    hashValue.textContent = data.hash_value;
    algorithmLabel.textContent = data.algorithm;
    fileSize.textContent = `File size: ${data.file_size} bytes`;
    securityIndicator.innerHTML = `<span class="table-badge ${data.security_label === "Secure" ? "safe" : "danger"}">${data.security_label}</span>`;
    setStatus(status, "Hash Ready", data.security_label === "Secure" ? "safe" : "danger");
  });

  copyButton.addEventListener("click", () => {
    copyText(hashValue.textContent, securityIndicator, "Hash copied to clipboard");
  });
}

function initSecureTransfer() {
  const form = document.getElementById("transfer-form");
  if (!form) {
    return;
  }

  const submit = document.getElementById("transfer-submit");
  const status = document.getElementById("transfer-status");
  const algorithm = document.getElementById("transfer-algorithm");
  const senderHash = document.getElementById("transfer-sender-hash");
  const receiverHash = document.getElementById("transfer-receiver-hash");
  const signatureStatus = document.getElementById("transfer-signature-status");
  const encryptionSummary = document.getElementById("transfer-encryption-summary");
  const deliveryMessage = document.getElementById("transfer-delivery-message");
  const shareMessage = document.getElementById("transfer-share-message");
  const downloadButton = document.getElementById("download-file-button");
  const copyHashButton = document.getElementById("copy-transfer-hash-button");
  const progressShell = document.querySelector(".transfer-progress-shell");
  let downloadObjectUrl = "";

  runTransferPacket("sender");

  window.addEventListener("resize", () => {
    if (!progressShell) {
      return;
    }
    const savedProgress = Number(progressShell.dataset.progress || "0");
    setTransferProgress(savedProgress);
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();

    submit.disabled = true;
    submit.classList.add("is-loading");
    submit.textContent = "Transferring...";
    setStatus(status, "Sending...", "neutral");
    runTransferPacket("sending");

    const formData = new FormData(form);
    const signatureToggle = document.getElementById("transfer-signature-toggle");
    const encryptionToggle = document.getElementById("transfer-encryption-toggle");
    formData.set("enable_signature", signatureToggle.checked ? "true" : "false");
    formData.set("encrypt_file", encryptionToggle.checked ? "true" : "false");

    const response = await fetch(form.dataset.endpoint, {
      method: "POST",
      body: formData,
    });
    const data = await response.json();

    if (!response.ok) {
      setStatus(status, "Transfer failed", "danger");
      deliveryMessage.textContent = data.error || "Unexpected error.";
      downloadButton.href = "#";
      downloadButton.classList.add("disabled-link");
      downloadButton.setAttribute("aria-disabled", "true");
      submit.disabled = false;
      submit.classList.remove("is-loading");
      submit.textContent = "Start Secure Transfer";
      return;
    }

    algorithm.textContent = `Algorithm: ${data.algorithm}`;
    senderHash.textContent = data.sender_hash;
    receiverHash.textContent = data.receiver_hash;
    signatureStatus.textContent = data.enable_signature
      ? (data.signature_valid ? "Signature valid" : "Signature failed")
      : "Digital signature disabled";
    encryptionSummary.textContent = data.encryption_summary;
    deliveryMessage.textContent = data.delivery_message;
    shareMessage.textContent = data.share_message;

    runTransferPacket("delivered");
    setTimeout(() => {
      runTransferPacket("verified");
    }, 600);

    setStatus(status, data.safe ? "Safe" : "Tampered", data.safe ? "safe" : "danger");

    if (downloadObjectUrl) {
      URL.revokeObjectURL(downloadObjectUrl);
      downloadObjectUrl = "";
    }

    if (data.download_payload_b64) {
      const binary = atob(data.download_payload_b64);
      const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
      const blob = new Blob([bytes], { type: "application/octet-stream" });
      downloadObjectUrl = URL.createObjectURL(blob);
      downloadButton.href = downloadObjectUrl;
      downloadButton.download = data.download_name || "received-file.bin";
      downloadButton.classList.remove("disabled-link");
      downloadButton.removeAttribute("aria-disabled");
    } else if (data.download_url) {
      downloadButton.href = data.download_url;
      downloadButton.download = data.download_name || "";
      downloadButton.classList.remove("disabled-link");
      downloadButton.removeAttribute("aria-disabled");
    }

    submit.disabled = false;
    submit.classList.remove("is-loading");
    submit.textContent = "Start Secure Transfer";
  });

  copyHashButton.addEventListener("click", () => {
    copyText(senderHash.textContent, shareMessage, "Hash copied. Share it with the receiver.");
  });
}

function updateSimulationDashboard(data) {
  const senderHash = document.getElementById("simulation-sender-hash");
  const currentHash = document.getElementById("simulation-current-hash");
  const receiverHash = document.getElementById("simulation-receiver-hash");
  const signatureStatus = document.getElementById("simulation-signature-status");
  const status = document.getElementById("simulation-status");
  const algorithm = document.getElementById("simulation-algorithm");
  const summary = document.getElementById("simulation-summary");
  const hashDiffSummary = document.getElementById("hash-diff-summary");
  const learningCopy = document.getElementById("learning-copy");

  algorithm.textContent = `Algorithm: ${data.algorithm}`;
  summary.textContent = data.last_output || data.learning_message || "The terminal output and learning panel will explain each command as you use it.";
  learningCopy.textContent = data.learning_message || "Use terminal commands to load, inspect, tamper, send, and verify the simulated file transfer.";

  const workingDiff = buildHashDiff(data.sender_hash, data.current_hash);
  senderHash.innerHTML = workingDiff.leftHtml;
  currentHash.innerHTML = workingDiff.rightHtml;

  if (data.receiver_hash) {
    const receiverDiff = buildHashDiff(data.sender_hash, data.receiver_hash);
    receiverHash.innerHTML = receiverDiff.rightHtml;
  } else {
    receiverHash.textContent = "-";
  }

  if (!data.enable_signature) {
    signatureStatus.textContent = "Digital signature disabled";
  } else if (typeof data.signature_valid === "boolean") {
    signatureStatus.textContent = data.signature_valid ? "Signature valid" : "Signature failed";
  } else {
    signatureStatus.textContent = "Waiting for verify";
  }

  if (data.progress.verified) {
    setStatus(status, data.safe ? "Safe" : "Tampered", data.safe ? "safe" : "danger");
  } else if (data.modified) {
    setStatus(status, "Tampering in Progress", "danger");
  } else if (data.progress.loaded) {
    setStatus(status, "Loaded in Terminal", "neutral");
  } else {
    setStatus(status, "Awaiting terminal input", "neutral");
  }

  hashDiffSummary.textContent = data.modified
    ? `${workingDiff.changedCount} hash positions differ between the sender and current working copy. This demonstrates the avalanche effect.`
    : "No tampering has been applied yet, so the current working hash still matches the sender hash.";

  updateStepList(data.progress);
  updateTerminalMode(data);
}

function initSimulationTerminal() {
  const form = document.getElementById("terminal-form");
  if (!form) {
    return;
  }

  const input = document.getElementById("terminal-command");
  const fileInput = document.getElementById("simulation-file");
  const algorithmSelect = document.getElementById("simulation-algorithm-select");
  const signatureToggle = document.getElementById("simulation-signature-toggle");
  const submitButton = document.getElementById("terminal-submit");
  const commandChips = Array.from(document.querySelectorAll(".command-chip"));

  let sessionId = "";
  let sessionBlob = "";

  commandChips.forEach((chip) => {
    chip.addEventListener("click", () => {
      input.value = chip.textContent;
      input.focus();
    });
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const command = input.value.trim();
    if (!command) {
      return;
    }

    submitButton.disabled = true;
    submitButton.classList.add("is-loading");
    submitButton.textContent = "Running";

    const formData = new FormData();
    formData.append("command", command);
    formData.append("session_id", sessionId);
    formData.append("session_blob", sessionBlob);
    formData.append("algorithm", algorithmSelect.value);
    formData.append("enable_signature", signatureToggle.checked ? "true" : "false");

    if (command.toLowerCase() === "load file" && fileInput.files[0]) {
      formData.append("file", fileInput.files[0]);
    }

    const response = await fetch("/api/simulation-terminal", {
      method: "POST",
      body: formData,
    });
    const data = await response.json();

    if (!response.ok) {
      appendTerminalError(command, data.error || "Unexpected terminal error.");
      document.getElementById("learning-copy").textContent = data.error || "Unexpected terminal error.";
      setStatus(document.getElementById("simulation-status"), "Command failed", "danger");
      submitButton.disabled = false;
      submitButton.classList.remove("is-loading");
      submitButton.textContent = "Run";
      input.focus();
      return;
    }

    sessionId = data.session_id;
    sessionBlob = data.session_blob || "";
    renderTerminalHistory(data.history);
    updateSimulationDashboard(data);

    input.value = "";
    submitButton.disabled = false;
    submitButton.classList.remove("is-loading");
    submitButton.textContent = "Run";
    input.focus();
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initThemeToggle();
  const page = document.body.dataset.page;

  if (page === "hash") {
    initHashTool();
  }

  if (page === "transfer") {
    initSecureTransfer();
  }

  if (page === "simulation") {
    initSimulationTerminal();
    loadCollisionDemo();
  }

  if (page === "logs") {
    loadLogs();
  }
});
