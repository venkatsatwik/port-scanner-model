// PortSentinel Frontend Application Logic

let userConsented = false;
let scanPollInterval = null;
let allConnections = [];
let discoveredOpenPorts = [];

// DOM Elements
const modal = document.getElementById("consent-modal");
const btnConsent = document.getElementById("btn-grant-consent");
const navItems = document.querySelectorAll(".nav-item");
const tabPanels = document.querySelectorAll(".tab-panel");
const viewTitle = document.getElementById("view-title");
const viewDesc = document.getElementById("view-desc");

// Scan controls
const scanModeSelect = document.getElementById("scan-mode");
const customRangeBox = document.getElementById("custom-range-box");
const btnStartScan = document.getElementById("btn-start-scan");
const btnStopScan = document.getElementById("btn-stop-scan");
const progressBox = document.getElementById("scan-progress-box");
const progressBarFill = document.getElementById("progress-bar-fill");
const progPercent = document.getElementById("prog-percent");
const progStatusText = document.getElementById("prog-status-text");
const progDetailsText = document.getElementById("prog-details-text");
const progSpeed = document.getElementById("prog-speed");

// Overview and tables
const securityScoreElem = document.getElementById("security-score");
const scoreStatusBadge = document.getElementById("score-status-badge");
const securitySummary = document.getElementById("security-summary");
const recsList = document.getElementById("recommendations-list");
const statTotalConns = document.getElementById("stat-total-conns");
const statListeningPorts = document.getElementById("stat-listening-ports");
const statFlaggedConns = document.getElementById("stat-flagged-conns");
const badgeConnCount = document.getElementById("badge-conn-count");
const overviewListeningTbody = document.getElementById("overview-listening-tbody");
const connectionsTbody = document.getElementById("connections-tbody");
const openPortsTbody = document.getElementById("open-ports-tbody");
const openPortsCounter = document.getElementById("open-ports-counter");

// Filters & buttons
const connFilter = document.getElementById("conn-filter");
const connFilterType = document.getElementById("conn-filter-type");
const btnQuickAudit = document.getElementById("btn-quick-audit");
const btnExportJson = document.getElementById("btn-export-json");

// System info elements
const sysHostname = document.getElementById("sys-hostname");
const sysIp = document.getElementById("sys-ip");
const sysOs = document.getElementById("sys-os");
const sysEngine = document.getElementById("sys-engine");

// Initialize on page load
document.addEventListener("DOMContentLoaded", () => {
  setupNavigation();
  setupScanControls();
  fetchSystemInfo();

  // Check previous authorization
  if (sessionStorage.getItem("portsentinel_authorized") === "true") {
    userConsented = true;
    modal.classList.add("hidden");
    refreshSecurityAudit();
  } else {
    modal.classList.remove("hidden");
  }

  btnConsent.addEventListener("click", () => {
    userConsented = true;
    sessionStorage.setItem("portsentinel_authorized", "true");
    modal.classList.add("hidden");
    refreshSecurityAudit();
  });

  btnQuickAudit.addEventListener("click", () => {
    refreshSecurityAudit();
  });

  btnExportJson.addEventListener("click", exportAuditReport);

  // Search/filter listeners
  connFilter.addEventListener("input", renderConnectionsTable);
  connFilterType.addEventListener("change", renderConnectionsTable);
});

// Setup tab switches
function setupNavigation() {
  const titles = {
    "tab-overview": {
      title: "System Security Overview",
      desc: "Real-time health rating, port exposure, and background network traffic."
    },
    "tab-connections": {
      title: "Active & Secret Connections",
      desc: "Investigate applications sending data to remote external servers or listeners."
    },
    "tab-scanner": {
      title: "TCP Port Scanner",
      desc: "Multi-threaded socket scan across standard or all 65,535 ports."
    },
    "tab-guide": {
      title: "Learning & GitHub Guide",
      desc: "Learn networking concepts and follow our step-by-step GitHub tutorial."
    }
  };

  navItems.forEach(item => {
    item.addEventListener("click", () => {
      const targetTab = item.getAttribute("data-tab");
      navItems.forEach(n => n.classList.remove("active"));
      tabPanels.forEach(p => p.classList.remove("active"));

      item.classList.add("active");
      const activePanel = document.getElementById(targetTab);
      if (activePanel) activePanel.classList.add("active");

      if (titles[targetTab]) {
        viewTitle.textContent = titles[targetTab].title;
        viewDesc.textContent = titles[targetTab].desc;
      }
    });
  });
}

// System info API
async function fetchSystemInfo() {
  try {
    const res = await fetch("/api/system-info");
    if (!res.ok) return;
    const data = await res.json();
    sysHostname.textContent = data.hostname || "Local PC";
    sysIp.textContent = data.local_ip || "127.0.0.1";
    sysOs.textContent = data.os || "Windows";
    sysEngine.textContent = `Python ${data.python_version || "3"}`;
  } catch (err) {
    console.warn("Could not fetch system info", err);
  }
}

// Active Connections & Process Audit
async function refreshSecurityAudit() {
  try {
    const res = await fetch("/api/connections");
    if (!res.ok) return;
    const data = await res.json();
    
    allConnections = data.connections || [];
    badgeConnCount.textContent = allConnections.length;

    // Update Score & Status
    const score = data.security_score || 100;
    securityScoreElem.textContent = score;
    scoreStatusBadge.textContent = data.rating || "GOOD";
    securitySummary.textContent = data.summary || "System inspection complete.";

    // Apply color to score badge
    scoreStatusBadge.className = "badge";
    if (score >= 90) {
      scoreStatusBadge.classList.add("badge-safe");
      securityScoreElem.style.color = "var(--color-safe)";
    } else if (score >= 70) {
      scoreStatusBadge.classList.add("badge-warning");
      securityScoreElem.style.color = "var(--color-warning)";
    } else {
      scoreStatusBadge.classList.add("badge-danger");
      securityScoreElem.style.color = "var(--color-danger)";
    }

    // Recommendations
    recsList.innerHTML = "";
    const recs = data.recommendations || [];
    if (recs.length === 0) {
      recsList.innerHTML = `<div class="rec-item safe"><span class="rec-icon">✅</span><div><strong>System Healthy:</strong> No high-risk open ports or suspicious connections detected.</div></div>`;
    } else {
      recs.forEach(r => {
        const item = document.createElement("div");
        item.className = "rec-item " + (score < 75 ? "danger" : "warning");
        item.innerHTML = `<span class="rec-icon">${score < 75 ? "⚠️" : "💡"}</span><div>${r}</div>`;
        recsList.appendChild(item);
      });
    }

    // Metrics counts
    statTotalConns.textContent = allConnections.length;
    const listeners = allConnections.filter(c => c.state === "LISTENING");
    const flagged = allConnections.filter(c => c.suspicion_level === "SUSPICIOUS" || c.suspicion_level === "CRITICAL");
    statListeningPorts.textContent = listeners.length;
    statFlaggedConns.textContent = flagged.length;

    // Render tables
    renderOverviewListeners(listeners);
    renderConnectionsTable();

  } catch (err) {
    console.error("Failed to fetch connection audit", err);
  }
}

// Render Overview Listening Table
function renderOverviewListeners(listeners) {
  if (!listeners || listeners.length === 0) {
    overviewListeningTbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted">No open listening ports detected.</td></tr>`;
    return;
  }

  overviewListeningTbody.innerHTML = listeners.map(c => `
    <tr>
      <td><span class="port-badge">${c.local_port}</span></td>
      <td><strong>${c.protocol}</strong></td>
      <td><span class="proc-tag">${c.process_name}</span></td>
      <td>${c.pid}</td>
      <td>${getRiskBadge(c.suspicion_level)}</td>
      <td class="text-secondary">${c.reason}</td>
    </tr>
  `).join("");
}

// Render Connections Table with Filtering
function renderConnectionsTable() {
  const searchTerm = connFilter.value.toLowerCase().trim();
  const filterType = connFilterType.value;

  const filtered = allConnections.filter(c => {
    // Type filter
    if (filterType === "ESTABLISHED" && c.state !== "ESTABLISHED") return false;
    if (filterType === "LISTENING" && c.state !== "LISTENING") return false;
    if (filterType === "SUSPICIOUS" && c.suspicion_level === "SAFE") return false;

    // Text search
    if (searchTerm) {
      const matchText = `${c.process_name} ${c.pid} ${c.local_ip}:${c.local_port} ${c.foreign_ip}:${c.foreign_port} ${c.reason}`.toLowerCase();
      return matchText.includes(searchTerm);
    }
    return true;
  });

  if (filtered.length === 0) {
    connectionsTbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">No connections match the selected filter.</td></tr>`;
    return;
  }

  connectionsTbody.innerHTML = filtered.map(c => `
    <tr>
      <td><span class="proc-tag">${c.process_name}</span></td>
      <td>${c.pid}</td>
      <td><span class="port-badge">${c.local_ip}:${c.local_port}</span></td>
      <td>${c.foreign_ip === "0.0.0.0" ? "<span class='text-muted'>*</span>" : `<strong>${c.foreign_ip}:${c.foreign_port}</strong>`}</td>
      <td><span class="badge ${c.state === 'ESTABLISHED' ? 'badge-info' : 'badge-safe'}">${c.state}</span></td>
      <td>${getRiskBadge(c.suspicion_level)}</td>
      <td class="text-secondary">${c.reason}</td>
    </tr>
  `).join("");
}

function getRiskBadge(level) {
  if (level === "CRITICAL") return `<span class="badge badge-danger">CRITICAL</span>`;
  if (level === "SUSPICIOUS" || level === "HIGH") return `<span class="badge badge-warning">SUSPICIOUS</span>`;
  if (level === "MEDIUM") return `<span class="badge badge-warning">MEDIUM</span>`;
  return `<span class="badge badge-safe">SAFE</span>`;
}

// Scanner Controls & Polling
function setupScanControls() {
  scanModeSelect.addEventListener("change", () => {
    if (scanModeSelect.value === "custom") {
      customRangeBox.classList.remove("hidden");
    } else {
      customRangeBox.classList.add("hidden");
    }
  });

  btnStartScan.addEventListener("click", startPortScan);
  btnStopScan.addEventListener("click", stopPortScan);
}

async function startPortScan() {
  if (!userConsented) {
    modal.classList.remove("hidden");
    return;
  }

  const target = document.getElementById("scan-target").value.trim() || "127.0.0.1";
  const mode = scanModeSelect.value;
  const startPort = parseInt(document.getElementById("scan-start-port").value) || 1;
  const endPort = parseInt(document.getElementById("scan-end-port").value) || 1024;
  const concurrency = parseInt(document.getElementById("scan-concurrency").value) || 80;

  try {
    btnStartScan.disabled = true;
    const res = await fetch("/api/scan/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target,
        mode,
        start_port: startPort,
        end_port: endPort,
        concurrency,
        consent: true
      })
    });

    const data = await res.json();
    if (!res.ok || !data.success) {
      alert("Scan failed to start: " + (data.error || data.message));
      btnStartScan.disabled = false;
      return;
    }

    // UI State for scanning
    btnStartScan.classList.add("hidden");
    btnStopScan.classList.remove("hidden");
    progressBox.classList.remove("hidden");
    openPortsTbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">Scanning ports... Discovered open ports will appear here in real time.</td></tr>`;

    // Start polling status
    if (scanPollInterval) clearInterval(scanPollInterval);
    scanPollInterval = setInterval(pollScanStatus, 800);

  } catch (err) {
    alert("Connection error starting scan: " + err.message);
    btnStartScan.disabled = false;
  }
}

async function stopPortScan() {
  try {
    await fetch("/api/scan/stop", { method: "POST" });
  } catch (e) {
    console.error(e);
  }
}

async function pollScanStatus() {
  try {
    const res = await fetch("/api/status");
    if (!res.ok) return;
    const status = await res.json();

    const percentage = status.percentage || 0;
    progressBarFill.style.width = percentage + "%";
    progPercent.textContent = percentage + "%";
    progSpeed.textContent = `(${status.elapsed_seconds || 0}s elapsed)`;
    progDetailsText.textContent = `${status.scanned_ports || 0} / ${status.total_ports || 0} ports scanned`;

    if (status.status === "scanning") {
      progStatusText.textContent = `Scanning ${status.target}...`;
    } else if (status.status === "completed") {
      progStatusText.textContent = `Scan Complete! Found ${status.open_ports.length} open ports.`;
      finishScan(status);
    } else if (status.status === "stopped") {
      progStatusText.textContent = `Scan cancelled by user.`;
      finishScan(status);
    } else if (status.status === "error") {
      progStatusText.textContent = `Error: ${status.error_message}`;
      finishScan(status);
    }

    // Update discovered open ports in real time
    if (status.open_ports) {
      discoveredOpenPorts = status.open_ports;
      renderDiscoveredPorts(status.open_ports);
    }

  } catch (err) {
    console.warn("Poll status error", err);
  }
}

function finishScan(status) {
  if (scanPollInterval) {
    clearInterval(scanPollInterval);
    scanPollInterval = null;
  }
  btnStartScan.disabled = false;
  btnStartScan.classList.remove("hidden");
  btnStopScan.classList.add("hidden");
}

function renderDiscoveredPorts(ports) {
  openPortsCounter.textContent = `${ports.length} Open Ports`;

  if (ports.length === 0) {
    openPortsTbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No open ports found so far.</td></tr>`;
    return;
  }

  openPortsTbody.innerHTML = ports.map(p => `
    <tr>
      <td><span class="port-badge">${p.port}</span></td>
      <td><strong>${p.service}</strong></td>
      <td>${getRiskBadge(p.risk)}</td>
      <td class="text-secondary">${p.description}</td>
      <td><code>${p.banner || "None detected"}</code></td>
    </tr>
  `).join("");
}

// Export Audit Report
function exportAuditReport() {
  const report = {
    generated_at: new Date().toISOString(),
    system: {
      hostname: sysHostname.textContent,
      local_ip: sysIp.textContent,
      os: sysOs.textContent
    },
    security_score: securityScoreElem.textContent,
    active_connections_count: allConnections.length,
    active_connections: allConnections,
    discovered_open_ports: discoveredOpenPorts
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `portsentinel-audit-report-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}
