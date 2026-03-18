const API_BASE = '';

let currentPage = 1;
let totalLogs = 0;
let currentFilters = {};
let selectedFile = null;

const elements = {
  logCount: document.getElementById('logCount'),
  totalLogs: document.getElementById('totalLogs'),
  totalSources: document.getElementById('totalSources'),
  timeRange: document.getElementById('timeRange'),
  logList: document.getElementById('logList'),
  emptyState: document.getElementById('emptyState'),
  pagination: document.getElementById('pagination'),
  pageInfo: document.getElementById('pageInfo'),
  searchInput: document.getElementById('searchInput'),
  sourceFilter: document.getElementById('sourceFilter'),
  levelFilter: document.getElementById('levelFilter'),
  startTime: document.getElementById('startTime'),
  endTime: document.getElementById('endTime'),
  uploadModal: document.getElementById('uploadModal'),
  pasteModal: document.getElementById('pasteModal'),
  configModal: document.getElementById('configModal'),
  logDetailModal: document.getElementById('logDetailModal'),
  logDetailBody: document.getElementById('logDetailBody'),
  dropZone: document.getElementById('dropZone'),
  fileInput: document.getElementById('fileInput'),
  fileInfo: document.getElementById('fileInfo'),
  pasteArea: document.getElementById('pasteArea'),
  vtApiKey: document.getElementById('vtApiKey'),
  extractIp: document.getElementById('extractIp'),
  extractHostname: document.getElementById('extractHostname'),
  extractUrl: document.getElementById('extractUrl'),
  extractHash: document.getElementById('extractHash'),
};

const levelColors = {
  CRITICAL: '#ff7b72',
  FATAL: '#ff7b72',
  ERROR: '#f85149',
  WARN: '#d29922',
  WARNING: '#d29922',
  INFO: '#58a6ff',
  DEBUG: '#8b949e',
  TRACE: '#8b949e',
};

function formatTimestamp(ts) {
  if (!ts) return '-';
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;
  return d.toLocaleString('en-US', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

async function fetchLogs(filters = {}, page = 1) {
  const params = new URLSearchParams({
    limit: 50,
    offset: (page - 1) * 50,
    ...filters,
  });
  
  const res = await fetch(`${API_BASE}/api/logs?${params}`);
  const data = await res.json();
  return data;
}

async function loadLogs(page = 1) {
  currentPage = page;
  const filters = getFilters();
  
  try {
    const data = await fetchLogs(filters, page);
    totalLogs = data.total;
    renderLogs(data.logs);
    renderPagination();
    updateStats();
  } catch (err) {
    console.error('Failed to load logs:', err);
  }
}

function getFilters() {
  const filters = {};
  const search = elements.searchInput.value.trim();
  const source = elements.sourceFilter.value;
  const level = elements.levelFilter.value;
  const start = elements.startTime.value;
  const end = elements.endTime.value;
  
  if (search) filters.search = search;
  if (source) filters.source = source;
  if (level) filters.level = level;
  if (start) filters.start = new Date(start).toISOString();
  if (end) filters.end = new Date(end).toISOString();
  
  currentFilters = filters;
  return filters;
}

function renderLogs(logs) {
  if (!logs || logs.length === 0) {
    elements.logList.innerHTML = '';
    elements.emptyState.style.display = 'flex';
    return;
  }
  
  elements.emptyState.style.display = 'none';
  
  const extractTags = (val, type) => {
    if (!val) return '';
    return val.split(',').filter(v => v.trim()).map(v => `<span class="extract-tag ${type}">${escapeHtml(v.trim())}</span>`).join('');
  };
  
  elements.logList.innerHTML = logs.map(log => {
    const indicators = [];
    if (log.ip) indicators.push(...log.ip.split(',').filter(i => i.trim()));
    if (log.hostname) indicators.push(...log.hostname.split(',').filter(h => h.trim()));
    if (log.url) indicators.push(...log.url.split(',').filter(u => u.trim()));
    if (log.hash) indicators.push(...log.hash.split(',').filter(h => h.trim()));
    
    return `
    <div class="log-entry level-${log.level}" data-id="${log.id}">
      <span class="log-timestamp">${formatTimestamp(log.timestamp)}</span>
      <span class="log-level ${log.level}">${log.level}</span>
      <span class="log-source" title="${log.source}">${log.source}</span>
      <span class="log-extract">${indicators.map(i => `<span class="extract-tag" title="${escapeHtml(i)}">${escapeHtml(i.length > 20 ? i.substring(0, 20) + '...' : i)}</span>`).join('')}</span>
      <span class="log-message" title="${escapeHtml(log.message)}">${escapeHtml(log.message)}</span>
    </div>
  `}).join('');
  
  elements.logList.querySelectorAll('.log-entry').forEach(el => {
    el.addEventListener('click', () => showLogDetail(el.dataset.id));
  });
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function renderPagination() {
  const totalPages = Math.ceil(totalLogs / 50);
  elements.pageInfo.textContent = `Page ${currentPage} of ${totalPages} (${totalLogs} logs)`;
  elements.pagination.querySelector('#prevPage').disabled = currentPage <= 1;
  elements.pagination.querySelector('#nextPage').disabled = currentPage >= totalPages;
}

async function updateStats() {
  try {
    const res = await fetch(`${API_BASE}/api/stats`);
    const stats = await res.json();
    
    elements.logCount.textContent = `${stats.total} logs`;
    elements.totalLogs.textContent = stats.total;
    elements.totalSources.textContent = stats.sources?.length || 0;
    
    if (stats.timeRange?.earliest && stats.timeRange?.latest) {
      elements.timeRange.textContent = `${formatTimestamp(stats.timeRange.earliest)} - ${formatTimestamp(stats.timeRange.latest)}`;
    }
    
    elements.sourceFilter.innerHTML = '<option value="">All Sources</option>' +
      (stats.sources || []).map(s => `<option value="${s.source}">${s.source} (${s.count})</option>`).join('');
  } catch (err) {
    console.error('Failed to update stats:', err);
  }
}

async function showLogDetail(id) {
  try {
    const res = await fetch(`${API_BASE}/api/logs/${id}`);
    const log = await res.json();
    
    const indicators = extractIndicatorsFromLog(log);
    
    elements.logDetailBody.innerHTML = `
      <div class="detail-section">
        <h3>Log Information</h3>
        <div class="detail-row">
          <span class="detail-label">ID</span>
          <span class="detail-value">${log.id}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Timestamp</span>
          <span class="detail-value">${formatTimestamp(log.timestamp)}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Source</span>
          <span class="detail-value">${escapeHtml(log.source)}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Level</span>
          <span class="detail-value"><span class="log-level ${log.level}">${log.level}</span></span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Message</span>
          <span class="detail-value">${escapeHtml(log.message)}</span>
        </div>
      </div>
      
      <div class="detail-section">
        <h3>Indicators</h3>
        <div class="indicator-list" id="indicatorList">
          ${indicators.map(ind => `
            <span class="indicator-tag" data-type="${ind.type}" data-value="${ind.value}">
              <span class="indicator-type">${ind.type}</span>
              <span class="indicator-value">${ind.value}</span>
              <button class="btn btn-secondary enrich-btn" onclick="enrichIndicator('${ind.type}', '${ind.value}', this)">Check VT</button>
            </span>
          `).join('') || '<span style="color: var(--text-muted)">No indicators found</span>'}
        </div>
      </div>
      
      <div class="detail-section">
        <h3>Raw Log</h3>
        <div class="raw-content">${escapeHtml(log.raw)}</div>
      </div>
    `;
    
    elements.logDetailModal.classList.add('active');
  } catch (err) {
    console.error('Failed to load log detail:', err);
  }
}

function extractIndicatorsFromLog(log) {
  const indicators = [];
  const text = log.raw || log.message || '';
  
  const ipPattern = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  const ips = text.match(ipPattern) || [];
  [...new Set(ips)].filter(ip => !ip.startsWith('0') && !ip.startsWith('255.') && !ip.match(/^127\./)).forEach(ip => {
    indicators.push({ type: 'ip', value: ip });
  });
  
  const domainPattern = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|edu|gov|co|info|biz|ru|cn|xyz|top|tk|ml|ga|cf|gq|pw|cc|ws|su|onion)\b/gi;
  const domains = text.match(domainPattern) || [];
  [...new Set(domains)].filter(d => !d.includes('localhost') && d.length > 3).forEach(d => {
    indicators.push({ type: 'domain', value: d });
  });
  
  const urlPattern = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi;
  const urls = text.match(urlPattern) || [];
  [...new Set(urls)].forEach(url => {
    indicators.push({ type: 'url', value: url });
  });
  
  const md5Pattern = /\b[a-fA-F0-9]{32}\b/g;
  const sha1Pattern = /\b[a-fA-F0-9]{40}\b/g;
  const sha256Pattern = /\b[a-fA-F0-9]{64}\b/g;
  
  const md5s = text.match(md5Pattern) || [];
  const sha1s = text.match(sha1Pattern) || [];
  const sha256s = text.match(sha256Pattern) || [];
  
  [...new Set(md5s)].forEach(h => indicators.push({ type: 'hash', value: h }));
  [...new Set(sha1s)].forEach(h => indicators.push({ type: 'hash', value: h }));
  [...new Set(sha256s)].forEach(h => indicators.push({ type: 'hash', value: h }));
  
  return indicators;
}

async function enrichIndicator(type, value, btn) {
  const tag = btn.closest('.indicator-tag');
  tag.classList.add('loading');
  btn.disabled = true;
  btn.textContent = 'Checking...';
  
  try {
    const res = await fetch(`${API_BASE}/api/enrich`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ indicator: value, type: type === 'hash' ? 'file' : type }),
    });
    
    const data = await res.json();
    
    if (data.result?.data) {
      const stats = data.result.data.attributes?.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const undetected = stats.undetected || 0;
      const suspicious = stats.suspicious || 0;
      const total = malicious + undetected + suspicious;
      
      const vtDiv = document.createElement('div');
      vtDiv.className = `vt-result ${malicious > 0 ? 'malicious' : 'clean'}`;
      vtDiv.innerHTML = `
        <div class="vt-stats">
          <span class="vt-stat malicious">${malicious} malicious</span>
          <span class="vt-stat" style="color: var(--warning)">${suspicious} suspicious</span>
          <span class="vt-stat" style="color: var(--success)">${undetected} undetected</span>
        </div>
        ${data.cached ? '<small style="color: var(--text-muted)">Cached result</small>' : ''}
      `;
      
      tag.appendChild(vtDiv);
      tag.classList.add('enriched');
      btn.textContent = '✓ Checked';
    } else if (data.result?.not_found) {
      btn.textContent = 'Not found';
    } else {
      btn.textContent = 'Error';
    }
  } catch (err) {
    console.error('Enrichment error:', err);
    btn.textContent = 'Error';
  }
  
  tag.classList.remove('loading');
}

async function importLogs(content, filename) {
  const formData = new FormData();
  formData.append('content', content);
  formData.append('filename', filename);
  
  try {
    const res = await fetch(`${API_BASE}/api/logs/import`, {
      method: 'POST',
      body: formData,
    });
    
    const data = await res.json();
    
    if (data.success) {
      loadLogs(1);
      closeAllModals();
      selectedFile = null;
      elements.fileInfo.innerHTML = '';
    } else {
      alert('Import failed: ' + data.error);
    }
  } catch (err) {
    console.error('Import error:', err);
    alert('Import failed: ' + err.message);
  }
}

function openModal(modal) {
  modal.classList.add('active');
}

function closeModal(modal) {
  modal.classList.remove('active');
}

function closeAllModals() {
  document.querySelectorAll('.modal').forEach(m => closeModal(m));
}

document.getElementById('uploadBtn').addEventListener('click', () => openModal(elements.uploadModal));
document.getElementById('pasteBtn').addEventListener('click', () => openModal(elements.pasteModal));
document.getElementById('configBtn').addEventListener('click', async () => {
  const res = await fetch(`${API_BASE}/api/config/vt-key`);
  const data = await res.json();
  elements.vtApiKey.value = data.configured ? '********' : '';
  
  const extractRes = await fetch(`${API_BASE}/api/config/extraction`);
  const extractData = await extractRes.json();
  elements.extractIp.checked = extractData.ip !== false;
  elements.extractHostname.checked = extractData.hostname !== false;
  elements.extractUrl.checked = extractData.url !== false;
  elements.extractHash.checked = extractData.hash !== false;
  
  openModal(elements.configModal);
});

document.getElementById('clearBtn').addEventListener('click', async () => {
  if (confirm('Clear all logs and enrichments? This cannot be undone.')) {
    await fetch(`${API_BASE}/api/logs`, { method: 'DELETE' });
    loadLogs(1);
  }
});

document.getElementById('closeUpload').addEventListener('click', () => closeModal(elements.uploadModal));
document.getElementById('closePaste').addEventListener('click', () => closeModal(elements.pasteModal));
document.getElementById('closeConfig').addEventListener('click', () => closeModal(elements.configModal));
document.getElementById('closeDetail').addEventListener('click', () => closeModal(elements.logDetailModal));

document.getElementById('cancelUpload').addEventListener('click', () => closeModal(elements.uploadModal));
document.getElementById('cancelPaste').addEventListener('click', () => closeModal(elements.pasteModal));
document.getElementById('cancelConfig').addEventListener('click', () => closeModal(elements.configModal));

elements.dropZone.addEventListener('click', () => elements.fileInput.click());
elements.dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  elements.dropZone.classList.add('dragover');
});
elements.dropZone.addEventListener('dragleave', () => elements.dropZone.classList.remove('dragover'));
elements.dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  elements.dropZone.classList.remove('dragover');
  if (e.dataTransfer.files.length) {
    selectedFile = e.dataTransfer.files[0];
    elements.fileInfo.innerHTML = `<strong>${selectedFile.name}</strong> (${formatBytes(selectedFile.size)})`;
  }
});

elements.fileInput.addEventListener('change', (e) => {
  if (e.target.files.length) {
    selectedFile = e.target.files[0];
    elements.fileInfo.innerHTML = `<strong>${selectedFile.name}</strong> (${formatBytes(selectedFile.size)})`;
  }
});

document.getElementById('importFile').addEventListener('click', async () => {
  if (!selectedFile) {
    alert('Please select a file');
    return;
  }
  
  const content = await selectedFile.text();
  importLogs(content, selectedFile.name);
});

document.getElementById('importPaste').addEventListener('click', () => {
  const content = elements.pasteArea.value.trim();
  if (!content) {
    alert('Please paste some logs');
    return;
  }
  importLogs(content, 'paste.log');
  elements.pasteArea.value = '';
});

document.getElementById('saveConfig').addEventListener('click', async () => {
  const apiKey = elements.vtApiKey.value.trim();
  if (apiKey && apiKey !== '********') {
    await fetch(`${API_BASE}/api/config/vt-key`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ apiKey }),
    });
  }
  
  await fetch(`${API_BASE}/api/config/extraction`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      ip: elements.extractIp.checked,
      hostname: elements.extractHostname.checked,
      url: elements.extractUrl.checked,
      hash: elements.extractHash.checked
    }),
  });
  
  closeModal(elements.configModal);
  alert('Settings saved!');
});

document.getElementById('applyFilter').addEventListener('click', () => loadLogs(1));

document.getElementById('exportBtn').addEventListener('click', () => {
  const filters = getFilters();
  const params = new URLSearchParams(filters);
  const url = `${API_BASE}/api/logs/export?${params}`;
  window.open(url, '_blank');
});

document.getElementById('prevPage').addEventListener('click', () => {
  if (currentPage > 1) loadLogs(currentPage - 1);
});

document.getElementById('nextPage').addEventListener('click', () => {
  if (currentPage * 50 < totalLogs) loadLogs(currentPage + 1);
});

document.querySelectorAll('.modal').forEach(modal => {
  modal.addEventListener('click', (e) => {
    if (e.target === modal) closeModal(modal);
  });
});

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function initColumnResize() {
  const resizeHandles = document.querySelectorAll('.resize-handle');
  let currentHandle = null;
  let startX = 0;
  let startWidth = 0;
  let colName = '';
  
  resizeHandles.forEach(handle => {
    handle.addEventListener('mousedown', (e) => {
      currentHandle = handle;
      colName = handle.parentElement.dataset.col;
      startX = e.pageX;
      const cell = handle.parentElement;
      startWidth = cell.offsetWidth;
      handle.classList.add('active');
      document.body.style.cursor = 'col-resize';
      document.body.style.userSelect = 'none';
    });
  });
  
  document.addEventListener('mousemove', (e) => {
    if (!currentHandle) return;
    
    const diff = e.pageX - startX;
    const newWidth = Math.max(50, Math.min(500, startWidth + diff));
    
    const root = document.documentElement;
    const varName = `--col-${colName}-width`;
    root.style.setProperty(varName, newWidth + 'px');
    
    const headerCell = document.querySelector(`.log-header-cell[data-col="${colName}"]`);
    if (headerCell) {
      headerCell.style.width = newWidth + 'px';
    }
  });
  
  document.addEventListener('mouseup', () => {
    if (currentHandle) {
      currentHandle.classList.remove('active');
      currentHandle = null;
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    }
  });
}

initColumnResize();

const elements2 = {
  threatIntelModal: document.getElementById('threatIntelModal'),
  analyzeModal: document.getElementById('analyzeModal'),
  reportModal: document.getElementById('reportModal'),
  reportsListModal: document.getElementById('reportsListModal'),
  ollamaConfigModal: document.getElementById('ollamaConfigModal'),
  threatIntelList: document.getElementById('threatIntelList'),
  reportsList: document.getElementById('reportsList'),
  reportContent: document.getElementById('reportContent'),
  analysisStatus: document.getElementById('analysisStatus'),
  tiDropZone: document.getElementById('tiDropZone'),
  tiFileInput: document.getElementById('tiFileInput'),
  tiFileInfo: document.getElementById('tiFileInfo'),
};

let tiSelectedFile = null;

document.getElementById('threatIntelBtn').addEventListener('click', async () => {
  await loadThreatIntelList();
  openModal(elements2.threatIntelModal);
});

document.getElementById('closeThreatIntel').addEventListener('click', () => closeModal(elements2.threatIntelModal));
document.getElementById('closeThreatIntelBtn').addEventListener('click', () => closeModal(elements2.threatIntelModal));

document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(tab.dataset.tab).classList.add('active');
  });
});

elements2.tiDropZone.addEventListener('click', () => elements2.tiFileInput.click());
elements2.tiDropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  elements2.tiDropZone.classList.add('dragover');
});
elements2.tiDropZone.addEventListener('dragleave', () => elements2.tiDropZone.classList.remove('dragover'));
elements2.tiDropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  elements2.tiDropZone.classList.remove('dragover');
  if (e.dataTransfer.files.length) {
    tiSelectedFile = e.dataTransfer.files[0];
    elements2.tiFileInfo.innerHTML = `<strong>${tiSelectedFile.name}</strong> (${formatBytes(tiSelectedFile.size)})`;
  }
});

elements2.tiFileInput.addEventListener('change', (e) => {
  if (e.target.files.length) {
    tiSelectedFile = e.target.files[0];
    elements2.tiFileInfo.innerHTML = `<strong>${tiSelectedFile.name}</strong> (${formatBytes(tiSelectedFile.size)})`;
  }
});

document.getElementById('fetchUrlBtn').addEventListener('click', async () => {
  const url = document.getElementById('tiUrl').value.trim();
  const title = document.getElementById('tiUrlTitle').value.trim();
  
  if (!url) {
    alert('Please enter a URL');
    return;
  }
  
  const btn = document.getElementById('fetchUrlBtn');
  btn.disabled = true;
  btn.textContent = 'Fetching...';
  
  try {
    const res = await fetch(`${API_BASE}/api/threat-intel/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, title }),
    });
    
    const data = await res.json();
    
    if (data.success) {
      alert('Threat intel fetched successfully!');
      document.getElementById('tiUrl').value = '';
      document.getElementById('tiUrlTitle').value = '';
      await loadThreatIntelList();
    } else {
      alert('Error: ' + data.error);
    }
  } catch (err) {
    alert('Error: ' + err.message);
  }
  
  btn.disabled = false;
  btn.textContent = 'Fetch Article';
});

async function loadThreatIntelList() {
  try {
    const res = await fetch(`${API_BASE}/api/threat-intel`);
    const items = await res.json();
    
    if (items.length === 0) {
      elements2.threatIntelList.innerHTML = '<p style="color: var(--text-muted)">No threat intel loaded</p>';
      return;
    }
    
    elements2.threatIntelList.innerHTML = items.map(item => `
      <div class="item-row">
        <div class="item-info">
          <strong>${escapeHtml(item.title)}</strong>
          <span class="item-meta">${item.source_type} • ${new Date(item.created_at).toLocaleString()}</span>
          ${item.url ? `<span class="item-url">${escapeHtml(item.url)}</span>` : ''}
        </div>
        <div class="item-actions">
          <button class="btn btn-secondary btn-sm" onclick="viewThreatIntel(${item.id})">View</button>
          <button class="btn btn-danger btn-sm" onclick="deleteThreatIntel(${item.id})">Delete</button>
        </div>
      </div>
    `).join('');
  } catch (err) {
    console.error('Failed to load threat intel:', err);
  }
}

async function viewThreatIntel(id) {
  try {
    const res = await fetch(`${API_BASE}/api/threat-intel/${id}`);
    const item = await res.json();
    
    const viewer = window.open('', '_blank');
    viewer.document.write(`
      <html>
      <head><title>${escapeHtml(item.title)}</title>
      <style>
        body { font-family: system-ui; max-width: 900px; margin: 0 auto; padding: 20px; white-space: pre-wrap; }
      </style>
      </head>
      <body>${escapeHtml(item.content)}</body>
      </html>
    `);
  } catch (err) {
    alert('Error: ' + err.message);
  }
}

async function deleteThreatIntel(id) {
  if (!confirm('Delete this threat intel?')) return;
  
  try {
    await fetch(`${API_BASE}/api/threat-intel/${id}`, { method: 'DELETE' });
    await loadThreatIntelList();
  } catch (err) {
    alert('Error: ' + err.message);
  }
}

document.getElementById('analyzeBtn').addEventListener('click', async () => {
  const res = await fetch(`${API_BASE}/api/config/ollama`);
  const config = await res.json();
  
  document.getElementById('ollamaUrl').value = config.url || 'http://localhost:11434';
  document.getElementById('ollamaModel').value = config.model || 'llama3';
  
  document.getElementById('analysisStatus').innerHTML = '';
  openModal(elements2.analyzeModal);
});

document.getElementById('closeAnalyze').addEventListener('click', () => closeModal(elements2.analyzeModal));
document.getElementById('cancelAnalyze').addEventListener('click', () => closeModal(elements2.analyzeModal));

document.getElementById('startAnalysis').addEventListener('click', async () => {
  const scope = document.getElementById('analysisScope').value;
  const customPrompt = document.getElementById('customPrompt').value.trim();
  
  const statusDiv = document.getElementById('analysisStatus');
  statusDiv.innerHTML = '<div class="loading-spinner">Analyzing with AI...</div>';
  
  document.getElementById('startAnalysis').disabled = true;
  
  try {
    const res = await fetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scope: { logLimit: scope === 'all' ? 10000 : parseInt(scope) },
        customPrompt: customPrompt || null
      }),
    });
    
    const data = await res.json();
    
    if (data.success) {
      statusDiv.innerHTML = '<p style="color: var(--success)">Analysis complete!</p>';
      closeModal(elements2.analyzeModal);
      showReport(data.report.id);
    } else {
      statusDiv.innerHTML = `<p style="color: var(--error)">Error: ${data.error}</p>`;
    }
  } catch (err) {
    statusDiv.innerHTML = `<p style="color: var(--error)">Error: ${err.message}</p>`;
  }
  
  document.getElementById('startAnalysis').disabled = false;
});

async function showReport(id) {
  try {
    const res = await fetch(`${API_BASE}/api/reports/${id}`);
    const report = await res.json();
    
    elements2.reportContent.innerHTML = marked.parse(report.content);
    openModal(elements2.reportModal);
  } catch (err) {
    alert('Error: ' + err.message);
  }
}

document.getElementById('closeReport').addEventListener('click', () => closeModal(elements2.reportModal));
document.getElementById('closeReportBtn').addEventListener('click', () => closeModal(elements2.reportModal));

document.getElementById('reportsBtn').addEventListener('click', async () => {
  await loadReportsList();
  openModal(elements2.reportsListModal);
});

document.getElementById('closeReportsList').addEventListener('click', () => closeModal(elements2.reportsListModal));
document.getElementById('closeReportsListBtn').addEventListener('click', () => closeModal(elements2.reportsListModal));

async function loadReportsList() {
  try {
    const res = await fetch(`${API_BASE}/api/reports`);
    const reports = await res.json();
    
    if (reports.length === 0) {
      elements2.reportsList.innerHTML = '<p style="color: var(--text-muted)">No reports generated yet</p>';
      return;
    }
    
    elements2.reportsList.innerHTML = reports.map(report => `
      <div class="item-row">
        <div class="item-info">
          <strong>${escapeHtml(report.title)}</strong>
          <span class="item-meta">${report.logs_analyzed} logs • ${report.threat_intel_count} threat intel • ${new Date(report.created_at).toLocaleString()}</span>
        </div>
        <div class="item-actions">
          <button class="btn btn-primary btn-sm" onclick="showReport(${report.id})">View</button>
          <button class="btn btn-danger btn-sm" onclick="deleteReport(${report.id})">Delete</button>
        </div>
      </div>
    `).join('');
  } catch (err) {
    console.error('Failed to load reports:', err);
  }
}

async function deleteReport(id) {
  if (!confirm('Delete this report?')) return;
  
  try {
    await fetch(`${API_BASE}/api/reports/${id}`, { method: 'DELETE' });
    await loadReportsList();
  } catch (err) {
    alert('Error: ' + err.message);
  }
}

document.getElementById('chefBtn').addEventListener('click', () => {
  window.open('https://gchq.github.io/Chef炒/', '_blank');
});

document.getElementById('ollamaConfigBtn').addEventListener('click', async () => {
  const res = await fetch(`${API_BASE}/api/config/ollama`);
  const config = await res.json();
  
  document.getElementById('ollamaUrl').value = config.url || 'http://localhost:11434';
  document.getElementById('ollamaModel').value = config.model || 'llama3';
  
  openModal(elements2.ollamaConfigModal);
});

document.getElementById('closeOllamaConfig').addEventListener('click', () => closeModal(elements2.ollamaConfigModal));
document.getElementById('cancelOllamaConfig').addEventListener('click', () => closeModal(elements2.ollamaConfigModal));

document.getElementById('saveOllamaConfig').addEventListener('click', async () => {
  const url = document.getElementById('ollamaUrl').value.trim();
  const model = document.getElementById('ollamaModel').value.trim();
  
  await fetch(`${API_BASE}/api/config/ollama`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, model }),
  });
  
  closeModal(elements2.ollamaConfigModal);
  alert('Ollama configuration saved!');
});

loadLogs(1);
