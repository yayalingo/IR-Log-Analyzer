const API_BASE = '';

let authCredentials = null;

function getAuthHeader() {
  if (!authCredentials) {
    const stored = localStorage.getItem('ir_auth');
    if (stored) {
      authCredentials = stored;
    }
  }
  return authCredentials ? { 'Authorization': `Basic ${authCredentials}` } : {};
}

function setAuth(username, password) {
  authCredentials = btoa(`${username}:${password}`);
  localStorage.setItem('ir_auth', authCredentials);
}

function clearAuth() {
  authCredentials = null;
  localStorage.removeItem('ir_auth');
}

async function authFetch(url, options = {}) {
  const headers = { ...getAuthHeader(), ...options.headers };
  return fetch(url, { ...options, headers });
}

let currentPage = 1;
let totalLogs = 0;
let currentFilters = {};
let selectedFile = null;
let selectMode = false;
let selectedLogs = new Set();

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
  
  const res = await authFetch(`${API_BASE}/api/logs?${params}`);
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
    
    const isSelected = selectedLogs.has(log.id);
    const checkbox = selectMode ? `<input type="checkbox" class="log-checkbox" data-id="${log.id}" ${isSelected ? 'checked' : ''}>` : '';
    
    return `
    <div class="log-entry level-${log.level}" data-id="${log.id}">
      ${checkbox}
      <span class="log-timestamp">${formatTimestamp(log.timestamp)}</span>
      <span class="log-level ${log.level}">${log.level}</span>
      <span class="log-source" title="${log.source}">${log.source}</span>
      <span class="log-extract">${indicators.map(i => `<span class="extract-tag" title="${escapeHtml(i)}">${escapeHtml(i.length > 20 ? i.substring(0, 20) + '...' : i)}</span>`).join('')}</span>
      <span class="log-message" title="${escapeHtml(log.message)}">${escapeHtml(log.message)}</span>
    </div>
  `}).join('');
  
  elements.logList.querySelectorAll('.log-entry').forEach(el => {
    if (selectMode) {
      el.addEventListener('click', (e) => {
        if (e.target.classList.contains('log-checkbox')) return;
        const checkbox = el.querySelector('.log-checkbox');
        const id = parseInt(el.dataset.id);
        if (checkbox.checked) {
          checkbox.checked = false;
          selectedLogs.delete(id);
        } else {
          checkbox.checked = true;
          selectedLogs.add(id);
        }
        updateSelectedCount();
      });
    } else {
      el.addEventListener('click', () => showLogDetail(el.dataset.id));
    }
  });
  
  if (selectMode) {
    elements.logList.querySelectorAll('.log-checkbox').forEach(cb => {
      cb.addEventListener('change', (e) => {
        const id = parseInt(e.target.dataset.id);
        if (e.target.checked) {
          selectedLogs.add(id);
        } else {
          selectedLogs.delete(id);
        }
        updateSelectedCount();
      });
    });
  }
}

function updateSelectedCount() {
  const btn = document.getElementById('addToCaseBtn');
  btn.textContent = `➕ Add to Case (${selectedLogs.size})`;
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
    const res = await authFetch(`${API_BASE}/api/stats`);
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
    const res = await authFetch(`${API_BASE}/api/logs/${id}`);
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
    const res = await authFetch(`${API_BASE}/api/enrich`, {
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
    const res = await authFetch(`${API_BASE}/api/logs/import`, {
      method: 'POST',
      body: formData,
    });
    
    const data = await res.json();
    
    if (data.success) {
loadLogs(1);

async function checkAuth() {
  const stored = localStorage.getItem('ir_auth');
  if (stored) {
    authCredentials = stored;
    try {
      const res = await fetch(`${API_BASE}/api/auth-check`, {
        headers: getAuthHeader()
      });
      const data = await res.json();
      if (!data.authenticated) {
        showLoginModal();
      }
    } catch (e) {
      showLoginModal();
    }
  } else {
    showLoginModal();
  }
}

function showLoginModal() {
  document.getElementById('loginModal').classList.add('active');
}

function hideLoginModal() {
  document.getElementById('loginModal').classList.remove('active');
}

document.getElementById('loginBtn').addEventListener('click', async () => {
  const username = document.getElementById('loginUsername').value.trim();
  const password = document.getElementById('loginPassword').value;
  const errorEl = document.getElementById('loginError');
  
  if (!username || !password) {
    errorEl.textContent = 'Please enter username and password';
    errorEl.style.display = 'block';
    return;
  }
  
  setAuth(username, password);
  
  try {
    const res = await fetch(`${API_BASE}/api/auth-check`, {
      headers: getAuthHeader()
    });
    const data = await res.json();
    
    if (data.authenticated) {
      errorEl.style.display = 'none';
      hideLoginModal();
      loadLogs(1);
      updateStats();
    } else {
      clearAuth();
      errorEl.textContent = 'Invalid credentials';
      errorEl.style.display = 'block';
    }
  } catch (e) {
    clearAuth();
    errorEl.textContent = 'Connection error';
    errorEl.style.display = 'block';
  }
});

document.getElementById('loginPassword').addEventListener('keypress', (e) => {
  if (e.key === 'Enter') {
    document.getElementById('loginBtn').click();
  }
});

checkAuth();
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
  const res = await authFetch(`${API_BASE}/api/config/vt-key`);
  const data = await res.json();
  elements.vtApiKey.value = data.configured ? '********' : '';
  
  const extractRes = await authFetch(`${API_BASE}/api/config/extraction`);
  const extractData = await extractRes.json();
  elements.extractIp.checked = extractData.ip !== false;
  elements.extractHostname.checked = extractData.hostname !== false;
  elements.extractUrl.checked = extractData.url !== false;
  elements.extractHash.checked = extractData.hash !== false;
  
  openModal(elements.configModal);
});

document.getElementById('clearBtn').addEventListener('click', async () => {
  if (confirm('Clear all logs and enrichments? This cannot be undone.')) {
    await authFetch(`${API_BASE}/api/logs`, { method: 'DELETE' });
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
    await authFetch(`${API_BASE}/api/config/vt-key`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ apiKey }),
    });
  }
  
  await authFetch(`${API_BASE}/api/config/extraction`, {
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
    const res = await authFetch(`${API_BASE}/api/threat-intel/url`, {
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
    const res = await authFetch(`${API_BASE}/api/threat-intel`);
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
    const res = await authFetch(`${API_BASE}/api/threat-intel/${id}`);
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
    await authFetch(`${API_BASE}/api/threat-intel/${id}`, { method: 'DELETE' });
    await loadThreatIntelList();
  } catch (err) {
    alert('Error: ' + err.message);
  }
}

document.getElementById('analyzeBtn').addEventListener('click', async () => {
  const res = await authFetch(`${API_BASE}/api/config/ollama`);
  const config = await res.json();
  
  document.getElementById('ollamaUrl').value = config.url || 'http://localhost:11434';
  document.getElementById('ollamaModel').value = config.model || 'llama3';
  
  const casesRes = await authFetch(`${API_BASE}/api/cases`);
  const cases = await casesRes.json();
  
  const caseSelect = document.getElementById('analyzeCaseId');
  caseSelect.innerHTML = '<option value="">-- All Logs (No Case) --</option>' + 
    cases.map(c => `<option value="${c.id}">${escapeHtml(c.title)} (${c.severity}) - ${c.linked_logs_count || 0} logs</option>`).join('');
  
  document.getElementById('analysisStatus').innerHTML = '';
  openModal(elements2.analyzeModal);
});

document.getElementById('closeAnalyze').addEventListener('click', () => closeModal(elements2.analyzeModal));
document.getElementById('cancelAnalyze').addEventListener('click', () => closeModal(elements2.analyzeModal));

document.getElementById('startAnalysis').addEventListener('click', async () => {
  const scope = document.getElementById('analysisScope').value;
  const customPrompt = document.getElementById('customPrompt').value.trim();
  const caseId = document.getElementById('analyzeCaseId').value;
  
  const statusDiv = document.getElementById('analysisStatus');
  statusDiv.innerHTML = '<div class="loading-spinner">Analyzing with AI...</div>';
  
  document.getElementById('startAnalysis').disabled = true;
  
  try {
    const res = await authFetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scope: { logLimit: scope === 'all' ? 10000 : parseInt(scope) },
        customPrompt: customPrompt || null,
        caseId: caseId || null
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
    const res = await authFetch(`${API_BASE}/api/reports/${id}`);
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
    const res = await authFetch(`${API_BASE}/api/reports`);
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
    await authFetch(`${API_BASE}/api/reports/${id}`, { method: 'DELETE' });
    await loadReportsList();
  } catch (err) {
    alert('Error: ' + err.message);
  }
}

document.getElementById('chefBtn').addEventListener('click', () => {
  window.open('https://gchq.github.io/Chef炒/', '_blank');
});

document.getElementById('ollamaConfigBtn').addEventListener('click', async () => {
  const res = await authFetch(`${API_BASE}/api/config/ollama`);
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
  
  await authFetch(`${API_BASE}/api/config/ollama`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, model }),
  });
  
  closeModal(elements2.ollamaConfigModal);
  alert('Ollama configuration saved!');
});

const elements3 = {
  dashboardModal: document.getElementById('dashboardModal'),
  casesModal: document.getElementById('casesModal'),
  newCaseModal: document.getElementById('newCaseModal'),
  iocMatchesModal: document.getElementById('iocMatchesModal'),
  integrationsModal: document.getElementById('integrationsModal'),
};

document.getElementById('dashboardBtn').addEventListener('click', async () => {
  const res = await authFetch(`${API_BASE}/api/dashboard`);
  const data = await res.json();
  
  document.getElementById('dashTotalLogs').textContent = data.totalLogs || 0;
  document.getElementById('dashOpenCases').textContent = data.openCases || 0;
  document.getElementById('dashIocMatches').textContent = data.iocMatches || 0;
  document.getElementById('dashThreatIntel').textContent = data.threatIntelCount || 0;
  
  const levelCounts = data.levelCounts || {};
  const levelColors = { CRITICAL: '#ff7b72', FATAL: '#ff7b72', ERROR: '#f85149', WARN: '#d29922', WARNING: '#d29922', INFO: '#58a6ff', DEBUG: '#8b949e' };
  let levelHtml = '';
  const totalLevel = Object.values(levelCounts).reduce((a, b) => a + b, 0) || 1;
  for (const [level, count] of Object.entries(levelCounts)) {
    const pct = Math.round((count / totalLevel) * 100);
    levelHtml += `<div class="level-bar"><span class="level-bar-label">${level}</span><div class="level-bar-track"><div class="level-bar-fill" style="width: ${pct}%; background: ${levelColors[level] || '#8b949e'}"></div></div><span class="level-bar-value">${count}</span></div>`;
  }
  document.getElementById('levelBars').innerHTML = levelHtml || '<p style="color: var(--text-muted)">No data</p>';
  
  const sourceList = data.topSources || [];
  document.getElementById('sourceList').innerHTML = sourceList.map(s => `<div class="source-item"><span>${escapeHtml(s.source)}</span><span>${s.count}</span></div>`).join('') || '<p style="color: var(--text-muted)">No data</p>';
  
  const trendHtml = (data.recentTrend || []).map(d => `<div class="trend-bar"><div class="trend-bar-fill" style="height: ${Math.min(100, (d.count / 100))}%"></div><span class="trend-bar-label">${d.date?.slice(5) || ''}</span></div>`).join('');
  document.getElementById('trendChart').innerHTML = trendHtml || '<p style="color: var(--text-muted)">No data</p>';
  
  openModal(elements3.dashboardModal);
});

document.getElementById('closeDashboard').addEventListener('click', () => closeModal(elements3.dashboardModal));
document.getElementById('closeDashboardBtn').addEventListener('click', () => closeModal(elements3.dashboardModal));

document.getElementById('casesBtn').addEventListener('click', async () => {
  await loadCasesList();
  openModal(elements3.casesModal);
});

document.getElementById('closeCases').addEventListener('click', () => closeModal(elements3.casesModal));
document.getElementById('closeCasesBtn').addEventListener('click', () => closeModal(elements3.casesModal));

document.getElementById('newCaseBtn').addEventListener('click', () => openModal(elements3.newCaseModal));
document.getElementById('closeNewCase').addEventListener('click', () => closeModal(elements3.newCaseModal));
document.getElementById('cancelNewCase').addEventListener('click', () => closeModal(elements3.newCaseModal));

document.getElementById('createCaseBtn').addEventListener('click', async () => {
  const title = document.getElementById('caseTitle').value.trim();
  const description = document.getElementById('caseDescription').value.trim();
  const severity = document.getElementById('caseSeverity').value;
  
  if (!title) {
    alert('Please enter a case title');
    return;
  }
  
  const res = await authFetch(`${API_BASE}/api/cases`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ title, description, severity }),
  });
  
  const data = await res.json();
  if (data.success) {
    closeModal(elements3.newCaseModal);
    document.getElementById('caseTitle').value = '';
    document.getElementById('caseDescription').value = '';
    await loadCasesList();
  } else {
    alert('Error: ' + data.error);
  }
});

async function loadCasesList() {
  const res = await authFetch(`${API_BASE}/api/cases`);
  const cases = await res.json();
  
  const severityColors = { Critical: '#ff7b72', High: '#f85149', Medium: '#d29922', Low: '#58a6ff' };
  const statusColors = { Open: '#3fb950', Closed: '#8b949e', InProgress: '#d29922' };
  
  document.getElementById('casesList').innerHTML = cases.length ? cases.map(c => `
    <div class="item-row">
      <div class="item-info">
        <strong>${escapeHtml(c.title)}</strong>
        <span class="item-meta">
          <span class="severity-badge" style="background: ${severityColors[c.severity] || '#8b949e'}">${c.severity}</span>
          <span class="status-badge" style="background: ${statusColors[c.status] || '#8b949e'}">${c.status}</span>
          ${new Date(c.created_at).toLocaleString()}
        </span>
      </div>
      <div class="item-actions">
        <button class="btn btn-primary btn-sm" onclick="viewCase(${c.id})">View</button>
        <button class="btn btn-danger btn-sm" onclick="deleteCase(${c.id})">Delete</button>
      </div>
    </div>
  `).join('') : '<p style="color: var(--text-muted)">No cases created yet</p>';
}

async function viewCase(id) {
    const res = await authFetch(`${API_BASE}/api/cases/${id}`);
  const c = await res.json();
  
  document.querySelector('.tab[data-tab="case-detail"]').click();
  
  document.getElementById('caseDetail').innerHTML = `
    <div class="case-header">
      <h3>${escapeHtml(c.title)}</h3>
      <div class="case-meta">
        <span class="severity-badge" style="background: ${{Critical:'#ff7b72',High:'#f85149',Medium:'#d29922',Low:'#58a6ff'}[c.severity]||'#8b949e'}">${c.severity}</span>
        <span class="status-badge" style="background: ${{Open:'#3fb950',Closed:'#8b949e',InProgress:'#d29922'}[c.status]||'#8b949e'}">${c.status}</span>
        <span>Created: ${new Date(c.created_at).toLocaleString()}</span>
      </div>
    </div>
    <p>${escapeHtml(c.description || 'No description')}</p>
    
    <h4>Notes</h4>
    <div class="notes-list">
      ${(c.notes || []).map(n => `<div class="note-item"><p>${escapeHtml(n.content)}</p><small>${new Date(n.created_at).toLocaleString()}</small></div>`).join('') || '<p style="color: var(--text-muted)">No notes</p>'}
    </div>
    <div class="form-group" style="margin-top: 12px;">
      <textarea id="newNote" class="textarea" rows="2" placeholder="Add a note..."></textarea>
      <button class="btn btn-primary btn-sm" onclick="addNote(${c.id})" style="margin-top: 8px;">Add Note</button>
    </div>
    
    <h4>Linked Logs (${(c.linkedLogs || []).length})</h4>
    <div class="linked-logs">
      ${(c.linkedLogs || []).map(l => `<div class="log-entry-small"><span class="log-level ${l.level}">${l.level}</span> <span>${escapeHtml(l.message?.substring(0, 80) || '')}</span></div>`).join('') || '<p style="color: var(--text-muted)">No logs linked</p>'}
    </div>
    
    <div class="case-actions" style="margin-top: 16px;">
      <select id="updateStatus" class="input select" style="width: auto;">
        <option value="Open">Open</option>
        <option value="InProgress">In Progress</option>
        <option value="Closed">Closed</option>
      </select>
      <button class="btn btn-secondary" onclick="updateCaseStatus(${c.id})">Update Status</button>
    </div>
  `;
}

async function addNote(caseId) {
  const content = document.getElementById('newNote').value.trim();
  if (!content) return;
  
    await authFetch(`${API_BASE}/api/cases/${caseId}/notes`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content }),
  });
  
  document.getElementById('newNote').value = '';
  await viewCase(caseId);
}

async function updateCaseStatus(caseId) {
  const status = document.getElementById('updateStatus').value;
    await authFetch(`${API_BASE}/api/cases/${caseId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
  });
  await loadCasesList();
  await viewCase(caseId);
}

async function deleteCase(id) {
  if (!confirm('Delete this case?')) return;
    await authFetch(`${API_BASE}/api/cases/${id}`, { method: 'DELETE' });
  await loadCasesList();
}

document.getElementById('iocMatchesBtn').addEventListener('click', async () => {
  const res = await authFetch(`${API_BASE}/api/ioc/matches`);
  const matches = await res.json();
  
  document.getElementById('iocList').innerHTML = matches.length ? matches.map(m => `
    <div class="ioc-match-item">
      <span class="ioc-type">${escapeHtml(m.indicator_type)}</span>
      <span class="ioc-value">${escapeHtml(m.indicator)}</span>
      <span class="ioc-log">${escapeHtml(m.message?.substring(0, 60) || '')}</span>
      <span class="ioc-time">${new Date(m.matched_at).toLocaleString()}</span>
    </div>
  `).join('') : '<p style="color: var(--text-muted)">No IOC matches found</p>';
  
  openModal(elements3.iocMatchesModal);
});

document.getElementById('closeIocMatches').addEventListener('click', () => closeModal(elements3.iocMatchesModal));
document.getElementById('closeIocMatchesBtn').addEventListener('click', () => closeModal(elements3.iocMatchesModal));

document.getElementById('integrationsBtn').addEventListener('click', async () => {
  await loadWebhooks();
  await loadForwarding();
  openModal(elements3.integrationsModal);
});

document.getElementById('closeIntegrations').addEventListener('click', () => closeModal(elements3.integrationsModal));
document.getElementById('closeIntegrationsBtn').addEventListener('click', () => closeModal(elements3.integrationsModal));

async function loadWebhooks() {
  const res = await authFetch(`${API_BASE}/api/config/webhooks`);
  const webhooks = await res.json();
  
  document.getElementById('webhookList').innerHTML = webhooks.length ? webhooks.map(w => `
    <div class="item-row">
      <div class="item-info">
        <strong>${escapeHtml(w.name)}</strong>
        <span class="item-meta">${escapeHtml(w.url)}</span>
      </div>
      <div class="item-actions">
        <button class="btn btn-secondary btn-sm" onclick="testWebhook(${w.id})">Test</button>
        <button class="btn btn-danger btn-sm" onclick="deleteWebhook(${w.id})">Delete</button>
      </div>
    </div>
  `).join('') : '<p style="color: var(--text-muted)">No webhooks configured</p>';
}

document.getElementById('addWebhookBtn').addEventListener('click', async () => {
  const name = document.getElementById('webhookName').value.trim();
  const url = document.getElementById('webhookUrl').value.trim();
  const events = [];
  if (document.getElementById('webhookCritical').checked) events.push('critical');
  if (document.getElementById('webhookIoc').checked) events.push('ioc_match');
  if (document.getElementById('webhookCase').checked) events.push('case_created');
  
  if (!name || !url || events.length === 0) {
    alert('Please fill in all fields');
    return;
  }
  
    await authFetch(`${API_BASE}/api/config/webhooks`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, url, events }),
  });
  
  document.getElementById('webhookName').value = '';
  document.getElementById('webhookUrl').value = '';
  await loadWebhooks();
});

async function testWebhook(id) {
    const res = await authFetch(`${API_BASE}/api/config/webhooks/${id}/test`, { method: 'POST' });
  const data = await res.json();
  alert(data.success ? 'Test successful!' : 'Test failed: ' + data.error);
}

async function deleteWebhook(id) {
  if (!confirm('Delete this webhook?')) return;
    await authFetch(`${API_BASE}/api/config/webhooks/${id}`, { method: 'DELETE' });
  await loadWebhooks();
}

async function loadForwarding() {
  const res = await authFetch(`${API_BASE}/api/config/forwarding`);
  const configs = await res.json();
  
  document.getElementById('forwardingList').innerHTML = configs.length ? configs.map(f => `
    <div class="item-row">
      <div class="item-info">
        <strong>${escapeHtml(f.name)}</strong>
        <span class="item-meta">${f.type}</span>
      </div>
      <div class="item-actions">
        <button class="btn btn-danger btn-sm" onclick="deleteForwarding(${f.id})">Delete</button>
      </div>
    </div>
  `).join('') : '<p style="color: var(--text-muted)">No forwarding configured</p>';
}

document.getElementById('addForwardingBtn').addEventListener('click', async () => {
  const name = document.getElementById('forwardName').value.trim();
  const type = document.getElementById('forwardType').value;
  const configStr = document.getElementById('forwardConfig').value.trim();
  
  if (!name || !configStr) {
    alert('Please fill in all fields');
    return;
  }
  
  try {
    const config = JSON.parse(configStr);
    await authFetch(`${API_BASE}/api/config/forwarding`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, type, config }),
    });
    
    document.getElementById('forwardName').value = '';
    document.getElementById('forwardConfig').value = '';
    await loadForwarding();
  } catch (e) {
    alert('Invalid JSON config');
  }
});

async function deleteForwarding(id) {
  if (!confirm('Delete this forwarding config?')) return;
    await authFetch(`${API_BASE}/api/config/forwarding/${id}`, { method: 'DELETE' });
  await loadForwarding();
}

document.getElementById('importMispBtn').addEventListener('click', async () => {
  const url = document.getElementById('mispUrl').value.trim();
  const apiKey = document.getElementById('mispApiKey').value.trim();
  
  if (!url || !apiKey) {
    alert('Please enter MISP URL and API key');
    return;
  }
  
  const btn = document.getElementById('importMispBtn');
  btn.disabled = true;
  btn.textContent = 'Importing...';
  
  try {
    const res = await authFetch(`${API_BASE}/api/threat-intel/misp/import`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, apiKey }),
    });
    const data = await res.json();
    alert(data.success ? `Imported ${data.imported} events` : 'Error: ' + data.error);
  } catch (e) {
    alert('Error: ' + e.message);
  }
  
  btn.disabled = false;
  btn.textContent = 'Import Events';
});

document.getElementById('importStixBtn').addEventListener('click', async () => {
  const bundleStr = document.getElementById('stixBundle').value.trim();
  
  if (!bundleStr) {
    alert('Please enter STIX bundle');
    return;
  }
  
  try {
    const bundle = JSON.parse(bundleStr);
    const res = await authFetch(`${API_BASE}/api/threat-intel/stix/import`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ bundle }),
    });
    const data = await res.json();
    alert(data.success ? `Imported ${data.imported} objects` : 'Error: ' + data.error);
  } catch (e) {
    alert('Invalid JSON');
  }
});

document.getElementById('selectModeBtn').addEventListener('click', () => {
  selectMode = !selectMode;
  const btn = document.getElementById('selectModeBtn');
  const addBtn = document.getElementById('addToCaseBtn');
  
  if (selectMode) {
    btn.textContent = '❌ Cancel Select';
    addBtn.style.display = 'inline-flex';
  } else {
    btn.textContent = '☑️ Select';
    addBtn.style.display = 'none';
    selectedLogs.clear();
  }
  
  loadLogs(currentPage);
});

document.getElementById('addToCaseBtn').addEventListener('click', async () => {
  if (selectedLogs.size === 0) {
    alert('Please select at least one log');
    return;
  }
  
  const res = await authFetch(`${API_BASE}/api/cases`);
  const cases = await res.json();
  
  if (cases.length === 0) {
    alert('No cases available. Please create a case first.');
    return;
  }
  
  const select = document.getElementById('targetCase');
  select.innerHTML = '<option value="">-- Select a case --</option>' + 
    cases.map(c => `<option value="${c.id}">${escapeHtml(c.title)} (${c.severity})</option>`).join('');
  
  document.getElementById('selectedCount').textContent = selectedLogs.size;
  document.getElementById('selectCaseModal').classList.add('active');
});

document.getElementById('closeSelectCase').addEventListener('click', () => {
  document.getElementById('selectCaseModal').classList.remove('active');
});

document.getElementById('cancelSelectCase').addEventListener('click', () => {
  document.getElementById('selectCaseModal').classList.remove('active');
});

document.getElementById('confirmAddToCase').addEventListener('click', async () => {
  const caseId = document.getElementById('targetCase').value;
  
  if (!caseId) {
    alert('Please select a case');
    return;
  }
  
  const logIds = Array.from(selectedLogs);
  
  const res = await authFetch(`${API_BASE}/api/cases/${caseId}/logs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ logIds }),
  });
  
  const data = await res.json();
  
  if (data.success) {
    alert(`Added ${logIds.length} logs to case!`);
    document.getElementById('selectCaseModal').classList.remove('active');
    selectMode = false;
    selectedLogs.clear();
    document.getElementById('selectModeBtn').textContent = '☑️ Select';
    document.getElementById('addToCaseBtn').style.display = 'none';
    loadLogs(currentPage);
  } else {
    alert('Error: ' + data.error);
  }
});

loadLogs(1);
