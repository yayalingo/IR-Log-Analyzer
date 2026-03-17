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
  
  elements.logList.innerHTML = logs.map(log => `
    <div class="log-entry level-${log.level}" data-id="${log.id}">
      <span class="log-timestamp">${formatTimestamp(log.timestamp)}</span>
      <span class="log-level ${log.level}">${log.level}</span>
      <span class="log-source" title="${log.source}">${log.source}</span>
      <span class="log-message" title="${escapeHtml(log.message)}">${escapeHtml(log.message)}</span>
    </div>
  `).join('');
  
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
  if (!apiKey || apiKey === '********') {
    closeModal(elements.configModal);
    return;
  }
  
  await fetch(`${API_BASE}/api/config/vt-key`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ apiKey }),
  });
  
  closeModal(elements.configModal);
  alert('API key saved!');
});

document.getElementById('applyFilter').addEventListener('click', () => loadLogs(1));

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

loadLogs(1);
