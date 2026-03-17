const express = require('express');
const initSqlJs = require('sql.js');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = 3000;
const DB_PATH = path.join(__dirname, 'ir-logs.db');

let db;

async function initDb() {
  const SQL = await initSqlJs();
  
  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }
  
  db.run(`
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT,
      source TEXT,
      level TEXT,
      message TEXT,
      raw TEXT,
      ip TEXT,
      hostname TEXT,
      url TEXT,
      hash TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  // Migration: add columns if they don't exist
  try { db.run(`ALTER TABLE logs ADD COLUMN ip TEXT`); } catch(e) {}
  try { db.run(`ALTER TABLE logs ADD COLUMN hostname TEXT`); } catch(e) {}
  try { db.run(`ALTER TABLE logs ADD COLUMN url TEXT`); } catch(e) {}
  try { db.run(`ALTER TABLE logs ADD COLUMN hash TEXT`); } catch(e) {}
  
  db.run(`
    CREATE TABLE IF NOT EXISTS enrichments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      indicator TEXT UNIQUE,
      type TEXT,
      vt_result TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  db.run(`CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_logs_source ON logs(source)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_logs_level ON logs(level)`);
  
  saveDb();
}

function saveDb() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
}

app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({ 
  dest: '/tmp/',
  limits: { fileSize: 50 * 1024 * 1024 }
});

const VT_API_KEY = process.env.VT_API_KEY || '';

const parseTimestamp = (line) => {
  const patterns = [
    /(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)/,
    /(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/,
    /(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/,
    /(\d{10,13})/,
    /(\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2})/,
  ];
  
  for (const pattern of patterns) {
    const match = line.match(pattern);
    if (match) {
      let ts = match[1];
      if (/^\d{10,13}$/.test(ts)) {
        const num = parseInt(ts);
        ts = num > 9999999999 ? new Date(num).toISOString() : new Date(num * 1000).toISOString();
      } else if (!ts.includes('T')) {
        const parsed = new Date(ts);
        if (!isNaN(parsed)) ts = parsed.toISOString();
      }
      return ts;
    }
  }
  return null;
};

const parseLevel = (line) => {
  const levels = ['CRITICAL', 'FATAL', 'ERROR', 'WARN', 'WARNING', 'INFO', 'DEBUG', 'TRACE', 'NOTICE'];
  const upper = line.toUpperCase();
  for (const lvl of levels) {
    if (upper.includes(lvl)) return lvl;
  }
  return 'INFO';
};

const extractSource = (line, parsed) => {
  if (parsed?.source) return parsed.source;
  if (parsed?.hostname) return parsed.hostname;
  const srcMatch = line.match(/(?:src|src_ip|source|host|hostname)["']?\s*[:=]\s*["']?([^"'\s,}]+)/i);
  if (srcMatch) return srcMatch[1];
  return 'unknown';
};

const extractFields = (text, config) => {
  const result = { ip: '', hostname: '', url: '', hash: '' };
  
  if (!config) config = getExtractConfig();
  
  if (config.ip) {
    const ipPattern = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
    const ips = text.match(ipPattern) || [];
    const uniqueIps = [...new Set(ips.filter(ip => !ip.startsWith('0') && !ip.startsWith('255.') && !ip.match(/^127\./)))];
    result.ip = uniqueIps.join(',');
  }
  
  if (config.hostname) {
    const domainPattern = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|edu|gov|co|info|biz|ru|cn|xyz|top|tk|ml|ga|cf|gq|pw|cc|ws|su|onion)\b/gi;
    const domains = text.match(domainPattern) || [];
    const uniqueDomains = [...new Set(domains.filter(d => !d.includes('localhost') && d.length > 3))];
    result.hostname = uniqueDomains.join(',');
  }
  
  if (config.url) {
    const urlPattern = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi;
    const urls = text.match(urlPattern) || [];
    result.url = [...new Set(urls)].join(',');
  }
  
  if (config.hash) {
    const md5Pattern = /\b[a-fA-F0-9]{32}\b/g;
    const sha1Pattern = /\b[a-fA-F0-9]{40}\b/g;
    const sha256Pattern = /\b[a-fA-F0-9]{64}\b/g;
    const md5s = text.match(md5Pattern) || [];
    const sha1s = text.match(sha1Pattern) || [];
    const sha256s = text.match(sha256Pattern) || [];
    const hashes = [...new Set([...md5s, ...sha1s, ...sha256s])];
    result.hash = hashes.join(',');
  }
  
  return result;
};

const parseLogLine = (line, config) => {
  let parsed = null;
  let message = line.trim();
  
  try {
    if (line.startsWith('{') && line.endsWith('}')) {
      parsed = JSON.parse(line);
      message = parsed.message || parsed.msg || parsed.log || line;
    }
  } catch (e) {}
  
  const timestamp = parsed?.timestamp || parsed?.time || parsed?.datetime || parsed?.date || parseTimestamp(line) || new Date().toISOString();
  const level = parsed?.level || parsed?.severity || parseLevel(line);
  const source = extractSource(line, parsed);
  
  const extracted = extractFields(line, config);
  
  return { timestamp, level, source, message, raw: line, ...extracted };
};

const parseJSONLog = (content, config) => {
  const logs = [];
  const lines = content.split('\n').filter(l => l.trim());
  
  for (const line of lines) {
    if (line.startsWith('{') && line.endsWith('}')) {
      try {
        const parsed = JSON.parse(line);
        const message = parsed.message || parsed.msg || parsed.log || JSON.stringify(parsed);
        const timestamp = parsed.timestamp || parsed.time || parsed.datetime || parsed.date || new Date().toISOString();
        const level = parsed.level || parsed.severity || parseLevel(message);
        const source = parsed.source || parsed.hostname || parsed.host || 'unknown';
        
        const extracted = extractFields(line, config);
        logs.push({ timestamp, level, source, message, raw: line, ...extracted });
      } catch (e) {
        logs.push(parseLogLine(line, config));
      }
    } else {
      logs.push(parseLogLine(line, config));
    }
  }
  return logs;
};

const parseSyslog = (content, config) => {
  const logs = [];
  const lines = content.split('\n').filter(l => l.trim());
  
  const syslogPattern = /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$/;
  
  for (const line of lines) {
    const match = line.match(syslogPattern);
    if (match) {
      const [, dateStr, host, process, , message] = match;
      const year = new Date().getFullYear();
      const timestamp = new Date(`${dateStr} ${year}`).toISOString();
      const extracted = extractFields(line, config);
      logs.push({ timestamp, level: parseLevel(message), source: host, message, raw: line, ...extracted });
    } else {
      logs.push(parseLogLine(line, config));
    }
  }
  return logs;
};

const parseCSVLog = (content, config) => {
  const logs = [];
  const lines = content.split('\n').filter(l => l.trim());
  
  if (lines.length < 2) return parsePlainText(content, config);
  
  const headers = lines[0].split(',').map(h => h.trim().toLowerCase());
  const timeIdx = headers.findIndex(h => h.includes('time') || h.includes('date'));
  const msgIdx = headers.findIndex(h => h.includes('message') || h.includes('msg') || h.includes('log'));
  const lvlIdx = headers.findIndex(h => h.includes('level') || h.includes('severity'));
  const srcIdx = headers.findIndex(h => h.includes('source') || h.includes('host'));
  
  for (let i = 1; i < lines.length; i++) {
    const cols = lines[i].split(/,(?=(?:(?:[^"]*"){2})*[^"]*$)/).map(c => c.trim().replace(/^"|"$/g, ''));
    const timestamp = timeIdx >= 0 ? (cols[timeIdx] || new Date().toISOString()) : new Date().toISOString();
    const message = msgIdx >= 0 ? (cols[msgIdx] || lines[i]) : lines[i];
    const level = lvlIdx >= 0 ? (cols[lvlIdx] || 'INFO') : parseLevel(message);
    const source = srcIdx >= 0 ? (cols[srcIdx] || 'unknown') : 'unknown';
    
    const extracted = extractFields(lines[i], config);
    logs.push({ timestamp, level, source, message, raw: lines[i], ...extracted });
  }
  return logs;
};

const parsePlainText = (content, config) => {
  return content.split('\n').filter(l => l.trim()).map(line => parseLogLine(line, config));
};

const parseLogs = (content, filename) => {
  const config = getExtractConfig();
  const ext = path.extname(filename).toLowerCase();
  
  if (ext === '.json' || content.trim().startsWith('{')) {
    return parseJSONLog(content, config);
  } else if (ext === '.csv' || content.includes(',') && content.split('\n')[0].split(',').length > 2) {
    return parseCSVLog(content, config);
  } else if (ext === '.xml' || content.trim().startsWith('<')) {
    return parseJSONLog(content.replace(/<[^>]+>/g, m => m.startsWith('<') && m.endsWith('>') ? '' : m), config);
  } else if (content.match(/^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/)) {
    return parseSyslog(content, config);
  }
  
  return parsePlainText(content, config);
};

const extractIndicators = (text) => {
  const indicators = { ips: [], domains: [], urls: [], hashes: [] };
  
  const ipPattern = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  const domainPattern = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|edu|gov|co|info|biz|ru|cn|xyz|top|tk|ml|ga|cf|gq|pw|cc|ws|su|onion)\b/gi;
  const urlPattern = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi;
  const md5Pattern = /\b[a-fA-F0-9]{32}\b/;
  const sha1Pattern = /\b[a-fA-F0-9]{40}\b/;
  const sha256Pattern = /\b[a-fA-F0-9]{64}\b/;
  
  const ips = text.match(ipPattern) || [];
  indicators.ips = [...new Set(ips.filter(ip => !ip.startsWith('0') && !ip.startsWith('255.') && !ip.match(/^127\./)))];
  
  const domains = text.match(domainPattern) || [];
  indicators.domains = [...new Set(domains.filter(d => !d.includes('localhost') && d.length > 3))];
  
  const urls = text.match(urlPattern) || [];
  indicators.urls = [...new Set(urls)];
  
  const md5s = text.match(md5Pattern) || [];
  const sha1s = text.match(sha1Pattern) || [];
  const sha256s = text.match(sha256Pattern) || [];
  
  for (const h of [...md5s, ...sha1s, ...sha256s]) {
    if (h.length === 32) indicators.hashes.push({ type: 'md5', value: h });
    else if (h.length === 40) indicators.hashes.push({ type: 'sha1', value: h });
    else if (h.length === 64) indicators.hashes.push({ type: 'sha256', value: h });
  }
  
  return indicators;
};

app.post('/api/logs/import', upload.single('file'), (req, res) => {
  try {
    let logs = [];
    let filename = 'upload.log';
    
    if (req.file) {
      filename = req.file.originalname;
      const content = fs.readFileSync(req.file.path, 'utf8');
      logs = parseLogs(content, filename);
      fs.unlinkSync(req.file.path);
    } else if (req.body.content) {
      filename = req.body.filename || 'paste.log';
      logs = parseLogs(req.body.content, filename);
    } else if (req.body.logs) {
      const arr = Array.isArray(req.body.logs) ? req.body.logs : [req.body.logs];
      logs = arr.map(l => typeof l === 'string' ? parseLogLine(l) : {
        timestamp: l.timestamp || l.time || new Date().toISOString(),
        level: l.level || l.severity || 'INFO',
        source: l.source || l.host || 'unknown',
        message: l.message || l.msg || l.log || JSON.stringify(l),
        raw: JSON.stringify(l)
      });
    }
    
    const stmt = db.prepare(`
      INSERT INTO logs (timestamp, source, level, message, raw, ip, hostname, url, hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    
    for (const log of logs) {
      stmt.run([log.timestamp, log.source, log.level, log.message, log.raw, log.ip || '', log.hostname || '', log.url || '', log.hash || '']);
    }
    stmt.free();
    
    saveDb();
    
    res.json({ success: true, count: logs.length, logs: logs.slice(0, 10) });
  } catch (error) {
    console.error('Import error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/logs', (req, res) => {
  try {
    const { start, end, source, level, search, limit = 500, offset = 0 } = req.query;
    
    let query = 'SELECT * FROM logs WHERE 1=1';
    const params = [];
    
    if (start) {
      query += ' AND timestamp >= ?';
      params.push(start);
    }
    if (end) {
      query += ' AND timestamp <= ?';
      params.push(end);
    }
    if (source) {
      query += ' AND source LIKE ?';
      params.push(`%${source}%`);
    }
    if (level) {
      query += ' AND level = ?';
      params.push(level.toUpperCase());
    }
    if (search) {
      query += ' AND (message LIKE ? OR raw LIKE ?)';
      params.push(`%${search}%`, `%${search}%`);
    }
    
    query += ' ORDER BY timestamp ASC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));
    
    const stmt = db.prepare(query);
    stmt.bind(params);
    const logs = [];
    while (stmt.step()) {
      logs.push(stmt.getAsObject());
    }
    stmt.free();
    
    let countQuery = 'SELECT COUNT(*) as total FROM logs WHERE 1=1';
    const countParams = [];
    if (start) { countQuery += ' AND timestamp >= ?'; countParams.push(start); }
    if (end) { countQuery += ' AND timestamp <= ?'; countParams.push(end); }
    if (source) { countQuery += ' AND source LIKE ?'; countParams.push(`%${source}%`); }
    if (level) { countQuery += ' AND level = ?'; countParams.push(level.toUpperCase()); }
    if (search) { countQuery += ' AND (message LIKE ? OR raw LIKE ?)'; countParams.push(`%${search}%`, `%${search}%`); }
    
    const countStmt = db.prepare(countQuery);
    countStmt.bind(countParams);
    countStmt.step();
    const { total } = countStmt.getAsObject();
    countStmt.free();
    
    res.json({ logs, total, limit: parseInt(limit), offset: parseInt(offset) });
  } catch (error) {
    console.error('Query error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/logs/:id', (req, res) => {
  try {
    const stmt = db.prepare('SELECT * FROM logs WHERE id = ?');
    stmt.bind([parseInt(req.params.id)]);
    if (stmt.step()) {
      const log = stmt.getAsObject();
      stmt.free();
      const indicators = extractIndicators(log.raw);
      return res.json({ ...log, indicators });
    }
    stmt.free();
    res.status(404).json({ error: 'Not found' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/enrich', async (req, res) => {
  try {
    const { indicator, type } = req.body;
    if (!indicator || !type) {
      return res.status(400).json({ error: 'Missing indicator or type' });
    }
    
    const checkStmt = db.prepare('SELECT * FROM enrichments WHERE indicator = ?');
    checkStmt.bind([indicator]);
    if (checkStmt.step()) {
      const cached = checkStmt.getAsObject();
      checkStmt.free();
      return res.json({ ...cached, cached: true });
    }
    checkStmt.free();
    
    if (!VT_API_KEY) {
      const keyPath = path.join(__dirname, '.vt-key');
      if (fs.existsSync(keyPath)) {
        const key = fs.readFileSync(keyPath, 'utf8').trim();
        if (key) {
          await doEnrichment(indicator, type, key, res);
          return;
        }
      }
      return res.status(400).json({ error: 'VirusTotal API key not configured' });
    }
    
    await doEnrichment(indicator, type, VT_API_KEY, res);
  } catch (error) {
    console.error('Enrichment error:', error);
    res.status(500).json({ error: error.message });
  }
});

async function doEnrichment(indicator, type, apiKey, res) {
  let vtId = indicator;
  let endpoint = 'ip_addresses';
  
  if (type === 'domain' || type.includes('.')) {
    endpoint = 'domains';
  } else if (type === 'url') {
    endpoint = 'urls';
    vtId = crypto.createHash('sha256').update(indicator).digest('hex');
  } else if (type === 'md5' || type === 'sha1' || type === 'sha256' || type === 'file') {
    endpoint = 'files';
  }
  
  const response = await fetch(`https://www.virustotal.com/api/v3/${endpoint}/${vtId}`, {
    headers: { 'x-apikey': apiKey }
  });
  
  if (!response.ok) {
    if (response.status === 404) {
      return res.json({ indicator, type, result: { not_found: true } });
    }
    throw new Error(`VT API error: ${response.status}`);
  }
  
  const result = await response.json();
  
  const insertStmt = db.prepare('INSERT INTO enrichments (indicator, type, vt_result) VALUES (?, ?, ?)');
  insertStmt.run([indicator, type, JSON.stringify(result)]);
  insertStmt.free();
  
  saveDb();
  
  res.json({ indicator, type, result, cached: false });
}

app.get('/api/enrich/:indicator', (req, res) => {
  try {
    const stmt = db.prepare('SELECT * FROM enrichments WHERE indicator = ?');
    stmt.bind([req.params.indicator]);
    if (stmt.step()) {
      const cached = stmt.getAsObject();
      stmt.free();
      return res.json({ ...cached, cached: true });
    }
    stmt.free();
    res.status(404).json({ error: 'Not found' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/config/vt-key', (req, res) => {
  const { apiKey } = req.body;
  if (!apiKey) return res.status(400).json({ error: 'Missing apiKey' });
  
  fs.writeFileSync(path.join(__dirname, '.vt-key'), apiKey);
  res.json({ success: true });
});

app.get('/api/config/vt-key', (req, res) => {
  const keyPath = path.join(__dirname, '.vt-key');
  const hasKey = fs.existsSync(keyPath);
  res.json({ configured: hasKey });
});

const EXTRACT_CONFIG_PATH = path.join(__dirname, '.extract-config');

function getExtractConfig() {
  if (fs.existsSync(EXTRACT_CONFIG_PATH)) {
    try {
      return JSON.parse(fs.readFileSync(EXTRACT_CONFIG_PATH, 'utf8'));
    } catch(e) {}
  }
  return { ip: true, hostname: true, url: true, hash: true };
}

app.get('/api/config/extraction', (req, res) => {
  res.json(getExtractConfig());
});

app.post('/api/config/extraction', (req, res) => {
  const { ip, hostname, url, hash } = req.body;
  const config = {
    ip: ip === true || ip === 'true',
    hostname: hostname === true || hostname === 'true',
    url: url === true || url === 'true',
    hash: hash === true || hash === 'true'
  };
  fs.writeFileSync(EXTRACT_CONFIG_PATH, JSON.stringify(config, null, 2));
  res.json({ success: true, config });
});

app.delete('/api/logs', (req, res) => {
  try {
    db.run('DELETE FROM logs');
    db.run('DELETE FROM enrichments');
    saveDb();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/logs/export', (req, res) => {
  try {
    const { start, end, source, level, search } = req.query;
    
    let query = 'SELECT timestamp, source, level, message, raw, ip, hostname, url, hash FROM logs WHERE 1=1';
    const params = [];
    
    if (start) { query += ' AND timestamp >= ?'; params.push(start); }
    if (end) { query += ' AND timestamp <= ?'; params.push(end); }
    if (source) { query += ' AND source LIKE ?'; params.push(`%${source}%`); }
    if (level) { query += ' AND level = ?'; params.push(level.toUpperCase()); }
    if (search) { query += ' AND (message LIKE ? OR raw LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }
    
    query += ' ORDER BY timestamp ASC';
    
    const stmt = db.prepare(query);
    stmt.bind(params);
    const logs = [];
    while (stmt.step()) {
      logs.push(stmt.getAsObject());
    }
    stmt.free();
    
    const headers = ['timestamp', 'source', 'level', 'message', 'ip', 'hostname', 'url', 'hash', 'raw'];
    const csvRows = [headers.join(',')];
    
    const escapeCsv = (str) => {
      if (str === null || str === undefined) return '';
      const s = String(str).replace(/"/g, '""');
      return s.includes(',') || s.includes('"') || s.includes('\n') ? `"${s}"` : s;
    };
    
    for (const log of logs) {
      csvRows.push(headers.map(h => escapeCsv(log[h])).join(','));
    }
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="ir-logs-${new Date().toISOString().slice(0,10)}.csv"`);
    res.send(csvRows.join('\n'));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/stats', (req, res) => {
  try {
    let stmt = db.prepare('SELECT COUNT(*) as count FROM logs');
    stmt.step();
    const total = stmt.getAsObject().count;
    stmt.free();
    
    stmt = db.prepare('SELECT source, COUNT(*) as count FROM logs GROUP BY source');
    const sources = [];
    while (stmt.step()) {
      sources.push(stmt.getAsObject());
    }
    stmt.free();
    
    stmt = db.prepare('SELECT level, COUNT(*) as count FROM logs GROUP BY level');
    const levels = [];
    while (stmt.step()) {
      levels.push(stmt.getAsObject());
    }
    stmt.free();
    
    stmt = db.prepare('SELECT MIN(timestamp) as earliest, MAX(timestamp) as latest FROM logs');
    stmt.step();
    const timeRange = stmt.getAsObject();
    stmt.free();
    
    res.json({ total, sources, levels, timeRange });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`IR Log Analyzer running at http://localhost:${PORT}`);
  });
}).catch(err => {
  console.error('Failed to initialize database:', err);
  process.exit(1);
});
