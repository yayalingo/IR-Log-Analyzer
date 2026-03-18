const express = require('express');
const initSqlJs = require('sql.js');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
const { marked } = require('marked');
const cheerio = require('cheerio');

const app = express();
const PORT = 3000;
const DB_PATH = path.join(__dirname, 'ir-logs.db');

const AUTH_USER = 'sanya';
const AUTH_PASS = 'sanya';

const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 60000;
const RATE_LIMIT_MAX = 100;

function rateLimitMiddleware(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const now = Date.now();
  const record = rateLimitMap.get(ip) || { count: 0, resetTime: now + RATE_LIMIT_WINDOW };
  
  if (now > record.resetTime) {
    record.count = 1;
    record.resetTime = now + RATE_LIMIT_WINDOW;
  } else {
    record.count++;
  }
  
  rateLimitMap.set(ip, record);
  
  if (record.count > RATE_LIMIT_MAX) {
    return res.status(429).json({ error: 'Too many requests. Please try again later.' });
  }
  next();
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  const base64Credentials = authHeader.split(' ')[1];
  if (!base64Credentials) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  const credentials = Buffer.from(base64Credentials, 'base64').toString('utf8');
  const [username, password] = credentials.split(':');
  
  if (username === AUTH_USER && password === AUTH_PASS) {
    next();
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
}

function isValidUrl(urlString) {
  try {
    const url = new URL(urlString);
    const hostname = url.hostname.toLowerCase();
    const invalidHosts = ['localhost', '127.0.0.1', '0.0.0.0', '::1', 'metadata.google.internal', '169.254.169.254'];
    if (invalidHosts.includes(hostname) || hostname.startsWith('192.168.') || hostname.startsWith('10.') || hostname.startsWith('172.16.') || hostname.startsWith('172.17.') || hostname.startsWith('172.18.') || hostname.startsWith('172.19.') || hostname.startsWith('172.2') || hostname.startsWith('172.30.') || hostname.startsWith('172.31.')) {
      return false;
    }
    return ['http:', 'https:'].includes(url.protocol);
  } catch (e) {
    return false;
  }
}

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
  
  db.run(`
    CREATE TABLE IF NOT EXISTS threat_intel (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT,
      source_type TEXT,
      content TEXT,
      url TEXT,
      file_name TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT,
      content TEXT,
      logs_analyzed INTEGER,
      threat_intel_count INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  db.run(`CREATE INDEX IF NOT EXISTS idx_threat_intel_created ON threat_intel(created_at)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at)`);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS cases (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT,
      description TEXT,
      severity TEXT DEFAULT 'Medium',
      status TEXT DEFAULT 'Open',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS case_notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id INTEGER,
      content TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (case_id) REFERENCES cases(id)
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS case_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id INTEGER,
      log_id INTEGER,
      added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (case_id) REFERENCES cases(id),
      FOREIGN KEY (log_id) REFERENCES logs(id)
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS ioc_matches (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      log_id INTEGER,
      indicator TEXT,
      indicator_type TEXT,
      threat_intel_id INTEGER,
      matched_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (log_id) REFERENCES logs(id),
      FOREIGN KEY (threat_intel_id) REFERENCES threat_intel(id)
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS webhook_configs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      url TEXT,
      events TEXT,
      enabled INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS forwarding_configs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      type TEXT,
      config TEXT,
      enabled INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  db.run(`CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_case_notes_case ON case_notes(case_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_ioc_matches_log ON ioc_matches(log_id)`);
  
  saveDb();
}

function saveDb() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
}

function getLastInsertId() {
  const result = db.exec('SELECT last_insert_rowid()');
  if (result && result[0] && result[0].values && result[0].values[0]) {
    return result[0].values[0][0];
  }
  return null;
}

app.use(rateLimitMiddleware);
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (username === AUTH_USER && password === AUTH_PASS) {
    const token = crypto.randomBytes(32).toString('hex');
    res.json({ success: true, token });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.get('/api/auth-check', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.json({ authenticated: false });
  
  const base64Credentials = authHeader.split(' ')[1];
  if (!base64Credentials) return res.json({ authenticated: false });
  
  const credentials = Buffer.from(base64Credentials, 'base64').toString('utf8');
  const [username, password] = credentials.split(':');
  
  if (username === AUTH_USER && password === AUTH_PASS) {
    res.json({ authenticated: true });
  } else {
    res.json({ authenticated: false });
  }
});

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Authentication required' });
  
  const base64Credentials = authHeader.split(' ')[1];
  if (!base64Credentials) return res.status(401).json({ error: 'Authentication required' });
  
  const credentials = Buffer.from(base64Credentials, 'base64').toString('utf8');
  const [username, password] = credentials.split(':');
  
  if (username === AUTH_USER && password === AUTH_PASS) {
    next();
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
}

const upload = multer({ 
  dest: '/tmp/',
  limits: { fileSize: 50 * 1024 * 1024 }
});

const VT_API_KEY = process.env.VT_API_KEY || '';
const OLLAMA_CONFIG_PATH = path.join(__dirname, '.ollama-config');

let ollamaConfig = {
  url: 'http://localhost:11434',
  model: 'llama3'
};

function loadOllamaConfig() {
  if (fs.existsSync(OLLAMA_CONFIG_PATH)) {
    try {
      ollamaConfig = JSON.parse(fs.readFileSync(OLLAMA_CONFIG_PATH, 'utf8'));
    } catch(e) {}
  }
  return ollamaConfig;
}

function saveOllamaConfig(config) {
  ollamaConfig = { ...ollamaConfig, ...config };
  fs.writeFileSync(OLLAMA_CONFIG_PATH, JSON.stringify(ollamaConfig, null, 2));
  return ollamaConfig;
}

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

app.post('/api/logs/import', requireAuth, upload.single('file'), (req, res) => {
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

app.get('/api/logs', requireAuth, (req, res) => {
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

app.get('/api/logs/:id', requireAuth, (req, res) => {
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

app.post('/api/enrich', requireAuth, async (req, res) => {
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

app.get('/api/enrich/:indicator', requireAuth, (req, res) => {
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

app.post('/api/config/vt-key', requireAuth, (req, res) => {
  const { apiKey } = req.body;
  if (!apiKey) return res.status(400).json({ error: 'Missing apiKey' });
  
  fs.writeFileSync(path.join(__dirname, '.vt-key'), apiKey);
  res.json({ success: true });
});

app.get('/api/config/vt-key', requireAuth, (req, res) => {
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

app.get('/api/config/extraction', requireAuth, (req, res) => {
  res.json(getExtractConfig());
});

app.post('/api/config/extraction', requireAuth, (req, res) => {
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

app.delete('/api/logs', requireAuth, (req, res) => {
  try {
    db.run('DELETE FROM logs');
    db.run('DELETE FROM enrichments');
    saveDb();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/logs/export', requireAuth, (req, res) => {
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

app.get('/api/stats', requireAuth, (req, res) => {
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

app.get('/api/config/ollama', requireAuth, (req, res) => {
  const config = loadOllamaConfig();
  res.json(config);
});

app.post('/api/config/ollama', requireAuth, (req, res) => {
  const { url, model } = req.body;
  const config = saveOllamaConfig({ url, model });
  res.json(config);
});

app.post('/api/threat-intel/import', requireAuth, upload.single('file'), (req, res) => {
  try {
    let content = '';
    let fileName = '';
    
    if (req.file) {
      fileName = req.file.originalname;
      content = fs.readFileSync(req.file.path, 'utf8');
      fs.unlinkSync(req.file.path);
    } else if (req.body.content) {
      content = req.body.content;
      fileName = req.body.filename || 'manual-input.txt';
    } else {
      return res.status(400).json({ error: 'No content provided' });
    }
    
    const title = req.body.title || fileName.substring(0, 100);
    
    const stmt = db.prepare(`
      INSERT INTO threat_intel (title, source_type, content, file_name)
      VALUES (?, ?, ?, ?)
    `);
    stmt.run([title, req.file ? 'file' : 'text', content, fileName]);
    stmt.free();
    
    saveDb();
    
    res.json({ success: true, id: getLastInsertId() });
  } catch (error) {
    console.error('Threat intel import error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/threat-intel/url', requireAuth, async (req, res) => {
  try {
    const { url, title } = req.body;
    if (!url) return res.status(400).json({ error: 'URL is required' });
    
    if (!isValidUrl(url)) {
      return res.status(400).json({ error: 'Invalid or disallowed URL' });
    }
    
    const response = await axios.get(url, { timeout: 30000 });
    const $ = cheerio.load(response.data);
    
    $('script, style, nav, footer, header, aside').remove();
    const content = $('body').text().trim().substring(0, 50000);
    
    const pageTitle = title || $('title').text() || url;
    
    const stmt = db.prepare(`
      INSERT INTO threat_intel (title, source_type, content, url)
      VALUES (?, ?, ?, ?)
    `);
    stmt.run([pageTitle.substring(0, 100), 'url', content, url]);
    stmt.free();
    
    saveDb();
    
    res.json({ success: true, id: getLastInsertId(), title: pageTitle });
  } catch (error) {
    console.error('URL fetch error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/threat-intel', requireAuth, (req, res) => {
  try {
    const stmt = db.prepare('SELECT id, title, source_type, url, file_name, created_at FROM threat_intel ORDER BY created_at DESC');
    const items = [];
    while (stmt.step()) {
      items.push(stmt.getAsObject());
    }
    stmt.free();
    res.json(items);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/threat-intel/:id', requireAuth, (req, res) => {
  try {
    const stmt = db.prepare('SELECT * FROM threat_intel WHERE id = ?');
    stmt.bind([parseInt(req.params.id)]);
    if (stmt.step()) {
      const item = stmt.getAsObject();
      stmt.free();
      return res.json(item);
    }
    stmt.free();
    res.status(404).json({ error: 'Not found' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/threat-intel/:id', requireAuth, (req, res) => {
  try {
    db.run('DELETE FROM threat_intel WHERE id = ?', [parseInt(req.params.id)]);
    saveDb();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/analyze', requireAuth, async (req, res) => {
  try {
    const config = loadOllamaConfig();
    const { scope, customPrompt, caseId } = req.body;
    
    let logs = [];
    let logCount = 0;
    let caseInfo = null;
    
    if (caseId) {
      const caseStmt = db.prepare('SELECT * FROM cases WHERE id = ?');
      caseStmt.bind([parseInt(caseId)]);
      if (caseStmt.step()) {
        caseInfo = caseStmt.getAsObject();
      }
      caseStmt.free();
      
      const logsStmt = db.prepare(`
        SELECT l.* FROM logs l
        JOIN case_logs cl ON l.id = cl.log_id
        WHERE cl.case_id = ?
        ORDER BY l.timestamp ASC
      `);
      logsStmt.bind([parseInt(caseId)]);
      while (logsStmt.step()) {
        logs.push(logsStmt.getAsObject());
      }
      logsStmt.free();
      logCount = logs.length;
    } else {
      let logQuery = 'SELECT * FROM logs ORDER BY timestamp ASC';
      const stmt = db.prepare(logQuery);
      while (stmt.step()) {
        logs.push(stmt.getAsObject());
      }
      stmt.free();
      logCount = logs.length;
    }
    
    const logLimit = scope?.logLimit || 100;
    const sampleLogs = logs.slice(-logLimit);
    
    const tiStmt = db.prepare('SELECT * FROM threat_intel ORDER BY created_at DESC');
    const threatIntel = [];
    while (tiStmt.step()) {
      threatIntel.push(tiStmt.getAsObject());
    }
    tiStmt.free();
    
    const tiContext = threatIntel.length > 0 
      ? `THREAT INTELLIGENCE REFERENCES:\n${threatIntel.map(t => `[${t.title}] ${t.content.substring(0, 2000)}`).join('\n\n')}`
      : '';
    
    const caseContext = caseInfo 
      ? `CASE INFORMATION:\nTitle: ${caseInfo.title}\nSeverity: ${caseInfo.severity}\nStatus: ${caseInfo.status}\nDescription: ${caseInfo.description || 'N/A'}\n\n`
      : '';
    
    const logsContext = caseId
      ? `LOG DATA (${sampleLogs.length} of ${logCount} case-linked logs):\n${sampleLogs.map(l => 
        `[${l.timestamp}] [${l.level}] [${l.source}] ${l.message}`
      ).join('\n')}`
      : `LOG DATA (last ${sampleLogs.length} of ${logCount} logs):\n${sampleLogs.map(l => 
        `[${l.timestamp}] [${l.level}] [${l.source}] ${l.message}`
      ).join('\n')}`;
    
    const defaultPrompt = `You are a cybersecurity incident response analyst. Analyze the following logs and threat intelligence to produce a comprehensive investigation report.

${caseContext}${tiContext}

${logsContext}

Based on your analysis, provide a detailed investigation report in markdown format with the following sections:
1. **Executive Summary** - Brief overview of the incident
2. **Timeline of Events** - Chronological sequence of suspicious activities
3. **Key Findings** - Important observations and patterns
4. **Indicators of Compromise (IOCs)** - IPs, domains, hashes, URLs identified
5. **Attack Vector Analysis** - How the attack likely occurred
6. **Severity Assessment** - Impact and criticality
7. **Recommendations** - Next steps for containment and remediation

Focus on security-relevant events, errors, warnings, and suspicious patterns.`;
    
    const prompt = customPrompt || defaultPrompt;
    
    try {
      const ollamaRes = await axios.post(`${config.url}/api/generate`, {
        model: config.model,
        prompt: prompt,
        stream: false
      }, { timeout: 300000 });
      
      const analysis = ollamaRes.data.response;
      
      const reportStmt = db.prepare(`
        INSERT INTO reports (title, content, logs_analyzed, threat_intel_count)
        VALUES (?, ?, ?, ?)
      `);
      const reportTitle = caseInfo 
        ? `Investigation Report - ${caseInfo.title} - ${new Date().toISOString().slice(0,10)}`
        : `Investigation Report - ${new Date().toISOString().slice(0,10)}`;
      reportStmt.run([reportTitle, analysis, logCount, threatIntel.length]);
      reportStmt.free();
      
      saveDb();
      
      const reportId = getLastInsertId();
      
      res.json({ success: true, report: { id: reportId, title: reportTitle, content: analysis }, caseId: caseId ? parseInt(caseId) : null });
    } catch (ollamaError) {
      console.error('Ollama error:', ollamaError.message);
      res.status(500).json({ error: `Ollama API error: ${ollamaError.message}` });
    }
  } catch (error) {
    console.error('Analysis error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/reports', requireAuth, (req, res) => {
  try {
    const stmt = db.prepare('SELECT id, title, logs_analyzed, threat_intel_count, created_at FROM reports ORDER BY created_at DESC');
    const reports = [];
    while (stmt.step()) {
      reports.push(stmt.getAsObject());
    }
    stmt.free();
    res.json(reports);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/reports/:id', requireAuth, (req, res) => {
  try {
    const stmt = db.prepare('SELECT * FROM reports WHERE id = ?');
    stmt.bind([parseInt(req.params.id)]);
    if (stmt.step()) {
      const report = stmt.getAsObject();
      stmt.free();
      return res.json(report);
    }
    stmt.free();
    res.status(404).json({ error: 'Not found' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/reports/:id', requireAuth, (req, res) => {
  try {
    db.run('DELETE FROM reports WHERE id = ?', [parseInt(req.params.id)]);
    saveDb();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/chef', (req, res) => {
  res.redirect('https://gchq.github.io/Chef炒/');
});

const MITRE_TECHNIQUES = {
  'T1078': { name: 'Valid Accounts', severity: 'High' },
  'T1078.003': { name: 'Valid Accounts: Cloud Accounts', severity: 'High' },
  'T1082': { name: 'System Information Discovery', severity: 'Medium' },
  'T1083': { name: 'File and Directory Discovery', severity: 'Medium' },
  'T1087': { name: 'Account Discovery', severity: 'Medium' },
  'T1105': { name: 'Ingress Tool Transfer', severity: 'High' },
  'T1110': { name: 'Brute Force', severity: 'High' },
  'T1112': { name: 'Modify Registry', severity: 'High' },
  'T1113': { name: 'Screen Capture', severity: 'Medium' },
  'T1486': { name: 'Data Encrypted for Impact', severity: 'Critical' },
  'T1490': { name: 'Inhibit System Recovery', severity: 'High' },
  'T1059': { name: 'Command and Scripting Interpreter', severity: 'High' },
  'T1059.004': { name: 'Command and Scripting Interpreter: Unix Shell', severity: 'High' },
  'T1059.007': { name: 'Command and Scripting Interpreter: JavaScript', severity: 'High' },
  'T1021': { name: 'Remote Services', severity: 'High' },
  'T1021.001': { name: 'Remote Services: Remote Desktop Protocol', severity: 'High' },
  'T1021.004': { name: 'Remote Services: SSH', severity: 'High' },
  'T1003': { name: 'OS Credential Dumping', severity: 'Critical' },
  'T1005': { name: 'Data from Local System', severity: 'High' },
  'T1041': { name: 'Exfiltration Over C2 Channel', severity: 'Critical' },
  'T1047': { name: 'Windows Management Instrumentation', severity: 'High' },
  'T1053': { name: 'Scheduled Task/Job', severity: 'High' },
  'T1055': { name: 'Process Injection', severity: 'High' },
  'T1068': { name: 'Exploitation for Privilege Escalation', severity: 'Critical' },
  'T1190': { name: 'Exploit Public-Facing Application', severity: 'Critical' },
  'T1200': { name: 'Adversary in the Middle', severity: 'High' },
  'T1203': { name: 'Exploitation for Client Execution', severity: 'High' },
  'T1210': { name: 'Exploitation of Remote Services', severity: 'Critical' },
  'T1547': { name: 'Boot or Logon Autostart Execution', severity: 'High' },
  'T1569': { name: 'System Services', severity: 'High' },
  'T1573': { name: 'Encrypted Channel', severity: 'High' },
  'T1588': { name: 'Obtain Capabilities', severity: 'Medium' },
  'T1595': { name: 'Active Scanning', severity: 'Medium' },
  'T1592': { name: 'Gather Victim Host Information', severity: 'Low' },
};

function calculateSeverity(level, indicators) {
  let score = 0;
  const levelScores = { CRITICAL: 10, FATAL: 10, ERROR: 7, WARN: 4, WARNING: 4, INFO: 1, DEBUG: 0, TRACE: 0 };
  score += levelScores[level] || 0;
  
  if (indicators?.ip) score += 3;
  if (indicators?.hash) score += 5;
  if (indicators?.url) score += 4;
  if (indicators?.hostname?.includes('.onion')) score += 8;
  
  if (score >= 10) return 'Critical';
  if (score >= 7) return 'High';
  if (score >= 4) return 'Medium';
  if (score >= 1) return 'Low';
  return 'Info';
}

function mapToMitre(log) {
  const techniques = [];
  const message = (log.message || '').toLowerCase();
  const raw = (log.raw || '').toLowerCase();
  const combined = message + ' ' + raw;
  
  if (combined.includes('ssh') && (combined.includes('failed') || combined.includes('authentication'))) {
    techniques.push({ id: 'T1110', ...MITRE_TECHNIQUES['T1110'] });
  }
  if (combined.includes('cmd.exe') || combined.includes('powershell') || combined.includes('bash') || combined.includes('sh -')) {
    techniques.push({ id: 'T1059', ...MITRE_TECHNIQUES['T1059'] });
  }
  if (combined.includes('registry') && (combined.includes('modify') || combined.includes('set') || combined.includes('add'))) {
    techniques.push({ id: 'T1112', ...MITRE_TECHNIQUES['T1112'] });
  }
  if (combined.includes('wmic') || combined.includes('winrm')) {
    techniques.push({ id: 'T1047', ...MITRE_TECHNIQUES['T1047'] });
  }
  if (combined.includes('scheduled task') || combined.includes('cron') || combined.includes('at job')) {
    techniques.push({ id: 'T1053', ...MITRE_TECHNIQUES['T1053'] });
  }
  if (combined.includes('lsass') || combined.includes('mimikatz') || combined.includes('credential')) {
    techniques.push({ id: 'T1003', ...MITRE_TECHNIQUES['T1003'] });
  }
  if (combined.includes('meterpreter') || combined.includes('reverse shell') || combined.includes('backdoor')) {
    techniques.push({ id: 'T1105', ...MITRE_TECHNIQUES['T1105'] });
  }
  if (combined.includes('rdp') || combined.includes('remote desktop')) {
    techniques.push({ id: 'T1021.001', ...MITRE_TECHNIQUES['T1021.001'] });
  }
  if (combined.includes('whoami') || combined.includes('hostname') || combined.includes('uname')) {
    techniques.push({ id: 'T1082', ...MITRE_TECHNIQUES['T1082'] });
  }
  if (combined.includes('.onion') || combined.includes('tor')) {
    techniques.push({ id: 'T1573', ...MITRE_TECHNIQUES['T1573'] });
  }
  if (combined.includes('exploit') || combined.includes('cve-')) {
    techniques.push({ id: 'T1190', ...MITRE_TECHNIQUES['T1190'] });
  }
  
  return techniques;
}

async function checkIocMatches(log) {
  const matches = [];
  const indicators = extractIndicators(log.raw || log.message || '');
  
  const tiStmt = db.prepare('SELECT * FROM threat_intel WHERE content LIKE ?');
  tiStmt.bind([`%${indicators.ips[0] || ''}%`]);
  while (tiStmt.step()) {
    const ti = tiStmt.getAsObject();
    if (indicators.ips.some(ip => ti.content.includes(ip))) {
      matches.push({ type: 'ip', value: indicators.ips.find(ip => ti.content.includes(ip)), threat_intel_id: ti.id });
    }
  }
  tiStmt.free();
  
  return matches;
}

async function sendWebhook(event, data) {
  try {
    const stmt = db.prepare('SELECT * FROM webhook_configs WHERE enabled = 1 AND events LIKE ?');
    stmt.bind([`%${event}%`]);
    const webhooks = [];
    while (stmt.step()) {
      webhooks.push(stmt.getAsObject());
    }
    stmt.free();
    
    for (const wh of webhooks) {
      try {
        await axios.post(wh.url, { event, data, timestamp: new Date().toISOString() }, { timeout: 5000 });
      } catch (e) {
        console.error('Webhook error:', e.message);
      }
    }
  } catch (e) {
    console.error('Webhook config error:', e.message);
  }
}

app.get('/api/logs/timeline', requireAuth, (req, res) => {
  try {
    const { start, end, interval = 'hour' } = req.query;
    
    let query = 'SELECT timestamp, level, source FROM logs WHERE 1=1';
    const params = [];
    
    if (start) { query += ' AND timestamp >= ?'; params.push(start); }
    if (end) { query += ' AND timestamp <= ?'; params.push(end); }
    
    query += ' ORDER BY timestamp ASC';
    
    const stmt = db.prepare(query);
    stmt.bind(params);
    const logs = [];
    while (stmt.step()) {
      logs.push(stmt.getAsObject());
    }
    stmt.free();
    
    const buckets = {};
    logs.forEach(log => {
      const ts = new Date(log.timestamp);
      let key;
      if (interval === 'minute') {
        key = ts.toISOString().slice(0, 16);
      } else if (interval === 'hour') {
        key = ts.toISOString().slice(0, 13);
      } else if (interval === 'day') {
        key = ts.toISOString().slice(0, 10);
      }
      
      if (!buckets[key]) {
        buckets[key] = { timestamp: key, total: 0, critical: 0, error: 0, warn: 0, info: 0, debug: 0 };
      }
      buckets[key].total++;
      const lvl = log.level?.toLowerCase() || 'info';
      if (['critical', 'fatal'].includes(lvl)) buckets[key].critical++;
      else if (lvl === 'error') buckets[key].error++;
      else if (lvl === 'warn' || lvl === 'warning') buckets[key].warn++;
      else if (lvl === 'info') buckets[key].info++;
      else buckets[key].debug++;
    });
    
    const timeline = Object.values(buckets).sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    res.json(timeline);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/cases', requireAuth, (req, res) => {
  try {
    const { title, description, severity = 'Medium' } = req.body;
    if (!title) return res.status(400).json({ error: 'Title is required' });
    
    const stmt = db.prepare('INSERT INTO cases (title, description, severity) VALUES (?, ?, ?)');
    stmt.run([title, description || '', severity]);
    stmt.free();
    
    saveDb();
    
    const id = getLastInsertId();
    res.json({ success: true, id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/cases', requireAuth, (req, res) => {
  try {
    const { status } = req.query;
    let query = 'SELECT * FROM cases';
    const params = [];
    if (status) { query += ' WHERE status = ?'; params.push(status); }
    query += ' ORDER BY created_at DESC';
    
    const stmt = db.prepare(query);
    stmt.bind(params);
    const cases = [];
    while (stmt.step()) {
      const c = stmt.getAsObject();
      const countStmt = db.prepare('SELECT COUNT(*) as count FROM case_logs WHERE case_id = ?');
      countStmt.bind([c.id]);
      countStmt.step();
      c.linked_logs_count = countStmt.getAsObject().count;
      countStmt.free();
      cases.push(c);
    }
    stmt.free();
    res.json(cases);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/cases/:id', requireAuth, (req, res) => {
  try {
    const stmt = db.prepare('SELECT * FROM cases WHERE id = ?');
    stmt.bind([parseInt(req.params.id)]);
    if (stmt.step()) {
      const caseData = stmt.getAsObject();
      stmt.free();
      
      const notesStmt = db.prepare('SELECT * FROM case_notes WHERE case_id = ? ORDER BY created_at DESC');
      notesStmt.bind([caseData.id]);
      const notes = [];
      while (notesStmt.step()) {
        notes.push(notesStmt.getAsObject());
      }
      notesStmt.free();
      
      const logsStmt = db.prepare(`
        SELECT l.* FROM logs l
        JOIN case_logs cl ON l.id = cl.log_id
        WHERE cl.case_id = ?
        ORDER BY l.timestamp ASC
      `);
      logsStmt.bind([caseData.id]);
      const linkedLogs = [];
      while (logsStmt.step()) {
        linkedLogs.push(logsStmt.getAsObject());
      }
      logsStmt.free();
      
      res.json({ ...caseData, notes, linkedLogs });
    } else {
      stmt.free();
      res.status(404).json({ error: 'Case not found' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/cases/:id', requireAuth, (req, res) => {
  try {
    const { title, description, severity, status } = req.body;
    const stmt = db.prepare(`
      UPDATE cases SET title = COALESCE(?, title), description = COALESCE(?, description),
      severity = COALESCE(?, severity), status = COALESCE(?, status), updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `);
    stmt.run([title, description, severity, status, parseInt(req.params.id)]);
    stmt.free();
    
    saveDb();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/cases/:id', requireAuth, (req, res) => {
  try {
    db.run('DELETE FROM case_notes WHERE case_id = ?', [parseInt(req.params.id)]);
    db.run('DELETE FROM case_logs WHERE case_id = ?', [parseInt(req.params.id)]);
    db.run('DELETE FROM cases WHERE id = ?', [parseInt(req.params.id)]);
    saveDb();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/cases/:id/notes', requireAuth, (req, res) => {
  try {
    const { content } = req.body;
    if (!content) return res.status(400).json({ error: 'Content is required' });
    
    const stmt = db.prepare('INSERT INTO case_notes (case_id, content) VALUES (?, ?)');
    stmt.run([parseInt(req.params.id), content]);
    stmt.free();
    
    saveDb();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/cases/:id/logs', requireAuth, (req, res) => {
  try {
    const { logIds } = req.body;
    if (!logIds || !Array.isArray(logIds)) {
      return res.status(400).json({ error: 'logIds array is required' });
    }
    
    const stmt = db.prepare('INSERT OR IGNORE INTO case_logs (case_id, log_id) VALUES (?, ?)');
    for (const logId of logIds) {
      stmt.run([parseInt(req.params.id), logId]);
    }
    stmt.free();
    
    saveDb();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/dashboard', requireAuth, (req, res) => {
  try {
    let stmt = db.prepare('SELECT COUNT(*) as count FROM logs');
    stmt.step();
    const totalLogs = stmt.getAsObject().count;
    stmt.free();
    
    stmt = db.prepare('SELECT COUNT(*) as count FROM cases WHERE status = "Open"');
    stmt.step();
    const openCases = stmt.getAsObject().count;
    stmt.free();
    
    stmt = db.prepare('SELECT level, COUNT(*) as count FROM logs GROUP BY level');
    const levelCounts = {};
    while (stmt.step()) {
      const row = stmt.getAsObject();
      levelCounts[row.level] = row.count;
    }
    stmt.free();
    
    stmt = db.prepare('SELECT COUNT(*) as count FROM ioc_matches');
    stmt.step();
    const iocMatches = stmt.getAsObject().count;
    stmt.free();
    
    stmt = db.prepare('SELECT COUNT(*) as count FROM threat_intel');
    stmt.step();
    const threatIntelCount = stmt.getAsObject().count;
    stmt.free();
    
    stmt = db.prepare(`
      SELECT DATE(timestamp) as date, COUNT(*) as count 
      FROM logs 
      WHERE timestamp >= DATE('now', '-7 days')
      GROUP BY DATE(timestamp)
      ORDER BY date ASC
    `);
    const recentTrend = [];
    while (stmt.step()) {
      recentTrend.push(stmt.getAsObject());
    }
    stmt.free();
    
    stmt = db.prepare(`
      SELECT source, COUNT(*) as count FROM logs 
      GROUP BY source ORDER BY count DESC LIMIT 5
    `);
    const topSources = [];
    while (stmt.step()) {
      topSources.push(stmt.getAsObject());
    }
    stmt.free();
    
    res.json({
      totalLogs,
      openCases,
      levelCounts,
      iocMatches,
      threatIntelCount,
      recentTrend,
      topSources
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/logs/severity', requireAuth, (req, res) => {
  try {
    const { id } = req.query;
    const stmt = db.prepare('SELECT * FROM logs WHERE id = ?');
    stmt.bind([parseInt(id)]);
    if (stmt.step()) {
      const log = stmt.getAsObject();
      stmt.free();
      
      const indicators = extractIndicators(log.raw || log.message || '');
      const severity = calculateSeverity(log.level, indicators);
      const mitre = mapToMitre(log);
      
      res.json({ severity, mitre, indicators });
    } else {
      stmt.free();
      res.status(404).json({ error: 'Log not found' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/mitre', requireAuth, (req, res) => {
  res.json(MITRE_TECHNIQUES);
});

app.post('/api/threat-intel/misp/import', requireAuth, async (req, res) => {
  try {
    const { url, apiKey } = req.body;
    if (!url || !apiKey) return res.status(400).json({ error: 'MISP URL and API key required' });
    
    const response = await axios.get(`${url}/events`, {
      headers: { 'Authorization': apiKey },
      params: { limit: 50 }
    });
    
    const events = response.data.response || [];
    let imported = 0;
    
    for (const event of events) {
      const content = JSON.stringify(event);
      const title = event.Event?.info || `MISP Event ${event.Event?.id}`;
      
      const stmt = db.prepare('INSERT INTO threat_intel (title, source_type, content) VALUES (?, ?, ?)');
      stmt.run([title, 'misp', content]);
      stmt.free();
      imported++;
    }
    
    saveDb();
    res.json({ success: true, imported });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/threat-intel/stix/import', requireAuth, (req, res) => {
  try {
    const { bundle } = req.body;
    if (!bundle) return res.status(400).json({ error: 'STIX bundle required' });
    
    const objects = bundle.objects || [];
    let imported = 0;
    
    for (const obj of objects) {
      if (obj.type === 'indicator' || obj.type === 'malware' || obj.type === 'attack-pattern') {
        const content = JSON.stringify(obj);
        const title = obj.name || obj.pattern || `STIX ${obj.type}`;
        
        const stmt = db.prepare('INSERT INTO threat_intel (title, source_type, content) VALUES (?, ?, ?)');
        stmt.run([title, 'stix', content]);
        stmt.free();
        imported++;
      }
    }
    
    saveDb();
    res.json({ success: true, imported });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/ioc/match', requireAuth, async (req, res) => {
  try {
    const { logId } = req.body;
    if (!logId) return res.status(400).json({ error: 'logId required' });
    
    const stmt = db.prepare('SELECT * FROM logs WHERE id = ?');
    stmt.bind([parseInt(logId)]);
    if (!stmt.step()) {
      stmt.free();
      return res.status(404).json({ error: 'Log not found' });
    }
    const log = stmt.getAsObject();
    stmt.free();
    
    const matches = await checkIocMatches(log);
    
    for (const match of matches) {
      const insertStmt = db.prepare(`
        INSERT INTO ioc_matches (log_id, indicator, indicator_type, threat_intel_id)
        VALUES (?, ?, ?, ?)
      `);
      insertStmt.run([logId, match.value, match.type, match.threat_intel_id]);
      insertStmt.free();
    }
    
    saveDb();
    res.json({ success: true, matches });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/ioc/matches', requireAuth, (req, res) => {
  try {
    const stmt = db.prepare(`
      SELECT im.*, l.timestamp, l.level, l.source, l.message
      FROM ioc_matches im
      JOIN logs l ON im.log_id = l.id
      ORDER BY im.matched_at DESC
      LIMIT 100
    `);
    const matches = [];
    while (stmt.step()) {
      matches.push(stmt.getAsObject());
    }
    stmt.free();
    res.json(matches);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/config/webhooks', requireAuth, (req, res) => {
  try {
    const stmt = db.prepare('SELECT * FROM webhook_configs ORDER BY created_at DESC');
    const configs = [];
    while (stmt.step()) {
      configs.push(stmt.getAsObject());
    }
    stmt.free();
    res.json(configs);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/config/webhooks', requireAuth, (req, res) => {
  try {
    const { name, url, events, enabled = true } = req.body;
    if (!name || !url || !events) {
      return res.status(400).json({ error: 'name, url, and events are required' });
    }
    
    if (!isValidUrl(url)) {
      return res.status(400).json({ error: 'Invalid or disallowed URL' });
    }
    
    const stmt = db.prepare('INSERT INTO webhook_configs (name, url, events, enabled) VALUES (?, ?, ?, ?)');
    stmt.run([name, url, JSON.stringify(events), enabled ? 1 : 0]);
    stmt.free();
    
    saveDb();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/config/webhooks/:id', requireAuth, (req, res) => {
  try {
    db.run('DELETE FROM webhook_configs WHERE id = ?', [parseInt(req.params.id)]);
    saveDb();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/config/webhooks/:id/test', requireAuth, async (req, res) => {
  try {
    const stmt = db.prepare('SELECT * FROM webhook_configs WHERE id = ?');
    stmt.bind([parseInt(req.params.id)]);
    if (!stmt.step()) {
      stmt.free();
      return res.status(404).json({ error: 'Webhook not found' });
    }
    const webhook = stmt.getAsObject();
    stmt.free();
    
    await axios.post(webhook.url, { test: true, timestamp: new Date().toISOString() }, { timeout: 5000 });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/config/forwarding', requireAuth, (req, res) => {
  try {
    const stmt = db.prepare('SELECT * FROM forwarding_configs ORDER BY created_at DESC');
    const configs = [];
    while (stmt.step()) {
      configs.push(stmt.getAsObject());
    }
    stmt.free();
    res.json(configs);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/config/forwarding', requireAuth, (req, res) => {
  try {
    const { name, type, config, enabled = true } = req.body;
    if (!name || !type || !config) {
      return res.status(400).json({ error: 'name, type, and config are required' });
    }
    
    const stmt = db.prepare('INSERT INTO forwarding_configs (name, type, config, enabled) VALUES (?, ?, ?, ?)');
    stmt.run([name, type, JSON.stringify(config), enabled ? 1 : 0]);
    stmt.free();
    
    saveDb();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/config/forwarding/:id', requireAuth, (req, res) => {
  try {
    db.run('DELETE FROM forwarding_configs WHERE id = ?', [parseInt(req.params.id)]);
    saveDb();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/forward/test', requireAuth, async (req, res) => {
  try {
    const { type, config } = req.body;
    
    if (type === 'syslog') {
      const dgram = require('dgram');
      const client = dgram.createSocket('udp4');
      const message = Buffer.from(JSON.stringify({ test: true, timestamp: new Date().toISOString() }));
      client.send(message, 0, message.length, config.port || 514, config.host || 'localhost', (err) => {
        client.close();
        if (err) throw err;
        res.json({ success: true });
      });
    } else if (type === 'http') {
      await axios.post(config.url, { test: true, timestamp: new Date().toISOString() }, { timeout: 5000 });
      res.json({ success: true });
    } else {
      res.status(400).json({ error: 'Unknown forwarding type' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api', (req, res) => {
  res.json({
    name: 'IR Log Analyzer API',
    version: '2.0.0',
    endpoints: {
      logs: ['GET /api/logs', 'POST /api/logs/import', 'GET /api/logs/:id', 'DELETE /api/logs', 'GET /api/logs/export', 'GET /api/logs/timeline'],
      threat_intel: ['GET /api/threat-intel', 'POST /api/threat-intel/import', 'POST /api/threat-intel/url', 'POST /api/threat-intel/misp/import', 'POST /api/threat-intel/stix/import'],
      analysis: ['POST /api/analyze', 'GET /api/reports', 'GET /api/logs/severity', 'GET /api/mitre', 'POST /api/ioc/match', 'GET /api/ioc/matches'],
      cases: ['GET /api/cases', 'POST /api/cases', 'GET /api/cases/:id', 'PUT /api/cases/:id', 'DELETE /api/cases/:id', 'POST /api/cases/:id/notes', 'POST /api/cases/:id/logs'],
      config: ['GET /api/config/ollama', 'POST /api/config/ollama', 'GET /api/config/webhooks', 'POST /api/config/webhooks', 'GET /api/config/forwarding', 'POST /api/config/forwarding'],
      other: ['GET /api/dashboard', 'GET /api/stats', 'GET /api/chef']
    }
  });
});

initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`IR Log Analyzer running at http://localhost:${PORT}`);
  });
}).catch(err => {
  console.error('Failed to initialize database:', err);
  process.exit(1);
});
