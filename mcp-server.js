#!/usr/bin/env node

const http = require('http');

const API_URL = process.env.API_URL || 'http://localhost:3000';

function makeRequest(path, method = 'GET', body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, API_URL);
    const options = {
      hostname: url.hostname,
      port: url.port || 3000,
      path: url.pathname,
      method,
      headers: { 'Content-Type': 'application/json' }
    };
    
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          resolve(data);
        }
      });
    });
    
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

const tools = {
  get_logs: {
    name: 'get_logs',
    description: 'Query logs with optional filters (time range, source, level, search)',
    inputSchema: {
      type: 'object',
      properties: {
        search: { type: 'string', description: 'Keyword search' },
        source: { type: 'string', description: 'Filter by source' },
        level: { type: 'string', description: 'Filter by level (CRITICAL, ERROR, WARN, INFO, DEBUG)' },
        start: { type: 'string', description: 'Start time (ISO format)' },
        end: { type: 'string', description: 'End time (ISO format)' },
        limit: { type: 'number', description: 'Number of logs (default 50)', default: 50 }
      }
    }
  },
  
  get_log_detail: {
    name: 'get_log_detail',
    description: 'Get detailed info about a specific log entry including extracted indicators',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'number', description: 'Log ID' }
      },
      required: ['id']
    }
  },
  
  enrich_indicator: {
    name: 'enrich_indicator',
    description: 'Enrich an indicator (IP, domain, hash, URL) with VirusTotal',
    inputSchema: {
      type: 'object',
      properties: {
        indicator: { type: 'string', description: 'The indicator to enrich (IP, domain, hash, URL)' },
        type: { type: 'string', description: 'Type: ip, domain, url, md5, sha1, sha256' }
      },
      required: ['indicator', 'type']
    }
  },
  
  import_logs: {
    name: 'import_logs',
    description: 'Import logs from text content',
    inputSchema: {
      type: 'object',
      properties: {
        content: { type: 'string', description: 'Log content to import' },
        filename: { type: 'string', description: 'Filename for format detection', default: 'logs.log' }
      },
      required: ['content']
    }
  },
  
  get_stats: {
    name: 'get_stats',
    description: 'Get overall statistics about imported logs',
    inputSchema: {
      type: 'object',
      properties: {}
    }
  },
  
  clear_logs: {
    name: 'clear_logs',
    description: 'Clear all logs and enrichments from database',
    inputSchema: {
      type: 'object',
      properties: {}
    }
  }
};

async function handleTool(name, args) {
  switch (name) {
    case 'get_logs':
      const params = new URLSearchParams(args);
      return await makeRequest(`/api/logs?${params}`);
    
    case 'get_log_detail':
      return await makeRequest(`/api/logs/${args.id}`);
    
    case 'enrich_indicator':
      return await makeRequest('/api/enrich', 'POST', args);
    
    case 'import_logs':
      return await makeRequest('/api/logs/import', 'POST', args);
    
    case 'get_stats':
      return await makeRequest('/api/stats');
    
    case 'clear_logs':
      return await makeRequest('/api/logs', 'DELETE');
    
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

const stdin = process.stdin;
const stdout = process.stdout;

let buffer = '';

stdin.setEncoding('utf8');

stdin.on('data', (chunk) => {
  buffer += chunk;
  let newlineIndex;
  while ((newlineIndex = buffer.indexOf('\n')) !== -1) {
    const line = buffer.slice(0, newlineIndex);
    buffer = buffer.slice(newlineIndex + 1);
    
    try {
      const msg = JSON.parse(line);
      
      if (msg.method === 'tools/list') {
        stdout.write(JSON.stringify({
          jsonrpc: '2.0',
          id: msg.id,
          result: { tools: Object.values(tools) }
        }) + '\n');
      } 
      else if (msg.method === 'tools/call') {
        const toolName = msg.params.name;
        const toolArgs = msg.params.arguments || {};
        
        handleTool(toolName, toolArgs)
          .then(result => {
            stdout.write(JSON.stringify({
              jsonrpc: '2.0',
              id: msg.id,
              result: { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] }
            }) + '\n');
          })
          .catch(err => {
            stdout.write(JSON.stringify({
              jsonrpc: '2.0',
              id: msg.id,
              error: { code: -32603, message: err.message }
            }) + '\n');
          });
      }
      else if (msg.method === 'initialize') {
        stdout.write(JSON.stringify({
          jsonrpc: '2.0',
          id: msg.id,
          result: {
            protocolVersion: '2024-11-05',
            capabilities: { tools: {} },
            serverInfo: { name: 'ir-log-analyzer', version: '1.0.0' }
          }
        }) + '\n');
      }
    } catch (e) {
      console.error('Parse error:', e.message);
    }
  }
});
