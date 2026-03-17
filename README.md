# IR Log Analyzer

Incident Response Log Analysis Tool with Timeline Visualization and Threat Intelligence Enrichment.

## Features

- **Log Import**: Upload files (JSON, Syslog, CSV, plain text, XML) or paste logs directly
- **Timeline View**: Chronological log display with color-coded severity levels
- **Filtering**: Filter by time range, source, log level, and keyword search
- **Threat Intelligence**: Extract and enrich IPs, domains, URLs, and file hashes with VirusTotal
- **Dark Mode**: Full dark theme UI for comfortable viewing
- **MCP Server**: Connect via Model Context Protocol for AI integration

## Quick Start

```bash
# Clone the repo
git clone https://github.com/yayalingo/IR-Log-Analyzer.git
cd IR-Log-Analyzer

# Install dependencies
npm install

# Start the server
npm start
```

Open http://localhost:3000 in your browser.

## Configuration

1. Click the **⚙️ Config** button
2. Enter your VirusTotal API key
3. Click Save

Get a free API key at [virustotal.com](https://www.virustotal.com)

## Supported Log Formats

- JSON (one object per line)
- Syslog
- CSV
- Plain text
- Windows Event XML

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/logs/import` | POST | Import logs |
| `/api/logs` | GET | Query logs with filters |
| `/api/logs/:id` | GET | Get log details |
| `/api/enrich` | POST | Enrich indicator |
| `/api/stats` | GET | Get statistics |
| `/api/logs` | DELETE | Clear all logs |

## MCP Server

Connect to AI assistants via Model Context Protocol. See `mcp-config.json` for configuration.

```bash
# Run MCP server
node mcp-server.js
```

### Available MCP Tools

- `get_logs` - Query logs with filters
- `get_log_detail` - Get log details with indicators
- `enrich_indicator` - VT enrichment for IPs, domains, hashes
- `import_logs` - Import log content
- `get_stats` - Statistics overview

## Tech Stack

- Backend: Node.js + Express
- Database: SQLite (sql.js)
- Frontend: Vanilla HTML/CSS/JS

## License

MIT
