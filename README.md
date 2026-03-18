# IR Log Analyzer

Incident Response Log Analysis Tool with Timeline Visualization, AI-Powered Analysis, and Threat Intelligence Enrichment.

## Features

- **Log Import**: Upload files (JSON, Syslog, CSV, plain text, XML) or paste logs directly
- **Log Deduplication**: Automatic removal of duplicate logs on import
- **Timeline View**: Chronological log display with color-coded severity levels, resizable columns
- **Filtering**: Filter by time range, source, log level, and keyword search
- **Field Extraction**: Configurable extraction of IPs, hostnames, URLs, and file hashes
- **CSV Export**: Export filtered logs to CSV format
- **Threat Intelligence**: Extract and enrich IPs, domains, URLs, and file hashes with VirusTotal
- **AI Analysis**: Analyze case logs with Ollama (local LLM) for incident investigation reports
- **Case Management**: Create cases, link logs, add notes, and track investigation progress
- **Dashboard**: Overview of logs, cases, IOC matches, and threat intel statistics
- **Integrations**: Webhook notifications and log forwarding (Syslog, HTTP)
- **MISP/STIX Import**: Import threat intelligence from MISP and STIX formats
- **Dark Mode**: Full dark theme UI for comfortable viewing
- **Authentication**: Secure access with username/password

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

## Authentication

The application requires authentication. Default credentials:
- Username: `admin`
- Password: `admin`

**For production, use environment variables:**
```bash
export AUTH_USER=your_user
export AUTH_PASS=your_password
npm start
```

## Configuration

### VirusTotal API

1. Click the **⚙️ Config** button
2. Enter your VirusTotal API key
3. Click Save

Get a free API key at [virustotal.com](https://www.virustotal.com)

### Ollama (AI Analysis)

1. Install [Ollama](https://ollama.ai/) on your machine
2. Pull a model: `ollama pull llama3:latest`
3. Start Ollama: `ollama serve`
4. In the app, click **AI Analysis Config** and verify the URL (`http://localhost:11434`)
5. Select a case and click **Start Analysis** to generate investigation reports

**For LAN access**, start Ollama with:
```bash
OLLAMA_HOST=0.0.0.0 ollama serve
```
Then update the URL in the app to your machine's IP (e.g., `http://192.168.1.100:11434`)

## Supported Log Formats

- JSON (one object per line)
- Syslog
- CSV
- Plain text
- Windows Event XML

## Workflow

1. **Import Logs** - Upload or paste log files
2. **Create Case** - Create an incident case for the investigation
3. **Link Logs** - Select and link relevant logs to the case
4. **AI Analysis** - Run AI analysis on the case logs to generate investigation report
5. **Export** - Export findings to CSV

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 3000 | Server port |
| `AUTH_USER` | admin | Authentication username |
| `AUTH_PASS` | admin | Authentication password |
| `VT_API_KEY` | - | VirusTotal API key |
| `DB_PATH` | ./ir-logs.db | Path to SQLite database |

## Tech Stack

- Backend: Node.js + Express
- Database: SQLite (sql.js)
- Frontend: Vanilla HTML/CSS/JS
- AI: Ollama (local LLM)

## License

MIT
