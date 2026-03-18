# IR Log Analyzer

Incident Response Log Analysis Tool with Timeline Visualization and Threat Intelligence Enrichment.

## Features

- **Log Import**: Upload files (JSON, Syslog, CSV, plain text, XML) or paste logs directly
- **Timeline View**: Chronological log display with color-coded severity levels, resizable columns
- **Filtering**: Filter by time range, source, log level, and keyword search
- **Field Extraction**: Configurable extraction of IPs, hostnames, URLs, and file hashes
- **CSV Export**: Export filtered logs to CSV format
- **Threat Intelligence**: Extract and enrich IPs, domains, URLs, and file hashes with VirusTotal
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
- Username: `sanya`
- Password: `sanya`

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

All API endpoints (except `/api/login` and `/api/auth-check`) require Basic Authentication.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/login` | POST | Authenticate and get token |
| `/api/auth-check` | GET | Check authentication status |
| `/api/logs/import` | POST | Import logs |
| `/api/logs` | GET | Query logs with filters |
| `/api/logs/:id` | GET | Get log details |
| `/api/enrich` | POST | Enrich indicator |
| `/api/stats` | GET | Get statistics |
| `/api/logs` | DELETE | Clear all logs |

### Authentication

Use Basic Authentication header:
```bash
curl -u sanya:sanya http://localhost:3000/api/logs
```

## Tech Stack

- Backend: Node.js + Express
- Database: SQLite (sql.js)
- Frontend: Vanilla HTML/CSS/JS

## License

MIT
