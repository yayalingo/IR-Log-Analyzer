# IR Log Analyzer - Specification

## Project Overview
- **Name**: IR Log Analyzer
- **Type**: Web Application (Local)
- **Core Functionality**: Incident Response log ingestion, timeline visualization, and threat intelligence enrichment
- **Target Users**: Cybersecurity incident responders

## Tech Stack
- Backend: Node.js + Express
- Database: SQLite (better-sqlite3)
- Frontend: Vanilla HTML/CSS/JS
- APIs: VirusTotal v3

## Features

### 1. Log Ingestion
- Upload log files (JSON, Syslog, CSV, plain text, Windows Event XML)
- Paste log content directly
- Parse multiple formats automatically
- Store parsed logs in SQLite

### 2. Timeline View
- Auto-extract timestamps from various formats (ISO8601, Unix, Syslog, custom)
- Display logs in chronological order
- Filter by:
  - Time range (start/end)
  - Source/hostname
  - Log level/severity
  - Keyword search
- Color-coded severity levels

### 3. Threat Intelligence Enrichment
- Extract IPs, domains, URLs, file hashes from logs
- Enrich via VirusTotal API
- Display enrichment results inline with logs
- Cache results to avoid redundant lookups
- Manual trigger for enrichment

### 4. UI/UX
- Dark mode interface
- Responsive design
- Real-time search/filter
- Expandable log entries
- Loading states for API calls

## Database Schema

### logs
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| timestamp | DATETIME | Extracted timestamp |
| source | TEXT | Log source/hostname |
| level | TEXT | Severity level |
| message | TEXT | Raw log message |
| raw | TEXT | Full raw log entry |
| created_at | DATETIME | Import time |

### enrichments
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| indicator | TEXT | IP/domain/hash |
| type | TEXT | indicator type |
| vt_result | TEXT | VirusTotal JSON |
| created_at | DATETIME | Query time |

## API Endpoints
- POST /api/logs/import - Import logs
- GET /api/logs - Query logs with filters
- GET /api/logs/:id - Get single log
- POST /api/enrich - Enrich indicator
- GET /api/enrich/:indicator - Get cached enrichment

## Acceptance Criteria
1. Can upload JSON, Syslog, CSV, plain text files
2. Timestamps auto-extracted and displayed in timeline
3. Filters work (time range, source, level, search)
4. VirusTotal enrichment works with provided API key
5. Dark mode UI loads correctly
6. Local SQLite database persists data
