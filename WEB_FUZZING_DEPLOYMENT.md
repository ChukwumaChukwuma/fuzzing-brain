

# WebFuzzingBrain Deployment Guide

Comprehensive guide for deploying the WebFuzzingBrain adaptation of FuzzingBrain for web application security testing.

## Architecture Overview

WebFuzzingBrain extends FuzzingBrain's binary fuzzing architecture to support web application vulnerability discovery:

```
┌──────────────────────────────────────────────────────────────┐
│                      WebFuzzingBrain                          │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────┐      ┌──────────────┐     ┌──────────────┐ │
│  │ Go Backend  │◄────►│  Python CRS  │◄───►│   Browsers   │ │
│  │   (main)    │      │  Strategies  │     │  (Playwright)│ │
│  └─────────────┘      └──────────────┘     └──────────────┘ │
│         │                     │                     │         │
│         ▼                     ▼                     ▼         │
│  ┌─────────────┐      ┌──────────────┐     ┌──────────────┐ │
│  │   Worker    │      │ Web Analysis │     │ Screenshots/ │ │
│  │ Distribution│      │   Service    │     │  HAR Files   │ │
│  └─────────────┘      └──────────────┘     └──────────────┘ │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### Key Differences from Binary Fuzzing

| Feature | Binary Fuzzing | Web Fuzzing |
|---------|---------------|-------------|
| **Target** | Binary executables | Web applications |
| **Testing Tool** | libFuzzer/AFL++ | Playwright browsers |
| **Input** | Binary blobs (x.bin) | Attack payloads (xss.js, sql.txt) |
| **Detection** | Crash detection | Vulnerability detection |
| **Evidence** | Crash dumps | Screenshots, HAR files |
| **Resources** | CPU-intensive | Memory-intensive (browsers) |
| **Concurrency** | 24 fuzzers | 3 browsers (memory limited) |

## Prerequisites

### System Requirements

- **OS**: Linux (Ubuntu 20.04+ recommended)
- **Memory**: 8GB RAM (for GitHub Codespace) or 16GB+ (for production)
- **CPU**: 2+ cores (4+ cores recommended)
- **Disk**: 20GB+ free space

### Software Dependencies

```bash
# Python 3.10+
python3 --version

# Node.js 18+ (for Playwright)
node --version

# Go 1.21+ (for backend)
go version

# Docker & Docker Compose (for containerized deployment)
docker --version
docker-compose --version
```

## Installation

### 1. Clone Repository

```bash
git clone https://github.com/o2lab/fuzzing-brain.git
cd fuzzing-brain
git checkout claude/web-fuzzing-brain-adaptation-011CUNGGWF6wZLSDwmYEDk8C
```

### 2. Install Python Dependencies

```bash
cd crs/strategy
pip install -r requirements.txt

# Install Playwright browsers
playwright install chromium firefox webkit
```

### 3. Set Up Environment Variables

Create a `.env` file in the project root:

```bash
# CRS Configuration
CRS_KEY_ID=your_api_key_id
CRS_KEY_TOKEN=your_api_token
CRS_WORKDIR=/crs-workdir

# Worker Configuration
WORKER_NODES=3
WORKER_BASE_PORT=9081
MAX_BROWSER_INSTANCES=3

# Analysis Services
ANALYSIS_SERVICE_URL=http://localhost:7082
WEB_ANALYSIS_SERVICE_URL=http://localhost:7083

# LLM Configuration (choose one)
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
GOOGLE_API_KEY=...

# Web Fuzzing Configuration
BROWSER_TYPE=chromium
HEADLESS=true
CAPTURE_SCREENSHOTS=true
BROWSER_TIMEOUT=30

# Submission Endpoint (optional)
SUBMISSION_ENDPOINT=http://localhost:7081
TASK_ID=web-task-001
```

### 4. Build Go Backend

```bash
cd crs
go build -o bin/crs-server cmd/server/main.go
go build -o bin/crs-worker cmd/worker/main.go
```

## Running WebFuzzingBrain

### Option 1: Local Development

#### Start Analysis Services (Optional)

```bash
# Binary analysis service
cd static-analysis
go run cmd/server/main.go

# Web analysis service (if available)
# This is a placeholder - would be a separate microservice
# cd web-analysis
# go run cmd/server/main.go
```

#### Start CRS Server

```bash
cd crs
./bin/crs-server
# Listens on http://localhost:7080
```

#### Start CRS Workers

```bash
# Worker 1
./bin/crs-worker --port 9081 --index 0

# Worker 2
./bin/crs-worker --port 9082 --index 1

# Worker 3
./bin/crs-worker --port 9083 --index 2
```

#### Submit a Web Fuzzing Task

```bash
curl -X POST http://localhost:7080/v1/task/ \
  -u "$CRS_KEY_ID:$CRS_KEY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "message_id": "550e8400-e29b-41d4-a716-446655440000",
    "message_time": 1234567890,
    "tasks": [{
      "task_id": "web-task-001",
      "type": "web-advanced",
      "target_url": "https://vulnerable-app.example.com",
      "web_framework": "react",
      "vulnerability_types": ["xss", "csrf", "prototype_pollution"],
      "browser_type": "chromium",
      "headless": true,
      "pov_phase": 0,
      "focus": "src",
      "project_name": "vulnerable-app"
    }]
  }'
```

### Option 2: Docker Deployment

#### Build Docker Image

```bash
cd crs
docker build -f Dockerfile.web -t webfuzzingbrain:latest .
```

#### Run with Docker Compose

Create `docker-compose.web.yml`:

```yaml
version: '3.8'

services:
  web-crs-server:
    image: webfuzzingbrain:latest
    ports:
      - "7080:7080"
    environment:
      - CRS_KEY_ID=${CRS_KEY_ID}
      - CRS_KEY_TOKEN=${CRS_KEY_TOKEN}
      - WORKER_NODES=3
      - MAX_BROWSER_INSTANCES=3
      - ANALYSIS_SERVICE_URL=http://analysis:7082
      - WEB_ANALYSIS_SERVICE_URL=http://web-analysis:7083
    volumes:
      - ./crs-workdir:/crs-workdir
      - ./logs:/logs
    command: ["./bin/crs-server"]

  web-crs-worker-1:
    image: webfuzzingbrain:latest
    environment:
      - WORKER_INDEX=0
      - BROWSER_TYPE=chromium
      - HEADLESS=true
    volumes:
      - ./crs-workdir:/crs-workdir
    command: ["./bin/crs-worker", "--port", "9081", "--index", "0"]

  web-crs-worker-2:
    image: webfuzzingbrain:latest
    environment:
      - WORKER_INDEX=1
      - BROWSER_TYPE=chromium
      - HEADLESS=true
    volumes:
      - ./crs-workdir:/crs-workdir
    command: ["./bin/crs-worker", "--port", "9082", "--index", "1"]

  web-crs-worker-3:
    image: webfuzzingbrain:latest
    environment:
      - WORKER_INDEX=2
      - BROWSER_TYPE=chromium
      - HEADLESS=true
    volumes:
      - ./crs-workdir:/crs-workdir
    command: ["./bin/crs-worker", "--port", "9083", "--index", "2"]

  # Optional: Static analysis services
  analysis:
    image: static-analysis:latest
    ports:
      - "7082:7082"

  web-analysis:
    image: web-analysis:latest
    ports:
      - "7083:7083"
```

Start services:

```bash
docker-compose -f docker-compose.web.yml up -d
```

## Usage

### Web Fuzzing Strategies

#### WS0 (Basic Web Vulnerability Discovery)

```bash
python3 crs/strategy/strategies/ws0_delta_new.py \
  https://example.com/app \
  myproject \
  src \
  javascript \
  --web-framework react \
  --vulnerability-types xss,sqli,csrf \
  --max-iterations 5 \
  --fuzzing-timeout 45 \
  --browser-type chromium \
  --headless true
```

#### WX0 (Advanced Multi-Phase Discovery)

```bash
python3 crs/strategy/strategies/wx0_delta_new.py \
  https://example.com/app \
  myproject \
  src \
  javascript \
  --web-framework vue \
  --vulnerability-types xss,sqli,csrf,prototype_pollution \
  --pov-phase 1 \
  --max-iterations 3 \
  --fuzzing-timeout 60 \
  --browser-type chromium
```

### POV Phases (WX0 Only)

- **Phase 0**: Basic commit-based (like WS0)
- **Phase 1**: Category-based (14 CWE categories)
- **Phase 2**: DOM flow analysis (source → sink)
- **Phase 3**: Framework-specific (React/Vue/Angular)

### Supported Vulnerability Types

- `xss` - Cross-Site Scripting
- `sqli` - SQL Injection
- `csrf` - Cross-Site Request Forgery
- `prototype_pollution` - JavaScript Prototype Pollution
- `xxe` - XML External Entity
- `ssrf` - Server-Side Request Forgery
- `open_redirect` - Open Redirect
- `path_traversal` - Path Traversal
- `code_injection` - Code Injection

### Supported Frameworks

- `react` - React.js
- `vue` - Vue.js
- `angular` - Angular
- `express` - Express.js
- `nextjs` - Next.js

## Monitoring

### Check Status

```bash
curl http://localhost:7080/status/
```

### View POV Statistics

```bash
curl -u "$CRS_KEY_ID:$CRS_KEY_TOKEN" \
  http://localhost:7080/v1/task/web-task-001/povs/
```

### View Logs

```bash
# Server logs
tail -f logs/crs-server.log

# Worker logs
tail -f logs/crs-worker-0.log
tail -f logs/crs-worker-1.log
tail -f logs/crs-worker-2.log

# Strategy logs
tail -f logs/ws0_delta.log
tail -f logs/wx0_delta.log
```

### View Evidence

Successful web POVs generate evidence packages:

```bash
ls -la /crs-workdir/successful_web_povs/
# - web_pov_metadata_<id>.json
# - screenshot_<id>.png
# - har_<id>.json
# - dom_snapshot_<id>.html
# - payload_<id>.js (or .txt, .html)
```

## Performance Tuning

### Memory Optimization

```bash
# Reduce concurrent browsers (default: 3)
export MAX_BROWSER_INSTANCES=2

# Reduce max iterations
--max-iterations 3

# Shorter timeouts
--fuzzing-timeout 30
```

### CPU Optimization

```bash
# Reduce worker nodes
export WORKER_NODES=2

# Use headless browsers (lighter)
export HEADLESS=true
```

### Network Optimization

```bash
# Disable screenshots for faster execution
export CAPTURE_SCREENSHOTS=false

# Use local analysis service
export WEB_ANALYSIS_SERVICE_URL=http://localhost:7083
```

## Troubleshooting

### Browser Installation Issues

```bash
# Reinstall Playwright browsers
playwright install --force chromium

# Check browser installation
playwright --version
```

### Memory Issues

```bash
# Check available memory
free -h

# Monitor browser memory usage
ps aux | grep chromium

# Reduce MAX_BROWSER_INSTANCES
export MAX_BROWSER_INSTANCES=1
```

### Connection Issues

```bash
# Check if target is accessible
curl -I https://example.com/app

# Test browser connection
python3 -c "from playwright.sync_api import sync_playwright; \
  with sync_playwright() as p: \
    browser = p.chromium.launch(); \
    page = browser.new_page(); \
    page.goto('https://example.com'); \
    print(page.title()); \
    browser.close()"
```

### LLM API Issues

```bash
# Verify API key
echo $ANTHROPIC_API_KEY

# Test API connection
python3 -c "from anthropic import Anthropic; \
  client = Anthropic(); \
  print(client.messages.create(model='claude-sonnet-4', max_tokens=10, messages=[{'role':'user','content':'Hi'}]))"
```

## Security Considerations

### Responsible Disclosure

- Only test applications you have permission to test
- Follow responsible disclosure practices
- Report vulnerabilities to the application owner first

### Network Isolation

```bash
# Run in isolated network
docker network create --internal web-fuzzing-net

# Use HTTP proxy for traffic control
export HTTP_PROXY=http://proxy:8080
export HTTPS_PROXY=http://proxy:8080
```

### Rate Limiting

```bash
# Add delays between requests
--max-iterations 3
--fuzzing-timeout 60

# Respect robots.txt
# (Not implemented yet - manual check)
```

## Advanced Configuration

### Custom Analysis Service

Implement the web analysis service API:

```
POST /v1/web_analysis
POST /v1/framework_analysis
POST /v1/dependency_analysis
POST /v1/call_graph
POST /v1/typescript_analysis
```

See `crs/strategy/common/utils/web_analysis.py` for interface details.

### Custom Strategies

Extend `WebPoVStrategy`:

```python
from core.web_pov_strategy import WebPoVStrategy

class MyCustomWebStrategy(WebPoVStrategy):
    def do_pov(self, initial_msg):
        # Custom implementation
        pass
```

### OpenTelemetry Integration

Enable distributed tracing:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
export OTEL_SERVICE_NAME=webfuzzingbrain
```

## Production Deployment

### Horizontal Scaling

```yaml
# Scale workers
docker-compose -f docker-compose.web.yml up -d --scale web-crs-worker=10
```

### Load Balancing

```nginx
# nginx configuration
upstream web_crs_workers {
    server worker1:9081;
    server worker2:9082;
    server worker3:9083;
}
```

### High Availability

- Deploy multiple CRS servers behind load balancer
- Use shared storage (NFS, S3) for POV artifacts
- Redis for distributed task queue
- PostgreSQL for task state persistence

## References

- [FuzzingBrain Original](https://github.com/o2lab/fuzzing-brain)
- [Playwright Documentation](https://playwright.dev/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)

## Support

For issues and questions:
- GitHub Issues: https://github.com/o2lab/fuzzing-brain/issues
- Documentation: See `crs/strategy/README.md`

---

**Note**: This is an adaptation of FuzzingBrain from binary fuzzing to web application security testing. The core Python implementation is complete (Phases 1-5). Full deployment requires completing Go backend integration (Phase 6) and Docker infrastructure (Phase 7).
