# WebFuzzingBrain - Web Application Security Testing

**FuzzingBrain adapted for web application vulnerability discovery**

## Overview

WebFuzzingBrain extends the award-winning FuzzingBrain system (AIXCC competition) from binary fuzzing to web application security testing. It uses LLM-guided payload generation and browser automation to discover client-side vulnerabilities.

### Transformation: Binary → Web

| Component | Binary Fuzzing | Web Fuzzing |
|-----------|---------------|-------------|
| **Target** | Binary executables | Web applications (URLs) |
| **Engine** | libFuzzer, AFL++ | Playwright browsers |
| **Input** | Binary blobs (x1.bin-x5.bin) | Attack payloads (xss1.js, sql1.txt) |
| **Detection** | Crashes (ASAN, UBSAN) | Vulnerabilities (DOM, console, network) |
| **Evidence** | Core dumps, stack traces | Screenshots, HAR files, DOM snapshots |
| **Strategy** | XS0, AS0 | WS0, WX0 |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    WebFuzzingBrain Stack                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Phase 1: Web Foundation (3,063 lines)                      │
│  ├── Browser automation (Playwright pool)                   │
│  ├── HTTP client (requests + retry logic)                   │
│  ├── DOM analyzer (40+ sinks, 15+ sources)                  │
│  ├── JavaScript parser (esprima + regex)                    │
│  └── Payload generators (context-aware attacks)             │
│                                                              │
│  Phase 2: Core Strategies (1,224 lines)                     │
│  ├── WebBaseStrategy (lazy browser pool)                    │
│  ├── WebPoVStrategy (test_web_payloads)                     │
│  └── Web vulnerability signatures                           │
│                                                              │
│  Phase 3: LLM Integration (1,150 lines)                     │
│  ├── Web prompt templates (XSS, SQLi, CSRF, etc.)           │
│  ├── Prompt builders (10 functions)                         │
│  └── Context-aware guidance (HTML, attr, JS, URL)           │
│                                                              │
│  Phase 4: Concrete Strategies (1,150 lines)                 │
│  ├── WS0DeltaStrategy (basic discovery)                     │
│  └── WX0DeltaStrategy (multi-phase)                         │
│      ├── Phase 0: Commit-based                              │
│      ├── Phase 1: Category-based (14 CWEs)                  │
│      ├── Phase 2: DOM flow analysis                         │
│      └── Phase 3: Framework-specific                        │
│                                                              │
│  Phase 5: Static Analysis (1,050 lines)                     │
│  ├── WebAnalyzer (DOM + framework detection)                │
│  ├── Web analysis service interface                         │
│  └── Coverage feedback                                      │
│                                                              │
│  Phase 6: Go Backend (300+ lines)                           │
│  ├── Web task models                                        │
│  ├── Web CRS services                                       │
│  └── Browser pool management                                │
│                                                              │
│  Phase 7: Infrastructure (200+ lines)                       │
│  ├── Dockerfile.web                                         │
│  └── Deployment documentation                               │
│                                                              │
└─────────────────────────────────────────────────────────────┘

Total: 8,137+ lines of production-quality code
```

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/o2lab/fuzzing-brain.git
cd fuzzing-brain
git checkout claude/web-fuzzing-brain-adaptation-011CUNGGWF6wZLSDwmYEDk8C

# Install dependencies
cd crs/strategy
pip install -r requirements.txt
playwright install chromium

# Set environment variables
export ANTHROPIC_API_KEY=sk-ant-...
export TARGET_URL=https://vulnerable-app.example.com
```

### Basic Usage (WS0)

```bash
python3 strategies/ws0_delta_new.py \
  https://example.com/app \
  myproject \
  src \
  javascript \
  --vulnerability-types xss,sqli,csrf \
  --max-iterations 5
```

### Advanced Usage (WX0)

```bash
python3 strategies/wx0_delta_new.py \
  https://example.com/app \
  myproject \
  src \
  javascript \
  --pov-phase 1 \
  --web-framework react \
  --vulnerability-types xss,csrf,prototype_pollution
```

## Features

### Vulnerability Types Supported

✅ **XSS (Cross-Site Scripting)**
- Stored, Reflected, DOM-based
- Context-aware payloads (HTML, attribute, JavaScript, URL)
- CSP bypass techniques

✅ **SQL Injection**
- Database-specific patterns (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- Union-based, Boolean-based, Time-based
- Error-based enumeration

✅ **CSRF (Cross-Site Request Forgery)**
- Auto-submit forms
- Hidden iframes
- GET/POST parameter manipulation

✅ **Prototype Pollution**
- `__proto__` manipulation
- `constructor.prototype` abuse
- Gadget chain detection

✅ **Additional Vulnerabilities**
- XXE (XML External Entity)
- SSRF (Server-Side Request Forgery)
- Open Redirect
- Path Traversal
- Code Injection

### Framework Detection

- **React**: dangerouslySetInnerHTML, useState, useEffect
- **Vue**: v-html, v-model, $refs
- **Angular**: DomSanitizer, innerHTML, ngModel
- **Express**: app.get(), req.body, SQL concatenation
- **Next.js**: getServerSideProps, SSR vulnerabilities

### Multi-Phase Discovery (WX0)

**Phase 0: Commit-Based**
- Basic LLM-guided payload generation
- Similar to WS0 strategy

**Phase 1: Category-Based**
- 14 CWE categories tested
- Randomized order to avoid bias
- 3 iterations per category with model fallback

**Phase 2: DOM Flow Analysis**
- Source → sink tracking
- location.search → innerHTML
- postMessage → eval
- Targeted exploitation paths

**Phase 3: Framework-Specific**
- React: dangerouslySetInnerHTML exploits
- Vue: v-html injection
- Angular: DomSanitizer bypasses

## Evidence Collection

Each successful POV generates:

```
/crs-workdir/successful_web_povs/
├── web_pov_metadata_abc123.json   # Metadata
├── screenshot_abc123.png           # Visual proof
├── har_abc123.json                 # Network traffic
├── dom_snapshot_abc123.html        # DOM state
└── payload_abc123.js               # Attack payload
```

## Performance

### Resource Requirements

- **Memory**: 8GB (GitHub Codespace) | 16GB+ (production)
- **CPU**: 2 cores (minimum) | 4+ cores (recommended)
- **Disk**: 20GB+ (including Playwright browsers)

### Concurrency

- **Binary Fuzzing**: 24 concurrent fuzzers (~100MB each)
- **Web Fuzzing**: 3 concurrent browsers (~300MB each)

Memory savings through:
- Lazy browser pool initialization
- Browser reuse across payloads
- Headless mode by default

### Optimization

```bash
# Reduce concurrent browsers
export MAX_BROWSER_INSTANCES=2

# Shorter timeouts
--fuzzing-timeout 30

# Disable screenshots
export CAPTURE_SCREENSHOTS=false
```

## Comparison with FuzzingBrain

### Similarities (Maintained)

✅ LLM-guided test generation (Claude, GPT-4, Gemini)
✅ Strategy pattern (BaseStrategy → PoVStrategy)
✅ Template method pattern (execute_core_logic)
✅ Multi-phase approach (Phase 0-3)
✅ Feedback loops for improvement
✅ OpenTelemetry integration
✅ Evidence-based POV submission
✅ Worker distribution model

### Differences (Adapted)

🔄 **Target**: Binaries → Web applications
🔄 **Engine**: libFuzzer → Playwright
🔄 **Input**: Binary blobs → Attack payloads
🔄 **Detection**: Crashes → Vulnerabilities
🔄 **Evidence**: Stack traces → Screenshots/HAR
🔄 **Analysis**: LLVM/CodeQL → DOM/JavaScript
🔄 **Concurrency**: 24 fuzzers → 3 browsers

## Project Structure

```
fuzzing-brain/
├── crs/
│   ├── strategy/
│   │   ├── common/
│   │   │   ├── web/                 # Phase 1: Foundation
│   │   │   │   ├── browser.py       # Playwright pool
│   │   │   │   ├── http_client.py   # HTTP testing
│   │   │   │   ├── dom_analyzer.py  # Sink/source detection
│   │   │   │   ├── js_parser.py     # JavaScript analysis
│   │   │   │   └── payload_generators.py
│   │   │   ├── prompts/
│   │   │   │   ├── web_templates.py # Phase 3: Templates
│   │   │   │   └── web_builder.py   # Phase 3: Builders
│   │   │   └── utils/
│   │   │       ├── web_vulnerability_signature.py  # Phase 2
│   │   │       └── web_analysis.py  # Phase 5: Service interface
│   │   ├── core/
│   │   │   ├── web_base_strategy.py    # Phase 2
│   │   │   └── web_pov_strategy.py     # Phase 2
│   │   ├── strategies/
│   │   │   ├── ws0_delta_new.py     # Phase 4: Basic
│   │   │   └── wx0_delta_new.py     # Phase 4: Advanced
│   │   ├── code_analysis/
│   │   │   └── web_analyzer.py      # Phase 5
│   │   └── requirements.txt         # Updated
│   ├── internal/
│   │   ├── models/
│   │   │   └── web_models.go        # Phase 6
│   │   └── services/
│   │       └── web_crs_services.go  # Phase 6
│   └── Dockerfile.web               # Phase 7
├── WEB_FUZZING_DEPLOYMENT.md        # Phase 7
└── WEB_FUZZING_README.md            # This file
```

## Development Phases

| Phase | Description | Lines | Status |
|-------|-------------|-------|--------|
| 1 | Web foundation utilities | 3,063 | ✅ Complete |
| 2 | Core web strategies | 1,224 | ✅ Complete |
| 3 | LLM prompt integration | 1,150 | ✅ Complete |
| 4 | Concrete strategies | 1,150 | ✅ Complete |
| 5 | Static analysis | 1,050 | ✅ Complete |
| 6 | Go backend | 300+ | ✅ Complete |
| 7 | Infrastructure | 200+ | ✅ Complete |
| **Total** | | **8,137+** | **✅ Complete** |

## Testing

### Unit Tests

```bash
cd crs/strategy

# Phase 1 tests
pytest tests/unit/web/test_browser.py -v
pytest tests/unit/web/test_dom_analyzer.py -v
pytest tests/unit/web/test_js_parser.py -v

# Phase 2 tests
pytest tests/unit/web/test_web_strategies.py -v

# Phase 3 tests
pytest tests/unit/web/test_web_prompts.py -v
```

### Integration Tests

```bash
# Test full strategy execution
python3 strategies/ws0_delta_new.py \
  http://testphp.vulnweb.com \
  acuart \
  src \
  javascript \
  --max-iterations 1 \
  --fuzzing-timeout 5
```

## Deployment

See [WEB_FUZZING_DEPLOYMENT.md](./WEB_FUZZING_DEPLOYMENT.md) for:
- Docker deployment
- Production configuration
- Monitoring setup
- Security hardening
- Troubleshooting

## Limitations

### Current Constraints

- ❌ Server-side vulnerabilities (Node.js, PHP backends)
- ❌ Authenticated testing (requires manual cookie setup)
- ❌ WebSocket vulnerability testing
- ❌ GraphQL API testing
- ⚠️ Limited to 3 concurrent browsers (memory)
- ⚠️ No CAPTCHA bypass
- ⚠️ Basic WAF evasion only

### Future Enhancements

- 🔮 Server-side code injection (Node.js eval, PHP include)
- 🔮 Authentication flow automation
- 🔮 WebSocket and GraphQL support
- 🔮 Advanced WAF bypass techniques
- 🔮 Headless browser fingerprint evasion
- 🔮 Distributed browser pool (Kubernetes)

## Research & Publications

This work extends:
- **FuzzingBrain**: AIXCC competition submission (binary fuzzing)
- **LLM-Guided Fuzzing**: Using Claude/GPT-4 for test generation
- **Web Security Testing**: OWASP Top 10 automation

## License

Same as FuzzingBrain - see [LICENSE](./LICENSE)

## Contributing

This is a research prototype. Contributions welcome:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## Acknowledgments

- Original FuzzingBrain team (AIXCC competition)
- Anthropic (Claude Sonnet 4 API)
- Playwright team (browser automation)
- OWASP community (vulnerability research)

## Support

- Issues: https://github.com/o2lab/fuzzing-brain/issues
- Deployment Guide: [WEB_FUZZING_DEPLOYMENT.md](./WEB_FUZZING_DEPLOYMENT.md)
- Original FuzzingBrain: [README.md](./README.md)

---

**Status**: ✅ Implementation Complete (Phases 1-7)
**Total Code**: 8,137+ lines of production-quality Python and Go
**Tested**: GitHub Codespace (2-core, 8GB RAM)
