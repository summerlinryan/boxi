# boxi 🎯

**Human-in-the-loop CTF/pentest CLI for authorized security testing**

Boxi is a modular penetration testing tool that combines automated reconnaissance and exploitation with human oversight. Designed for CTF competitions and authorized penetration testing, it provides an intelligent pipeline that can be paused, guided, and resumed by the operator.

## ⚡ Quick Start

```bash
# Install boxi
pip install boxi

# Run against a target
boxi 10.10.10.10

# Interactive mode with manual control
boxi 10.10.10.10 --interactive

# Dry run to see planned actions
boxi 10.10.10.10 --dry-run

# Generate report
boxi report 10.10.10.10
```

## 🎯 Features

### Automated Pipeline

- **Port scanning** with nmap integration
- **Service enumeration** (FTP, SMB, WinRM)
- **File discovery and download** from accessible shares
- **OCR credential extraction** from documents
- **Password hash cracking** with hashcat/john
- **Credential spraying** across discovered services

### Human-in-the-Loop

- **Pause/resume** pipeline at any time
- **Inject credentials** discovered manually
- **Add hints** to guide stage selection
- **Ignore patterns** to skip false positives
- **Interactive console** for real-time control

### Intelligence

- **Event-driven architecture** with automatic stage coordination
- **Artifact correlation** (files → creds → access → foothold)
- **Idempotent execution** avoids repeating completed work
- **Rule-based stage scheduling** with dependency tracking

## 📋 Requirements

### Core Dependencies

- Python 3.10+
- Rich (console output)
- Typer (CLI interface)
- Pydantic v2 (data models)

### External Tools (Optional)

- `nmap` - Port scanning and service detection
- `smbclient` or `smbmap` - SMB enumeration
- `evil-winrm` - WinRM access testing
- `hashcat` or `john` - Password hash cracking
- `tesseract` - OCR text extraction
- `pdftotext` - PDF text extraction

## 🚀 Installation

### From PyPI

```bash
pip install boxi
```

### From Source

```bash
git clone https://github.com/example/boxi.git
cd boxi
poetry install
```

### Development Setup

```bash
git clone https://github.com/example/boxi.git
cd boxi
poetry install --with dev
poetry run pre-commit install
```

## 📖 Usage

### Basic Scan

```bash
# Automated scan with default settings
boxi 192.168.1.100

# Verbose output
boxi 192.168.1.100 -v

# Quiet mode
boxi 192.168.1.100 -q
```

### Interactive Mode

```bash
boxi 192.168.1.100 --interactive
```

Interactive commands:

- `start` - Start/resume pipeline
- `pause` - Pause execution
- `status` - Show current progress
- `inject creds username:password` - Add credentials
- `inject hint "check /backup directory"` - Add guidance
- `plan` - Show execution plan
- `report` - Generate report
- `quit` - Exit

### Injection During Run

```bash
# Inject credentials found manually
boxi inject --creds admin:Password123

# Add ignore pattern
boxi inject --ignore "*.tmp"

# Add hint for orchestrator
boxi inject --hint "focus on SMB shares"
```

### Reporting

```bash
# Markdown report
boxi report 10.10.10.10

# JSON report
boxi report 10.10.10.10 --format json

# Save to file
boxi report 10.10.10.10 -o report.md
```

### Tool Status

```bash
# Check external tool availability
boxi tools
```

## 🏗️ Architecture

### Core Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CLI Interface │    │   Orchestrator  │    │   Event Bus     │
│   (Typer/Rich)  │◄──►│   (Scheduler)   │◄──►│   (Pub/Sub)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Run Context   │    │     Stages      │    │    Adapters     │
│   (State)       │◄──►│   (Pipeline)    │◄──►│  (External)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Pipeline Stages

1. **port_scan** - Discover open ports and services
2. **ftp_enum** - Test FTP anonymous access, download files
3. **ocr_creds** - Extract credentials from documents
4. **smb_spray** - Test credentials against SMB
5. **smb_loot** - Download files from accessible shares
6. **sqlite_parse** - Extract data from SQLite databases
7. **hash_crack** - Crack discovered password hashes
8. **winrm_spray** - Test credentials against WinRM
9. **winrm_foothold** - Establish remote access

### Artifact Types

- **Target** - Host information and OS detection
- **Service** - Open ports and service banners
- **Credential** - Username/password pairs with confidence scores
- **FileArtifact** - Downloaded files with metadata
- **HashArtifact** - Password hashes for cracking
- **Flag** - CTF flags and target objectives

## ⚙️ Configuration

### Environment Variables

```bash
# Workspace directory
export BOXI_WORKSPACE_ROOT=~/.boxi

# Tool paths (auto-discovered if not set)
export BOXI_TOOL_PATHS__NMAP=/usr/bin/nmap
export BOXI_TOOL_PATHS__HASHCAT=/usr/bin/hashcat

# Timeouts
export BOXI_NMAP_TIMEOUT=300
export BOXI_CRACK_TIMEOUT=600

# Safety settings
export BOXI_SAFE_MODE=true
export BOXI_REQUIRE_CONFIRMATION=true
```

### Config File

Create `.env` in project directory:

```ini
BOXI_WORKSPACE_ROOT=/opt/boxi
BOXI_DEFAULT_TIMEOUT=60
BOXI_SAFE_MODE=false
BOXI_LOG_LEVEL=DEBUG
```

## 🔒 Safety & Ethics

### Safe Mode

Boxi defaults to "safe mode" which:

- Performs only read-only operations
- Requires explicit flags for potentially invasive actions
- Respects timeout limits to avoid infinite loops
- Logs all actions for audit trails

### Authorization Required

⚠️ **IMPORTANT**: Only use boxi against systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal.

### Recommended Use Cases

- ✅ CTF competitions (Hack The Box, TryHackMe, etc.)
- ✅ Authorized penetration testing with proper scope
- ✅ Security research in controlled environments
- ✅ Educational purposes in lab environments

## 🧪 Testing

### Run Tests

```bash
# All tests
poetry run pytest

# With coverage
poetry run pytest --cov=boxi

# Specific test file
poetry run pytest tests/test_orchestrator.py

# Verbose output
poetry run pytest -v
```

### Test Categories

- **Unit tests** - Individual component testing
- **Integration tests** - Component interaction testing
- **Mock tests** - External tool simulation
- **Fixture tests** - Captured output parsing

## 🤝 Contributing

### Development Workflow

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Run quality checks
5. Submit pull request

### Quality Checks

```bash
# Type checking
poetry run mypy src/boxi

# Linting and formatting
poetry run ruff check src/ tests/
poetry run ruff format src/ tests/

# Tests
poetry run pytest
```

### Code Style

- Type hints required for all functions
- Pydantic models for data structures
- Rich for console output
- Comprehensive error handling
- Detailed logging

## 📚 Examples

### Demo Scenario

This example demonstrates the complete pipeline against a fictional target:

```bash
# Start scan
boxi 10.10.10.10 --interactive

# Pipeline discovers:
# 1. FTP service with anonymous access
# 2. Downloads PDF with embedded credentials
# 3. OCR extracts username:password
# 4. SMB spray finds valid access
# 5. Downloads SQLite database from share
# 6. Extracts MD5 hashes from users table
# 7. Cracks hashes with hashcat
# 8. WinRM spray with new credentials succeeds
# 9. Establishes foothold and captures flag

# Manual intervention example:
boxi> inject creds backup:backup123
boxi> inject hint "check backup share for databases"
boxi> status
boxi> report
```

### Custom Wordlists

```bash
# Configure custom wordlist
export BOXI_WORDLIST_PATHS="/opt/wordlists/rockyou.txt,/opt/wordlists/custom.txt"

# Run with specific timeout
boxi 10.10.10.10 --max-iterations 50
```

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🔗 Links

- **Documentation**: Coming soon
- **Issues**: [GitHub Issues](https://github.com/example/boxi/issues)
- **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **Security**: [SECURITY.md](SECURITY.md)

## 🙏 Acknowledgments

- Inspired by tools like AutoRecon, nmapAutomator, and LinPEAS
- Built on the shoulders of nmap, hashcat, impacket, and other security tools
- Thanks to the CTF and InfoSec communities for feedback and testing

---

**⚠️ Use Responsibly**: This tool is for authorized security testing only. Always ensure you have proper permission before testing any systems.
