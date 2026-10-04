# FileSentry 🔐
### File Integrity Monitoring & Tamper Detection

FileSentry is a Python command-line tool that records SHA-256 hashes for files in a directory and compares later scans against a saved baseline. It reports files that are **modified, deleted, or newly discovered**.

> A file change is an indicator to investigate, not proof of malicious activity. Legitimate software updates and normal administration can change files too.

## Features
- SHA-256 hashing with chunked reads for large files
- JSON baseline and optional JSON scan report
- Detection of modified, deleted, and new files
- Directory-name and relative-path exclusions
- Symlinks skipped to reduce traversal surprises
- Clear CLI output and meaningful exit codes
- Automated unit tests using temporary test directories
- Standard-library-only implementation

## Requirements
- Python 3.10 or later
- No third-party packages required

## Quick start

Clone the repository, then run these commands from its root.

### Windows PowerShell

#### 1. Create sample files
```powershell
New-Item -ItemType Directory -Force .\testdata
Set-Content .\testdata\settings.txt "safe configuration"
```

#### 2. Create a baseline
```powershell
python filesentry.py baseline --path .\testdata --baseline .\baseline.json
```

#### 3. Scan for changes
```powershell
python filesentry.py scan --path .\testdata --baseline .\baseline.json --report .\reports\scan.json
```

#### 4. Test detection
```powershell
Set-Content .\testdata\settings.txt "changed configuration"
python filesentry.py scan --path .\testdata --baseline .\baseline.json --report .\reports\after-change.json
```

### Linux / Kali Linux / macOS

#### 1. Create sample files
```bash
mkdir -p ./testdata
echo "safe configuration" > ./testdata/settings.txt
```

#### 2. Create a baseline
```bash
python3 filesentry.py baseline --path ./testdata --baseline ./baseline.json
```

#### 3. Scan for changes
```bash
python3 filesentry.py scan --path ./testdata --baseline ./baseline.json --report ./reports/scan.json
```

#### 4. Test detection
```bash
echo "changed configuration" > ./testdata/settings.txt
python3 filesentry.py scan --path ./testdata --baseline ./baseline.json --report ./reports/after-change.json
```

The changed file should appear under `MODIFIED`. A scan exits with:
- `0`: no changes or scan errors found
- `1`: changes or scan errors found
- `2`: invalid input or operational error

### Exclusions

Repeat `--exclude` to exclude a directory name or relative path.

**Windows PowerShell**
```powershell
python filesentry.py baseline --path .\testdata --exclude .git --exclude cache
```

**Linux / Kali Linux / macOS**
```bash
python3 filesentry.py baseline --path ./testdata --exclude .git --exclude cache
```

## Run tests

**Windows PowerShell**
```powershell
python -m unittest discover -s tests -v
```

**Linux / Kali Linux / macOS**
```bash
python3 -m unittest discover -s tests -v
```

## Example report shape
```json
{
  "tool": "FileSentry",
  "files_scanned": 2,
  "unchanged_count": 1,
  "modified": [{"path": "settings.txt", "baseline_sha256": "…", "current_sha256": "…"}],
  "deleted": [],
  "new": [],
  "scan_errors": []
}
```
Hash values above are illustrative, not output from a real scan.

## Security considerations
- **Protect the baseline.** If an attacker can alter both the monitored files and baseline, they may conceal changes. Keep the baseline in a separately protected location and restrict write access.
- **Baseline creation is a trust decision.** Create it from a known-good state.
- **Avoid scanning sensitive locations without authorization.** Test on a directory you own or are permitted to monitor.
- **No real-time monitoring.** FileSentry performs point-in-time scans; it does not watch filesystem events continuously.
- **No attribution.** It cannot identify who changed a file or prove intent.
- **Metadata limits.** Hashes detect content changes, not every ownership, permission, or timestamp change.
- **Race conditions.** Files can change while a scan is in progress.
- **Exclusions matter.** Excluding paths means changes there are not monitored.

## Project status
Initial implementation and tests are published in this repository. Run the test suite and the quick-start experiments in your own environment before relying on the tool. Record verified results and any platform-specific limitations.

## Learning outcomes
Python filesystem operations · SHA-256 hashing · host-based defensive security · baseline integrity · JSON reporting · unit testing · secure operational documentation.

## License
MIT. See [LICENSE](LICENSE).
