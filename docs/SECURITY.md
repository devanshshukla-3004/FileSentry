# FileSentry Security Notes

## Intended use
FileSentry is a learning project for defensive file integrity monitoring. Use it only on files and systems you own or are explicitly authorized to monitor.

## Baseline trust
A baseline represents a known-good state only if its source was trusted when created. Store the baseline outside the monitored directory where practical, restrict write access, and consider recording its own digest in a separate trusted system.

## Interpretation
A mismatch means the file's content differs from the baseline. It does not establish maliciousness, attacker identity, or intent. Investigate changes in context.

## Current limitations
- Scans are point-in-time, not continuous.
- Symbolic links are skipped.
- File content hashes are checked; permissions, ownership, and timestamps are not baseline comparison criteria.
- A file may change while being read.
- Excluded paths are not checked.
- Baseline authenticity is not cryptographically signed by this tool.
