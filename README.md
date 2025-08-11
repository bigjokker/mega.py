# mega_size.py

Inspect sizes and structure of **public MEGA** links (folders or files) from the command line.  
Print a readable tree, export to JSON/CSV, and estimate download times — all without requiring a MEGA account.

> ✅ Works with both old (`#!`, `#F!`) and new (`/file/…#…`, `/folder/…#…`) public link formats.

---

## Features

- **Total size** for public folders or single files (repeated again at the bottom for long outputs).
- **Name decryption** when the URL contains a key and `pycryptodome` is installed; otherwise shows handles as “(encrypted)”.
- **Filters** you can combine:
  - `--ext .mp4,.mkv`
  - `--min-size 500MB`
  - `--since 2024-01-01`
  - `--until 2025-08-01`
- **Breakdown by file type** (video/audio/image/archive/docs/other) with counts, total sizes, and % of total.
- **Sorting** of the printed tree and flat list: `--sort size|name|date` + `--desc`.
- **Only-folders view**: `-of` (alias: `-OF`, `--only-folders`) prints **folders only**.
- **Output modes**:
  - `--bytes-only` → just the total number (for piping).
  - `--flat` → one line per file: `<size_bytes>\t<path>`.
  - `--export json,csv` → JSON tree and/or CSV file list:
    - CSV columns: `path, type, size_bytes, size_human, ts_iso, handle`.
- **Download-time estimate**: `--mbps 100` prints ETA for the total (or filtered total) **and per top-level folder**.
- **Stable exit codes** for CI/scripting:
  - `0` OK
  - `2` bad URL / bad input
  - `3` API error (non-rate-limit)
  - `4` rate limited after retries

---

## Installation

```bash
# Python 3.8+ recommended
pip install requests
# Optional (enables decrypted names when a key is present)
pip install pycryptodome
```

## Usage

```bash
python mega_size.py <MEGA_PUBLIC_URL> [options]
```

### Common examples

Total size + tree:
```bash
python mega_size.py "https://mega.nz/folder/AAAAA#BBBBB"
```

Summary only (skip the tree):
```bash
python mega_size.py "https://mega.nz/folder/AAAAA#BBBBB" --summary
```

Only folders:
```bash
python mega_size.py "https://mega.nz/folder/AAAAA#BBBBB" -of
```

Filters (combine freely):
```bash
python mega_size.py "https://mega.nz/folder/AAAAA#BBBBB" \
  --ext .mp4,.mkv --min-size 500MB \
  --since 2024-01-01 --until 2025-08-01
```

Sort by size descending:
```bash
python mega_size.py "https://mega.nz/folder/AAAAA#BBBBB" --sort size --desc
```

Flat list for scripting:
```bash
python mega_size.py "https://mega.nz/folder/AAAAA#BBBBB" --flat
# prints: <size_bytes>\t<path> per file
```

Bytes only (for piping):
```bash
python mega_size.py "https://mega.nz/folder/AAAAA#BBBBB" --bytes-only
```

Export JSON and CSV:
```bash
python mega_size.py "https://mega.nz/folder/AAAAA#BBBBB" --export json,csv
# -> mega_structure.json, mega_structure.csv
```

Download-time estimate (overall + per top-level folder):
```bash
python mega_size.py "https://mega.nz/folder/AAAAA#BBBBB" --mbps 100
```

Verbose logging:
```bash
python mega_size.py "https://mega.nz/folder/AAAAA#BBBBB" --verbose
```

---

## Options

| Option | Description |
|---|---|
| `--summary` | Print only the total size (skip tree). |
| `-of`, `-OF`, `--only-folders` | Show **only folders** in the printed tree (no files). |
| `--ext` | Comma-separated extensions to include (e.g., `.mp4,.mkv`). |
| `--min-size` | Minimum file size (e.g., `500MB`, `2GB`, `1500` for bytes). |
| `--since`, `--until` | Date bounds (`YYYY-MM-DD`). Uses local time. |
| `--sort` | `size`, `name`, or `date` (folders sort by rollup size / newest descendant time). |
| `--desc` | Sort descending. |
| `--flat` | Additionally print a flat list: `<size_bytes>\t<path>`. Suppressed when `-of` is used. |
| `--bytes-only` | Print just the total number of bytes and exit. |
| `--export` | `json`, `csv`, or `json,csv`. CSV lists files only with `path,type,size_bytes,size_human,ts_iso,handle`. |
| `--mbps` | Estimate download time at the given Mbps (overall and per top-level folder). |
| `--verbose` | INFO-level logs (helpful for troubleshooting). |

> **Note:** Filters affect what is printed/exported and what the breakdown/ETA considers. The top “Total Folder Size” header always shows the *actual* total; the ETA notes whether it’s for the “filtered total” or full total.

---

## Decryption & names

- If the public URL includes the decryption **key**, and `pycryptodome` is installed, the script will decrypt and display node names.
- Without a key (or without `pycryptodome`), names appear as MEGA handles with “(encrypted)”. Size calculations still work.

---

## Output files

- `mega_structure.json` — hierarchical tree of the printed view (filtered scope).
- `mega_structure.csv` — flat file list with:  
  `path, type, size_bytes, size_human, ts_iso, handle`

Timestamps in the console are printed in **local time**; `ts_iso` in CSV is ISO-8601 (local).

---

## Exit codes

- `0` — success  
- `2` — invalid URL or argument error  
- `3` — MEGA API error (non-rate-limit) or request failed after retries  
- `4` — rate limited by API after retries (`-4`/`-6`)

Your CI can key off these codes.

---

## Troubleshooting

- **“Warning: No decryption key found in URL”** — expected for keyless links; names won’t decrypt.
- **Rate limited** — the script retries with backoff; if still limited, it exits with code `4`.
- **Windows console** — no special setup required.
- **Large folders** — use `--summary`, `-of`, `--flat`, and/or filters to reduce output volume.

---

## License

MIT LICENSE

---

