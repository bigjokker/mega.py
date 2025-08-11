import json
import re
import sys
import argparse
import requests
import time
import logging
import base64
from datetime import datetime, timedelta
from collections import defaultdict

# ----- Optional crypto (unchanged) -----
HAS_CRYPTO = False
AES = None
try:
    from Crypto.Cipher import AES as _AES
    AES = _AES
    HAS_CRYPTO = True
except ImportError:
    print("Warning: pycryptodome not installed—file/folder names will show as encrypted handles. Install via 'pip install pycryptodome' for full functionality.")

# ----- Logging (unchanged default) -----
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')


# =========================
# Helpers: base64 / AES
# =========================
def base64urldecode(data):
    """Decode base64url-encoded data."""
    data += '=' * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data)

def a32_to_str(a):
    return b''.join((x.to_bytes(4, 'big') for x in a))

def str_to_a32(b):
    if len(b) % 4:
        b += b'\0' * (4 - len(b) % 4)
    return [int.from_bytes(b[i:i+4], 'big') for i in range(0, len(b), 4)]

def aes_cbc_decrypt(data, key, iv=b'\0' * 16):
    """Decrypt data using AES-CBC."""
    if not HAS_CRYPTO:
        return None
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher.decrypt(data)

def aes_ecb_decrypt(data, key):
    """Decrypt data using AES-ECB."""
    if not HAS_CRYPTO:
        return None
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data)

def decrypt_key(cipher_a32, key_a32):
    if not HAS_CRYPTO:
        return None
    decrypted = []
    key_bytes = a32_to_str(key_a32)
    for i in range(0, len(cipher_a32), 4):
        block = a32_to_str(cipher_a32[i:i+4])
        dec_block = aes_ecb_decrypt(block, key_bytes)
        if dec_block is None:
            return None
        decrypted += str_to_a32(dec_block)
    return tuple(decrypted)

def decrypt_attr(attr_bytes, k):
    if not HAS_CRYPTO:
        return None
    key_bytes = a32_to_str(k)
    dec_attr = aes_cbc_decrypt(attr_bytes, key_bytes)
    if dec_attr is None:
        return None
    dec_attr = dec_attr.rstrip(b'\0')  # zero padding
    if dec_attr.startswith(b'MEGA'):
        try:
            attr_json = json.loads(dec_attr[4:].decode('utf-8'))
            return attr_json.get('n', 'Unknown')
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
    return None


# =========================
# New: parsing & display utils
# =========================
def parse_size(s):
    """
    Parse human size like '500MB', '1.5 GB', '1024', case-insensitive.
    Uses binary (1024) units.
    """
    if s is None:
        return None
    txt = s.strip().replace(" ", "").lower()
    m = re.match(r'^(\d+(\.\d+)?)([kmgtp]?b?)$', txt)
    if not m:
        raise ValueError(f"Invalid size: {s}")
    val = float(m.group(1))
    unit = m.group(3)
    mult = 1
    if unit in ('k', 'kb'):
        mult = 1024
    elif unit in ('m', 'mb'):
        mult = 1024**2
    elif unit in ('g', 'gb'):
        mult = 1024**3
    elif unit in ('t', 'tb'):
        mult = 1024**4
    elif unit in ('p', 'pb'):
        mult = 1024**5
    return int(val * mult)

def parse_date_ymd_start(s):
    """Return unix ts for YYYY-MM-DD at 00:00:00 LOCAL."""
    if s is None:
        return None
    try:
        dt = datetime.fromisoformat(s)
        return int(dt.timestamp())
    except Exception:
        raise ValueError(f"Invalid date (use YYYY-MM-DD): {s}")

def parse_date_ymd_end_inclusive(s):
    """Return unix ts for YYYY-MM-DD 23:59:59 LOCAL (end of the day, inclusive)."""
    if s is None:
        return None
    try:
        dt = datetime.fromisoformat(s)
        end = dt + timedelta(days=1) - timedelta(seconds=1)
        return int(end.timestamp())
    except Exception:
        raise ValueError(f"Invalid date (use YYYY-MM-DD): {s}")

def format_size(size_bytes):
    """Convert bytes to human-readable format (e.g., KB, MB, GB)."""
    for unit in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} PB"

def format_duration(seconds):
    """Simple human-ish ETA string."""
    secs = int(round(seconds))
    if secs < 60:
        return f"{secs}s"
    mins, s = divmod(secs, 60)
    if mins < 60:
        return f"{mins}m {s}s"
    hrs, m = divmod(mins, 60)
    if hrs < 24:
        return f"{hrs}h {m}m"
    days, h = divmod(hrs, 24)
    return f"{days}d {h}h"

def download_time_seconds(total_bytes, mbps):
    if not mbps or mbps <= 0:
        return None
    return (total_bytes * 8.0) / (mbps * 1_000_000.0)

def ext_of(name):
    i = name.rfind('.')
    if i == -1:
        return ''
    return name[i:].lower()

def categorize_ext(ext):
    video = {'.mp4', '.mkv', '.avi', '.mov', '.wmv', '.flv', '.webm', '.m4v'}
    audio = {'.mp3', '.flac', '.aac', '.m4a', '.wav', '.ogg', '.wma', '.alac'}
    image = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp', '.heic'}
    archive = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.iso'}
    docs = {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.rtf', '.csv', '.md'}
    if ext in video:
        return 'video'
    if ext in audio:
        return 'audio'
    if ext in image:
        return 'image'
    if ext in archive:
        return 'archive'
    if ext in docs:
        return 'docs'
    return 'other'

def shorten_middle(text, max_len):
    """Middle-ellipsis if name is too long (for display only)."""
    if max_len is None or max_len <= 0:
        return text
    if len(text) <= max_len:
        return text
    keep_left = (max_len - 1) // 2
    keep_right = max_len - keep_left - 1
    return text[:keep_left] + "…" + text[-keep_right:]


# =========================
# Errors & exit codes
# =========================
class MegaAPIError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code

RATE_LIMIT_CODES = {-4, -6}  # Rate limit exceeded / Too many requests

MEGA_ERROR_CODES = {
    -1: "Internal error",
    -2: "Invalid argument",
    -3: "Request failed (retry)",
    -4: "Rate limit exceeded",
    -5: "Failed",
    -6: "Too many requests",
    -7: "Operation not allowed",
    -8: "Transfer limit reached",
    -9: "Not found",
    -10: "Circular linkage",
    -11: "Access denied",
    -12: "Already exists",
    -13: "Incomplete",
    -14: "Invalid key/Decryption error",
    -15: "Bad session ID",
    -16: "Quota exceeded",
    -17: "Resource temporarily unavailable",
    -18: "Request over quota",
    -19: "Connection reset by peer",
    -20: "Upload token expired",
    -21: "Invalid fingerprint",
    -22: "Invalid token",
    -23: "File too large",
    -24: "Bandwidth over quota",
}


# =========================
# Printing & export
# =========================
def print_file_summary(resp, master_key, total_size):
    print()
    dec_name = None
    if master_key and HAS_CRYPTO:
        try:
            master_key_a32 = str_to_a32(master_key)
            if len(master_key_a32) != 8:
                raise ValueError("File master key should be 8 a32 (32 bytes)")
            k = (
                master_key_a32[0] ^ master_key_a32[4],
                master_key_a32[1] ^ master_key_a32[5],
                master_key_a32[2] ^ master_key_a32[6],
                master_key_a32[3] ^ master_key_a32[7],
            )
            at_bytes = base64urldecode(resp['at'])
            dec_name = decrypt_attr(at_bytes, k)
        except Exception as e:
            logging.debug(f"File decryption error: {str(e)}")
    name = dec_name if dec_name else 'Encrypted file'
    print(f"File Name: {name}")
    print(f"Total File Size: {format_size(total_size)} ({total_size} bytes)")


def print_folder_summary(
    resp,
    master_key,
    total_size_all,
    *,
    summary_only=False,
    export_formats=None,
    only_folders=False,
    filters=None,
    sort_key='name',
    sort_desc=False,
    flat=False,
    mbps=None,
    name_max=80
):
    export_formats = export_formats or []  # list like ['json','csv']

    print()
    print(f"Total Folder Size: {format_size(total_size_all)} ({total_size_all} bytes)")
    print()

    if summary_only:
        return

    nodes = resp.get('f', [])
    if not nodes:
        print("Folder is empty.")
        return

    # Build node map
    node_map = {node['h']: node for node in nodes}
    for node in nodes:
        node['children'] = []
    for node in nodes:
        p = node.get('p')
        if p in node_map:
            node_map[p]['children'].append(node)

    # Decrypt display names
    master_key_a32 = str_to_a32(master_key) if master_key else None
    for node in nodes:
        dec_name = None
        if master_key and HAS_CRYPTO:
            try:
                if 'k' in node:
                    parts = node['k'].split(':', 1)
                    if len(parts) == 2:
                        _, enc_key = parts
                        k_bytes = base64urldecode(enc_key)
                        cipher_a32 = str_to_a32(k_bytes)
                        node_key_a32 = decrypt_key(cipher_a32, master_key_a32)
                        if node_key_a32:
                            if node['t'] == 0 and len(node_key_a32) == 8:
                                k = (
                                    node_key_a32[0] ^ node_key_a32[4],
                                    node_key_a32[1] ^ node_key_a32[5],
                                    node_key_a32[2] ^ node_key_a32[6],
                                    node_key_a32[3] ^ node_key_a32[7],
                                )
                            else:
                                k = node_key_a32
                            if 'a' in node:
                                a_bytes = base64urldecode(node['a'])
                                dec_name = decrypt_attr(a_bytes, k)
            except Exception as e:
                logging.debug(f"Decryption error for node {node['h']}: {str(e)}")
        node['dec_name'] = dec_name if dec_name else node['h'] + ' (encrypted)'

    # Roots (top-level)
    roots = [node for node in nodes if node.get('p') not in node_map]

    # Build full paths for files (and folders if needed)
    def build_path(n):
        path = []
        cur = n
        while cur:
            path.append(cur['dec_name'])
            cur = node_map.get(cur.get('p'))
        return "/".join(reversed(path))

    # Collect files with derived fields
    files = []
    for n in nodes:
        if n.get('t') == 0:  # file
            sz = n.get('s', 0)
            ts = n.get('ts')
            files.append({
                'handle': n['h'],
                'parent': n.get('p'),
                'name': n['dec_name'],
                'size': sz,
                'ts': ts,
                'path': None,  # fill later
                'node': n
            })

    # ---------- Filters ----------
    ext_set = None
    if filters and filters.get('ext'):
        ext_set = {e.lower() if e.startswith('.') else ('.' + e.lower())
                   for e in filters['ext']}

    min_size = parse_size(filters.get('min_size')) if filters and filters.get('min_size') else None
    since_ts = parse_date_ymd_start(filters.get('since')) if filters and filters.get('since') else None
    until_ts = parse_date_ymd_end_inclusive(filters.get('until')) if filters and filters.get('until') else None

    def file_passes(f):
        if ext_set is not None:
            e = ext_of(f['name'])
            if e not in ext_set:
                return False
        if (min_size is not None) and (f['size'] < min_size):
            return False
        if since_ts is not None:
            if f['ts'] is None or f['ts'] < since_ts:
                return False
        if until_ts is not None:
            if f['ts'] is None or f['ts'] > until_ts:
                return False
        return True

    filtered_files = []
    for f in files:
        if file_passes(f):
            f['path'] = build_path(f['node'])
            filtered_files.append(f)

    filters_active = (ext_set is not None) or (min_size is not None) or (since_ts is not None) or (until_ts is not None)
    if not filters_active:
        for f in files:
            f['path'] = build_path(f['node'])
        filtered_files = files

    # ---------- Rollups for folders (based on filtered files) ----------
    cum_size = defaultdict(int)
    max_ts = defaultdict(lambda: None)
    has_filtered = defaultdict(bool)

    for f in filtered_files:
        cur = node_map.get(f['parent'])
        while cur:
            cum_size[cur['h']] += f['size']
            if f['ts'] is not None:
                if max_ts[cur['h']] is None or f['ts'] > max_ts[cur['h']]:
                    max_ts[cur['h']] = f['ts']
            has_filtered[cur['h']] = True
            cur = node_map.get(cur.get('p'))
        has_filtered[f['handle']] = True  # mark file itself

    # ---------- Sorting ----------
    def child_sort_key(n):
        if sort_key == 'size':
            val = n.get('s', 0) if n['t'] == 0 else cum_size.get(n['h'], 0)
        elif sort_key == 'date':
            if n['t'] == 0:
                val = (n.get('ts') or -1)
            else:
                t = max_ts.get(n['h'])
                if t is None:
                    # fall back to folder's own ts if present
                    t = n.get('ts') or -1
                val = t
        else:
            val = (n.get('dec_name') or '').lower()
        return val

    def sort_children_rec(n):
        n['children'].sort(key=child_sort_key, reverse=sort_desc)
        for ch in n['children']:
            sort_children_rec(ch)

    for r in roots:
        sort_children_rec(r)

    # ---------- Decide inclusion (PRINT vs EXPORT) ----------
    def should_print_node_tree(n):
        if only_folders:
            # Only folders that have any filtered descendants
            return n['t'] == 1 and has_filtered.get(n['h'], False)
        # Otherwise: folders with filtered descendants OR filtered files themselves
        if n['t'] == 1:
            return has_filtered.get(n['h'], False)
        else:
            return any(f['handle'] == n['h'] for f in filtered_files)

    def should_include_export(n):
        # Ignore only_folders for exports (keep previous behavior)
        if n['t'] == 1:
            return has_filtered.get(n['h'], False)
        else:
            return any(f['handle'] == n['h'] for f in filtered_files)

    # ---------- Printed tree ----------
    print("Folder Structure:\n")

    def build_tree_and_print(n, depth=0):
        if not should_print_node_tree(n):
            return None

        indent = "  " * depth
        disp_name = shorten_middle(n['dec_name'], name_max)

        if n['t'] == 0:
            # FILE: in only_folders mode we never print files
            if not only_folders:
                size_str = f" - {format_size(n.get('s', 0))}"
                ts_str = ""
                if 'ts' in n and n['ts'] is not None:
                    try:
                        ts = datetime.fromtimestamp(n['ts'])
                        ts_str = f" [{ts.strftime('%Y-%m-%d %H:%M:%S')}]"
                    except Exception:
                        ts_str = " [Invalid timestamp]"
                print(f"{indent}- {disp_name} (File{size_str}{ts_str})")
            return True

        # FOLDER line (always printed if included)
        folder_sz = cum_size.get(n['h'], 0)
        ts_v = max_ts.get(n['h']) or n.get('ts')
        ts_str = f" [{datetime.fromtimestamp(ts_v).strftime('%Y-%m-%d %H:%M:%S')}]" if ts_v else ""
        print(f"{indent}- {disp_name} (Folder - {format_size(folder_sz)}{ts_str})")

        for ch in n['children']:
            build_tree_and_print(ch, depth + 1)
        return True

    for r in roots:
        build_tree_and_print(r)

    # ---------- Flat output ----------
    if flat and not only_folders:
        print("\nFlat listing (size_bytes\\tpath):")
        def flat_key(f):
            if sort_key == 'size':
                return f['size']
            elif sort_key == 'date':
                return f['ts'] or -1
            else:
                return f['path'].lower()
        filtered_files.sort(key=flat_key, reverse=sort_desc)
        for f in filtered_files:
            print(f"{f['size']}\t{f['path']}")

    # ---------- Breakdown ----------
    if filtered_files:
        total_filtered = sum(f['size'] for f in filtered_files)
        print("\nBreakdown by type " + ("(filtered subset)" if filters_active else "") + ":")
        bucket = defaultdict(lambda: {'count': 0, 'bytes': 0})
        for f in filtered_files:
            cat = categorize_ext(ext_of(f['name']))
            bucket[cat]['count'] += 1
            bucket[cat]['bytes'] += f['size']
        for cat, data in sorted(bucket.items(), key=lambda kv: kv[1]['bytes'], reverse=True):
            pct = (100.0 * data['bytes'] / total_filtered) if total_filtered else 0.0
            print(f"  {cat:8s}  files={data['count']:>6}  size={format_size(data['bytes']):>12}  ({pct:5.1f}%)")

    # ---------- Download-time estimate ----------
    if mbps:
        total_filtered = sum(f['size'] for f in filtered_files) if filtered_files else 0
        eta_all = download_time_seconds(total_filtered if filters_active else total_size_all, mbps)
        scope = "filtered total" if filters_active else "total"
        if eta_all is not None:
            print(f"\nEstimated download time at {mbps} Mbps ({scope}): ~{format_duration(eta_all)}")

        if roots:
            print("Per top-level folder ETA:")
            for r in roots:
                sz = 0
                if filters_active:
                    root_handles = set()
                    stack = [r]
                    while stack:
                        n = stack.pop()
                        root_handles.add(n['h'])
                        stack.extend(n['children'])
                    sz = sum(f['size'] for f in filtered_files if f['parent'] in root_handles or f['handle'] in root_handles)
                else:
                    sz = cum_size.get(r['h'], 0)
                eta = download_time_seconds(sz, mbps)
                disp_name = shorten_middle(r['dec_name'], name_max)
                print(f"  {disp_name}: {format_size(sz)}  →  ~{format_duration(eta) if eta is not None else 'n/a'}")

    # ---------- Export JSON / CSV ----------
    tree_data = []

    def build_export_tree(n):
        if not should_include_export(n):
            return None
        item = {
            'name': n['dec_name'],
            'type': "Folder" if n['t'] == 1 else "File",
            'size': n.get('s', 0),
            'timestamp': n.get('ts', None),
            'children': []
        }
        if n['t'] == 1:
            item['rollup_size'] = cum_size.get(n['h'], 0)
        for ch in n['children']:
            child_item = build_export_tree(ch)
            if child_item:
                item['children'].append(child_item)
        return item

    for r in roots:
        it = build_export_tree(r)
        if it:
            tree_data.append(it)

    if export_formats:
        if 'json' in export_formats:
            with open('mega_structure.json', 'w', encoding='utf-8') as f:
                json.dump(tree_data, f, indent=4)
            print("\nExported folder structure to mega_structure.json")

        if 'csv' in export_formats:
            import csv
            rows = []
            for f in filtered_files:
                ts_iso = ''
                if f['ts'] is not None:
                    try:
                        ts_iso = datetime.fromtimestamp(f['ts']).isoformat(timespec='seconds')
                    except Exception:
                        ts_iso = ''
                rows.append([f['path'], 'File', f['size'], format_size(f['size']), ts_iso, f['handle']])

            with open('mega_structure.csv', 'w', newline='', encoding='utf-8') as fcsv:
                w = csv.writer(fcsv)
                w.writerow(['path', 'type', 'size_bytes', 'size_human', 'ts_iso', 'handle'])
                w.writerows(rows)
            print("Exported file list to mega_structure.csv")

    # Footer: counts + total again
    folder_count = sum(1 for n in nodes if n['t'] == 1 and should_print_node_tree(n))
    file_count = 0 if only_folders else len(filtered_files)

    print("\n" + "-" * 48)
    print(f"{folder_count} folders · {file_count} files")
    print(f"Total Folder Size: {format_size(total_size_all)} ({total_size_all:,} bytes)")
    print("-" * 48 + "\n")


# =========================
# Core fetcher
# =========================
def get_mega_size(
    url,
    retries=3,
    backoff_factor=1,
    timeout=30,
    summary_only=False,
    export_format=None,
    only_folders=False,
    filters=None,
    sort_key='name',
    sort_desc=False,
    flat=False,
    mbps=None,
    bytes_only=False,
    name_max=80
):
    url = url.strip()
    if not url.startswith('https://mega.nz/'):
        raise ValueError("URL must start with 'https://mega.nz/'")

    # Extract handle, key_str, and determine if folder
    handle = None
    key_str = ''
    is_folder = None

    old_folder_match = re.search(r'#F!([^!]+)!([^!]+)', url)
    if old_folder_match:
        handle, key_str = old_folder_match.groups()
        is_folder = True
    elif re.search(r'#!([^!]+)!([^!]+)', url):
        old_file_match = re.search(r'#!([^!]+)!([^!]+)', url)
        if old_file_match:
            handle, key_str = old_file_match.groups()
            is_folder = False
    elif '/folder/' in url:
        new_folder_match = re.search(r'/folder/([^#]+)#?([^#]*)', url)
        if new_folder_match:
            handle, key_str = new_folder_match.groups()
            is_folder = True
    elif '/file/' in url:
        new_file_match = re.search(r'/file/([^#]+)#?([^#]*)', url)
        if new_file_match:
            handle, key_str = new_file_match.groups()
            is_folder = False

    if handle is None or is_folder is None:
        raise ValueError("Invalid MEGA URL format. Supported: old (#F!/#!) or new (/folder//file/).")

    # Decryption key (optional)
    master_key = None
    if key_str:
        try:
            master_key = base64urldecode(key_str)
            expected_key_len = 16 if is_folder else 32
            if len(master_key) != expected_key_len:
                print(f"Warning: Invalid key length (expected {expected_key_len} bytes, got {len(master_key)})—skipping decryption.")
                master_key = None
        except Exception:
            print("Warning: Invalid base64 key—skipping decryption.")
            master_key = None
    else:
        print("Warning: No decryption key found in URL—names will not be decrypted.")

    session = requests.Session()
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

    if is_folder:
        payload = [{"a": "f", "c": 1, "ca": 1, "r": 1}]
        params = {'id': 0, 'n': handle}
    else:
        payload = [{"a": "g", "p": handle, "ssl": 1}]
        params = {'id': 0}

    for attempt in range(retries):
        try:
            response = session.post(
                "https://g.api.mega.co.nz/cs",
                params=params,
                data=json.dumps(payload),
                headers=headers,
                timeout=timeout
            )
            response.raise_for_status()
            json_resp = response.json()

            if isinstance(json_resp, int) and json_resp < 0:
                msg = MEGA_ERROR_CODES.get(json_resp, f"Unknown MEGA API error: {json_resp}")
                raise MegaAPIError(json_resp, msg)

            if is_folder:
                obj = json_resp[0]
                if isinstance(obj, int) and obj < 0:
                    msg = MEGA_ERROR_CODES.get(obj, f"Unknown MEGA API error: {obj}")
                    raise MegaAPIError(obj, msg)

                nodes = obj.get("f", [])
                total_size_all = sum(node.get("s", 0) for node in nodes if node["t"] == 0)

                if bytes_only:
                    print(total_size_all)
                    return total_size_all, True

                export_formats = []
                if export_format:
                    export_formats = [x.strip().lower() for x in export_format.split(',') if x.strip()]

                print_folder_summary(
                    obj,
                    master_key,
                    total_size_all,
                    summary_only=summary_only,
                    export_formats=export_formats,
                    only_folders=only_folders,
                    filters=filters,
                    sort_key=sort_key,
                    sort_desc=sort_desc,
                    flat=flat,
                    mbps=mbps,
                    name_max=name_max
                )
                return total_size_all, True

            else:
                obj = json_resp[0]
                if isinstance(obj, int) and obj < 0:
                    msg = MEGA_ERROR_CODES.get(obj, f"Unknown MEGA API error: {obj}")
                    raise MegaAPIError(obj, msg)

                total_size = obj.get("s", 0)

                if bytes_only:
                    print(total_size)
                    return total_size, False

                print_file_summary(obj, master_key, total_size)
                return total_size, False

        except MegaAPIError as e:
            logging.error(f"Attempt {attempt + 1} failed: {e}")
            if attempt < retries - 1:
                time.sleep(backoff_factor * (2 ** attempt))
                continue
            raise

        except (requests.exceptions.RequestException, ValueError, json.JSONDecodeError) as e:
            logging.error(f"Attempt {attempt + 1} failed: {str(e)}")
            if attempt < retries - 1:
                time.sleep(backoff_factor * (2 ** attempt))
                continue
            raise MegaAPIError(-3, f"API request failed after {retries} attempts: {str(e)}")

    return 0, is_folder


# =========================
# CLI
# =========================
if __name__ == "__main__":
    try:
        import requests  # keep friendly error if missing
    except ImportError:
        print("Error: The 'requests' library is not installed.")
        print("Please install it by running: pip install requests")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Calculate the size of a public MEGA folder or file and display organized information.",
        epilog="Example: python mega_size.py https://mega.nz/folder/ABC123#def456"
    )
    parser.add_argument('url', help="Public MEGA URL (folder or file).")
    parser.add_argument('--verbose', action='store_true', help="Enable verbose logging (INFO level).")
    parser.add_argument('--summary', action='store_true', help="Print only the total size (skip detailed folder structure).")
    parser.add_argument('--export', help="Export format(s): json, csv, or 'json,csv'.")
    # -of (and keep -OF for compatibility), plus --only-folders
    parser.add_argument('-of', '-OF', '--only-folders', dest='only_folders', action='store_true',
                        help="Show only folders in the printed tree (no files).")
    # Filters
    parser.add_argument('--ext', help="Comma-separated extensions (e.g., .mp4,.mkv).")
    parser.add_argument('--min-size', dest='min_size', help="Minimum file size (e.g., 500MB).")
    parser.add_argument('--since', help="Only files with timestamp >= this date (YYYY-MM-DD).")
    parser.add_argument('--until', help="Only files with timestamp <= this date (YYYY-MM-DD, inclusive).")
    # Sorting
    parser.add_argument('--sort', choices=['size', 'name', 'date'], default='name',
                        help="Sort children by this key in the printed tree and flat list.")
    parser.add_argument('--desc', action='store_true', help="Sort descending.")
    # Output modes
    parser.add_argument('--bytes-only', action='store_true', help="Print only the total number of bytes, for piping.")
    parser.add_argument('--flat', action='store_true', help="Also print a flat list of files: '<size>\\t<path>'.")
    # Download time
    parser.add_argument('--mbps', type=float, help="Estimate download time at given Mbps (e.g., --mbps 100).")
    # Name truncation
    parser.add_argument('--name-max', type=int, default=80,
                        help="Max characters for displayed names; longer names are middle-ellipsized (default: 80).")

    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    # Validate mbps
    if args.mbps is not None and args.mbps <= 0:
        print("Error: --mbps must be greater than 0.")
        sys.exit(2)

    # Collect filters
    filter_dict = {}
    if args.ext:
        filter_dict['ext'] = [x.strip() for x in args.ext.split(',') if x.strip()]
    if args.min_size:
        filter_dict['min_size'] = args.min_size
    if args.since:
        filter_dict['since'] = args.since
    if args.until:
        filter_dict['until'] = args.until

    try:
        size_bytes, is_folder = get_mega_size(
            args.url,
            summary_only=args.summary,
            export_format=args.export,
            only_folders=args.only_folders,
            filters=filter_dict if filter_dict else None,
            sort_key=args.sort,
            sort_desc=args.desc,
            flat=args.flat,
            mbps=args.mbps,
            bytes_only=args.bytes_only,
            name_max=args.name_max
        )
        sys.exit(0)

    except ValueError as ve:
        print(f"Error: {ve}")
        sys.exit(2)

    except MegaAPIError as me:
        if me.code in RATE_LIMIT_CODES:
            print(f"Error: {MEGA_ERROR_CODES.get(me.code, 'Rate limited')} (code {me.code})")
            sys.exit(4)
        else:
            code = me.code if me.code is not None else -3
            print(f"Error: {MEGA_ERROR_CODES.get(code, str(me))} (code {code})")
            sys.exit(3)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(3)
