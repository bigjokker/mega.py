import json
import re
import sys
import argparse
import requests
import time
import logging
import base64
from datetime import datetime

# Attempt to import Crypto, but make it optional
HAS_CRYPTO = False
AES = None
try:
    from Crypto.Cipher import AES as _AES
    AES = _AES
    HAS_CRYPTO = True
except ImportError:
    print("Warning: pycryptodome not installed—file/folder names will show as encrypted handles. Install via 'pip install pycryptodome' for full functionality.")

# Set up logging
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

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
    dec_attr = dec_attr.rstrip(b'\0')  # Use rstrip for zero padding
    if dec_attr.startswith(b'MEGA'):
        try:
            attr_json = json.loads(dec_attr[4:].decode('utf-8'))
            return attr_json.get('n', 'Unknown')
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
    return None

def print_folder_summary(resp, master_key, total_size, summary_only=False, export_format=None):
    """
    Print a clean, organized summary of the folder response, including a tree structure with decrypted names if possible.
    """
    print()
    print(f"Total Folder Size: {format_size(total_size)} ({total_size} bytes)")
    print()
    
    if summary_only:
        return
    
    nodes = resp.get('f', [])
    if not nodes:
        print("Folder is empty.")
        return
    
    node_map = {node['h']: node for node in nodes}

    # Prepare nodes with decrypted names and children
    master_key_a32 = str_to_a32(master_key) if master_key else None
    for node in nodes:
        node['children'] = []
        dec_name = None
        if master_key and HAS_CRYPTO:
            try:
                if 'k' in node:
                    _, enc_key = node['k'].split(':')
                    k_bytes = base64urldecode(enc_key)
                    cipher_a32 = str_to_a32(k_bytes)
                    node_key_a32 = decrypt_key(cipher_a32, master_key_a32)
                    if node_key_a32:
                        if node['t'] == 0 and len(node_key_a32) == 8:
                            k = (node_key_a32[0] ^ node_key_a32[4], node_key_a32[1] ^ node_key_a32[5],
                                 node_key_a32[2] ^ node_key_a32[6], node_key_a32[3] ^ node_key_a32[7])
                        else:
                            k = node_key_a32
                        if 'a' in node:
                            a_bytes = base64urldecode(node['a'])
                            dec_name = decrypt_attr(a_bytes, k)
            except Exception as e:
                logging.debug(f"Decryption error for node {node['h']}: {str(e)}")
        node['dec_name'] = dec_name if dec_name else node['h'] + ' (encrypted)'

    # Build children
    for node in nodes:
        p = node.get('p')
        if p in node_map:
            node_map[p]['children'].append(node)

    # Find roots
    roots = [node for node in nodes if node.get('p') not in node_map]

    tree_data = []

    def build_tree(node, depth=0):
        indent = "  " * depth
        name = node['dec_name']
        type_str = "Folder" if node['t'] == 1 else "File"
        size_str = f" - {format_size(node['s'])}" if 's' in node and node['t'] == 0 else ""
        ts_str = ""
        if 'ts' in node:
            try:
                ts = datetime.fromtimestamp(node['ts'])
                ts_str = f" [{ts.strftime('%Y-%m-%d %H:%M:%S')}]"
            except:
                ts_str = " [Invalid timestamp]"
        line = f"{indent}- {name} ({type_str}{size_str}{ts_str})"
        print(line)
        tree_data.append({
            'name': name,
            'type': type_str,
            'size': node.get('s', 0),
            'timestamp': node.get('ts', None),
            'children': [build_tree(child, depth + 1) for child in node['children']]
        })
        return tree_data[-1]  # Return the current node data for recursion

    print("Folder Structure:")
    print("")
    for root in roots:
        build_tree(root)

    if export_format == 'json':
        with open('mega_structure.json', 'w') as f:
            json.dump(tree_data, f, indent=4)
        print("\nExported folder structure to mega_structure.json")

def print_file_summary(resp, master_key, total_size):
    """
    Print a clean, organized summary of the file response, including decrypted name if possible.
    """
    print()
    dec_name = None
    if master_key and HAS_CRYPTO:
        try:
            master_key_a32 = str_to_a32(master_key)
            if len(master_key_a32) != 8:
                raise ValueError("File master key should be 8 a32 (32 bytes)")
            k = (master_key_a32[0] ^ master_key_a32[4], master_key_a32[1] ^ master_key_a32[5],
                 master_key_a32[2] ^ master_key_a32[6], master_key_a32[3] ^ master_key_a32[7])
            at_bytes = base64urldecode(resp['at'])
            dec_name = decrypt_attr(at_bytes, k)
        except Exception as e:
            logging.debug(f"File decryption error: {str(e)}")
    name = dec_name if dec_name else 'Encrypted file'
    print(f"File Name: {name}")
    print(f"Total File Size: {format_size(total_size)} ({total_size} bytes)")

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

def get_mega_size(url, retries=3, backoff_factor=1, timeout=30, summary_only=False, export_format=None):
    """
    Calculate the size (in bytes) of a public MEGA file or the total size of all files in a public MEGA folder.

    Args:
        url (str): The public MEGA URL, e.g., 'https://mega.nz/folder/ABC123#def456' or 'https://mega.nz/file/ABC123#def456'.
        retries (int): Number of retry attempts for API calls.
        backoff_factor (int): Backoff factor for exponential retry delay.
        timeout (int): Timeout in seconds for the API request.
        summary_only (bool): If True, print only the total size without the folder structure.
        export_format (str): If 'json', export the folder structure to a JSON file.

    Returns:
        tuple: (size in bytes, is_folder boolean).

    Raises:
        ValueError: If the URL is invalid or unsupported.
        Exception: If the API request fails after retries.
    """
    url = url.strip()
    if not url.startswith('https://mega.nz/'):
        raise ValueError("URL must start with 'https://mega.nz/'")

    # Extract the decryption key from the URL if present
    master_key = None
    key_match = re.search(r'#([^!]+)', url)
    if key_match:
        key_str = key_match.group(1)
        try:
            master_key = base64urldecode(key_str)
            expected_key_len = 16 if '/folder/' in url else 32
            if len(master_key) != expected_key_len:
                print(f"Warning: Invalid key length (expected {expected_key_len} bytes, got {len(master_key)})—skipping decryption.")
                master_key = None
        except Exception as e:
            print(f"Warning: Invalid base64 key ({str(e)})—skipping decryption.")
            master_key = None
    else:
        print("Warning: No decryption key found in URL—names will not be decrypted.")

    session = requests.Session()
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

    if '/folder/' in url:
        match = re.search(r'/folder/([^#]+)', url)
        if not match:
            raise ValueError("Invalid MEGA folder URL format")
        handle = match.group(1)
        payload = [{"a": "f", "c": 1, "ca": 1, "r": 1}]
        params = {'id': 0, 'n': handle}
        is_folder = True
    elif '/file/' in url:
        match = re.search(r'/file/([^#]+)', url)
        if not match:
            raise ValueError("Invalid MEGA file URL format")
        handle = match.group(1)
        payload = [{"a": "g", "p": handle, "ssl": 1}]
        params = {'id': 0}
        is_folder = False
    else:
        raise ValueError("URL must contain '/folder/' or '/file/'")

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
            if isinstance(json_resp, int):
                error_msg = MEGA_ERROR_CODES.get(json_resp, f"Unknown MEGA API error: {json_resp}")
                raise Exception(error_msg)

            if is_folder:
                nodes = json_resp[0].get("f", [])
                total_size = sum(node.get("s", 0) for node in nodes if node["t"] == 0)
                print_folder_summary(json_resp[0], master_key, total_size, summary_only=summary_only, export_format=export_format)
            else:
                file_info = json_resp[0]
                total_size = file_info.get("s", 0)
                print_file_summary(json_resp[0], master_key, total_size)

            return total_size, is_folder

        except (requests.exceptions.RequestException, ValueError, json.JSONDecodeError) as e:
            logging.error(f"Attempt {attempt + 1} failed: {str(e)}")
            if attempt < retries - 1:
                time.sleep(backoff_factor * (2 ** attempt))
            else:
                raise Exception(f"API request failed after {retries} attempts: {str(e)}")

def format_size(size_bytes):
    """Convert bytes to human-readable format (e.g., KB, MB, GB)."""
    for unit in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} PB"

if __name__ == "__main__":
    try:
        import requests
    except ImportError:
        print("Error: The 'requests' library is not installed.")
        print("Please install it by running: pip install requests")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Calculate the size of a public MEGA folder or file and display organized information.",
        epilog="Example: python mega.py https://mega.nz/folder/ABC123#def456"
    )
    parser.add_argument(
        'url',
        help="Public MEGA URL (folder or file)."
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help="Enable verbose logging (INFO level)."
    )
    parser.add_argument(
        '--summary',
        action='store_true',
        help="Print only the total size (skip detailed folder structure for large folders)."
    )
    parser.add_argument(
        '--export',
        choices=['json'],
        help="Export the folder structure to a file (e.g., --export json)."
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    try:
        size_bytes, is_folder = get_mega_size(args.url, summary_only=args.summary, export_format=args.export)
    except ValueError as ve:
        print(f"Error: {ve}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)