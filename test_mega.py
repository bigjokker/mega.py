import pytest
from mega import format_size, base64urldecode, get_mega_size  # Adjust import if your script file name is different

def test_format_size():
    assert format_size(0) == "0.00 bytes"
    assert format_size(1023) == "1023.00 bytes"
    assert format_size(1024) == "1.00 KB"
    assert format_size(1048576) == "1.00 MB"
    assert format_size(1073741824) == "1.00 GB"

def test_base64urldecode():
    assert base64urldecode("dGVzdA") == b"test"  # "test" base64url encoded without padding
    assert base64urldecode("dGVzdA==") == b"test"  # With padding

def test_get_mega_size_file(requests_mock):
    # Mock the API response for a file
    requests_mock.post(
        "https://g.api.mega.co.nz/cs",
        json=[{"s": 1024, "at": "test"}],
        status_code=200
    )
    size, is_folder = get_mega_size("https://mega.nz/file/ABC#def", summary_only=True)
    assert size == 1024
    assert not is_folder