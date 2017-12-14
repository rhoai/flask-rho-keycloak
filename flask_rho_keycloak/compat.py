# Compatibility
import sys

PY3 = sys.version_info[0] >= 3

if PY3:
    from json.decoder import JSONDecodeError

    json_decode_error = JSONDecodeError

else:
    json_decode_error = ValueError