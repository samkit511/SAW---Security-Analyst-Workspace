import re

KV_PATTERN = re.compile(r'(\b[a-zA-Z_]+)=')
IP_PATTERN = re.compile(r'\d{1,3}(?:\.\d{1,3}){3}')
REQUEST_LINE_PATTERN = re.compile(r'(?:GET|POST|PUT|DELETE|PATCH)\s+([^\s?]+)', re.IGNORECASE)


def parse_key_value_segments(log_data: str) -> dict:
    matches = list(KV_PATTERN.finditer(log_data))
    if not matches:
        return {}

    parsed = {}
    for index, match in enumerate(matches):
        key = match.group(1).lower()
        value_start = match.end()
        value_end = matches[index + 1].start() if index + 1 < len(matches) else len(log_data)
        parsed[key] = log_data[value_start:value_end].strip()
    return parsed


def analyze_logs(log_data: str) -> dict:
    """Extract security signals from raw log strings with key-value and request-line fallbacks."""
    parsed = parse_key_value_segments(log_data)
    ip_match = IP_PATTERN.search(log_data)
    path_match = REQUEST_LINE_PATTERN.search(log_data)

    ip_value = parsed.get("ip") or (ip_match.group(0) if ip_match else "unknown")
    path_value = parsed.get("path") or (path_match.group(1) if path_match else "/unknown")
    payload_value = parsed.get("payload") or log_data
    method_value = parsed.get("method")

    if path_value and not str(path_value).startswith("/"):
        path_value = "/" + str(path_value).lstrip("/")

    return {
        "ip": ip_value,
        "path": path_value or "/unknown",
        "method": method_value.upper() if method_value else "UNKNOWN",
        "payload": payload_value.strip(),
        "raw": log_data,
        "parse_mode": "key_value" if parsed else "regex_fallback",
    }
