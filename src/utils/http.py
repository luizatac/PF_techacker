import re
import time
from urllib.parse import urljoin, urlparse, urlencode

import requests

DEFAULT_TIMEOUT = 10
UA = "websec-tool/0.1 (+edu)"

def get(url, **kw):
    headers = kw.pop("headers", {})
    headers.setdefault("User-Agent", UA)
    return requests.get(url, headers=headers, timeout=kw.pop("timeout", DEFAULT_TIMEOUT), **kw)

def head(url, **kw):
    headers = kw.pop("headers", {})
    headers.setdefault("User-Agent", UA)
    return requests.head(url, headers=headers, timeout=kw.pop("timeout", DEFAULT_TIMEOUT), **kw)

def build_url_with_params(base, params):
    sep = "&" if ("?" in base) else "?"
    return f"{base}{sep}{urlencode(params)}"

SQL_ERROR_REGEXES = [
    r"SQL syntax.*MySQL", r"Warning: mysql_", r"Unclosed quotation mark after the character string",
    r"pg_query\(", r"PostgreSQL.*ERROR", r"SQLite/JDBCDriver", r"SQLSTATE\[\w+\]",
    r"ORA-\d{5}", r"ODBC SQL Server Driver", r"Microsoft OLE DB Provider for ODBC Drivers"
]
sql_error_re = re.compile("|".join(SQL_ERROR_REGEXES), re.I)

def likely_sqli_error(text):
    return bool(sql_error_re.search(text or ""))

def looks_like_passwd(text):
    return "root:x:" in (text or "")

def contains_reflected_payload(text, payload):
    return (payload in (text or ""))

def has_csrf_token(inputs):
    joined = " ".join(i.get("name","") + " " + i.get("id","") for i in inputs)
    return ("csrf" in joined.lower()) or ("token" in joined.lower()) or ("_token" in joined.lower())
