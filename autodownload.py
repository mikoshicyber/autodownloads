#!/usr/bin/python3

import argparse
from contextlib import contextmanager, nullcontext
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque
from datetime import datetime
import ctypes
from ctypes import wintypes
import errno
import hashlib
import json
import ntpath
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
from threading import Lock
from time import sleep
from urllib.parse import parse_qsl, quote, unquote, urlencode, urljoin, urlparse, urlsplit, urlunsplit

import bs4
import requests
from natsort import natsorted

if os.name != "nt":
    import fcntl

DEBUG = False
SCRIPT_VERSION = "2026.11.26.3"
DEFAULT_DOWNLOAD_DIRECTORY = "/mnt/hdd1/shares/autodownloads/"
workdir = os.path.abspath(os.path.expanduser(os.environ.get("AUTODOWNLOAD_DIR") or DEFAULT_DOWNLOAD_DIRECTORY))
STAGING_DIRECTORY = os.path.join(workdir, ".autodownload-stage")
blacklist = []
plugins_directory = os.path.join(sys.path[0], "plugins")

PROXY_ENV_KEYS = (
    "http_proxy",
    "https_proxy",
    "ftp_proxy",
    "all_proxy",
    "no_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "FTP_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
)

DEFAULT_ARIA2 = {
    "split": 4,
    "max_connection_per_server": 4,
    "max_tries": 3,
    "retry_wait": 2,
    "connect_timeout": 10,
    "timeout": 10,
    "max_concurrent_downloads": 4,
}

BROWSER_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0"
SOURCEFORGE_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
SOURCEFORGE_MAX_DEPTH = 5
SOURCEFORGE_MAX_PAGES = 50
SOURCEFORGE_EXTENSIONS = (".exe", ".zip", ".7z", ".tar", ".gz", ".bz2", ".xz", ".zst", ".tgz", ".deb", ".rpm", ".msi", ".msix", ".dmg", ".iso", ".img", ".jar", ".war", ".apk", ".bin", ".run", ".whl", ".pdf", ".txt", ".sig", ".asc", ".sha256", ".sha512", ".appimage", ".box")
SENSITIVE_URL_PARAMETERS = frozenset(("token", "access_token", "auth", "authorization", "password", "passwd", "key", "api_key", "signature", "sig", "st", "fid", "e", "expires", "x-amz-signature", "x-amz-credential", "x-amz-security-token", "jwt", "skt", "ske", "sks", "skoid", "sktid"))


def redact_url(url):
    try:
        parts = urlsplit(str(url))
        port = parts.port
    except ValueError:
        return re.sub(r"(?<=://)[^/@]+@", "", str(url))
    if parts.scheme not in ("http", "https"):
        return str(url)
    host = parts.hostname or ""
    if not host:
        return str(url)
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if port:
        host = f"{host}:{port}"
    params = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        params.append((key, "REDACTED" if key.lower() in SENSITIVE_URL_PARAMETERS else value))
    return urlunsplit((parts.scheme, host, parts.path, urlencode(params), parts.fragment))


def redact_log_text(value):
    return re.sub(r"https?://[^\s\"'<>]+", lambda match: redact_url(match.group(0)), value)


class TeeStream:
    def __init__(self, terminal, logfile):
        self.terminal = terminal
        self.logfile = logfile

    def write(self, text):
        safe_text = redact_log_text(text)
        self.terminal.write(safe_text)
        self.logfile.write(safe_text)
        return len(text)

    def flush(self):
        self.terminal.flush()
        self.logfile.flush()

    def isatty(self):
        return self.terminal.isatty()


@contextmanager
def windows_named_lock(identity, scopes):
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel32.CreateMutexW
    create.argtypes = (ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR)
    create.restype = wintypes.HANDLE
    wait = kernel32.WaitForSingleObject
    wait.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    wait.restype = wintypes.DWORD
    release = kernel32.ReleaseMutex
    release.argtypes = (wintypes.HANDLE,)
    release.restype = wintypes.BOOL
    close = kernel32.CloseHandle
    close.argtypes = (wintypes.HANDLE,)
    close.restype = wintypes.BOOL
    acquired = []
    try:
        normalized = os.path.normcase(os.path.realpath(identity))
        for scope in sorted(set(scopes)):
            identifier = hashlib.sha256(os.fsencode(normalized + "\0" + scope)).hexdigest()
            handle = create(None, False, f"Global\\autodownload-{identifier}")
            if not handle:
                raise ctypes.WinError(ctypes.get_last_error())
            acquired.append((handle, False))
            result = wait(handle, 0xFFFFFFFF)
            if result not in (0, 0x80):
                raise RuntimeError(f"Cannot acquire autodownload mutex for {scope}: {ctypes.get_last_error()}")
            acquired[-1] = (handle, True)
        yield
    finally:
        for handle, owned in reversed(acquired):
            if owned:
                release(handle)
            close(handle)


@contextmanager
def capture_log(path):
    lock = windows_named_lock(path, ("log",)) if os.name == "nt" else nullcontext()
    with lock:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", buffering=1) as logfile:
            if os.name != "nt":
                fcntl.flock(fd, fcntl.LOCK_EX)
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            original_stdout, original_stderr = sys.stdout, sys.stderr
            sys.stdout = TeeStream(original_stdout, logfile)
            sys.stderr = TeeStream(original_stderr, logfile)
            try:
                print(f"INFO: Run started at {datetime.now().astimezone().isoformat(timespec='seconds')}")
                print(f"INFO: Log file: {path}")
                print(f"INFO: Script version: {SCRIPT_VERSION}")
                print(f"INFO: Download directory: {workdir}")
                yield
            finally:
                sys.stdout.flush()
                sys.stderr.flush()
                sys.stdout, sys.stderr = original_stdout, original_stderr


@contextmanager
def exclusive_lock(script_path, scopes):
    script_path = os.path.realpath(script_path)
    requested = sorted(set(scopes)) or ["plugin:__empty__"]
    if os.name == "nt":
        with windows_named_lock(script_path, requested):
            yield
        return
    addresses = [
        (scope, b"\0autodownload-" + hashlib.sha256(os.fsencode(script_path + "\0" + scope)).hexdigest().encode("ascii"))
        for scope in requested
    ]
    legacy_address = b"\0autodownload-" + hashlib.sha256(os.fsencode(script_path)).hexdigest().encode("ascii")
    acquired = []
    waiting_for = None
    try:
        while True:
            conflict = None
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as old_lock:
                try:
                    old_lock.bind(legacy_address)
                except OSError as error:
                    if error.errno != errno.EADDRINUSE:
                        raise RuntimeError(f"Cannot check legacy autodownload lock: {error}") from error
                    conflict = "legacy instance"
            if conflict:
                if waiting_for != conflict:
                    print(f"INFO: Waiting for another autodownload instance ({conflict})", file=sys.stderr)
                    waiting_for = conflict
                sleep(1)
                continue
            for scope, address in addresses:
                try:
                    lock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                except OSError as error:
                    raise RuntimeError(f"Cannot create autodownload lock for {scope}: {error}") from error
                try:
                    lock.bind(address)
                except OSError as error:
                    lock.close()
                    if error.errno != errno.EADDRINUSE:
                        raise RuntimeError(f"Cannot acquire autodownload lock for {scope}: {error}") from error
                    conflict = scope
                    break
                acquired.append(lock)
            if conflict is None:
                break
            for lock in reversed(acquired):
                lock.close()
            acquired.clear()
            if waiting_for != conflict:
                print(f"INFO: Waiting for another autodownload instance ({conflict})", file=sys.stderr)
                waiting_for = conflict
            sleep(1)
        yield
    finally:
        for lock in reversed(acquired):
            lock.close()


def eprint(*args, **kwargs):
    print("DEBUG:", *args, file=sys.stderr, **kwargs)


def strip_json_comments(text):
    result = []
    i = 0
    in_string = False
    escaped = False
    while i < len(text):
        c = text[i]
        n = text[i + 1] if i + 1 < len(text) else ""
        if in_string:
            result.append(c)
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                in_string = False
            i += 1
            continue
        if c == '"':
            in_string = True
            result.append(c)
            i += 1
            continue
        if c == "/" and n == "/":
            i += 2
            while i < len(text) and text[i] not in "\r\n":
                i += 1
            continue
        if c == "/" and n == "*":
            i += 2
            while i + 1 < len(text) and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        result.append(c)
        i += 1
    return "".join(result)


def load_jsonc_file(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        return json.loads(strip_json_comments(file.read()))


def load_plugin(directory, filename, failures=None):
    file_name = filename if filename.endswith(".json") else filename + ".json"
    file_path = os.path.join(directory, file_name)
    try:
        data = load_jsonc_file(file_path)
        if not isinstance(data, dict):
            raise ValueError("Plugin configuration must be a JSON object")
        data["_plugin_name"] = os.path.splitext(file_name)[0]
        data["_plugin_file"] = file_path
        return [data]
    except (OSError, UnicodeError, ValueError) as error:
        if failures is not None:
            failures.append(file_name)
        print(f"ERROR: Cannot load plugin {file_name}: {error}", file=sys.stderr)
        return []


def load_plugins(directory, failures=None):
    file_list = []
    if not os.path.isdir(directory):
        return file_list
    try:
        filenames = os.listdir(directory)
    except OSError as error:
        if failures is not None:
            failures.append(directory)
        print(f"ERROR: Cannot list plugins in {directory}: {error}", file=sys.stderr)
        return file_list
    for filename in filenames:
        if not filename.endswith(".json"):
            continue
        file_list.extend(load_plugin(directory, filename, failures))
    return file_list


def sort_key(x):
    return str(x).replace(".", "_").replace(" ", "_").replace("-", "_")


def in_blacklist(url):
    for b in blacklist:
        if b.lower() in url.lower():
            print("url in blacklist", url, b)
            return True
    return False


def checkurl(url, rules, filename=None):
    if not url:
        return False
    filename = (filename if filename is not None else filename_from_url(url)).lower()
    for r in rules or []:
        if not r:
            continue
        check = re.compile(str(r), re.IGNORECASE)
        if check.match(filename) and not in_blacklist(url):
            if DEBUG:
                eprint("matched", filename, "from", url)
            return True
    return False


def normalize_proxy_url(proxy):
    if proxy is None:
        return ""
    value = str(proxy).strip()
    if not value:
        return ""
    if "://" not in value:
        value = "http://" + value
    return value


def parse_proxy_config(value):
    if not value:
        return {}
    if isinstance(value, str):
        proxy = normalize_proxy_url(value)
        return {"all": proxy} if proxy else {}
    if isinstance(value, dict):
        result = {}
        for src, dst in (
            ("all", "all"),
            ("all_proxy", "all"),
            ("http", "http"),
            ("http_proxy", "http"),
            ("https", "https"),
            ("https_proxy", "https"),
            ("ftp", "ftp"),
            ("ftp_proxy", "ftp"),
        ):
            if src in value and value[src]:
                result[dst] = normalize_proxy_url(value[src])
        no_proxy = value.get("no_proxy") or value.get("no")
        if no_proxy:
            result["no_proxy"] = str(no_proxy).strip()
        return result
    return {}


def target_proxy_config(target):
    return parse_proxy_config(target.get("proxy"))


def requests_proxies(proxy_config):
    result = {}
    if proxy_config.get("all"):
        result["http"] = proxy_config["all"]
        result["https"] = proxy_config["all"]
    if proxy_config.get("http"):
        result["http"] = proxy_config["http"]
    if proxy_config.get("https"):
        result["https"] = proxy_config["https"]
    return result


def clean_proxy_env(env):
    clean = dict(env)
    for key in PROXY_ENV_KEYS:
        clean.pop(key, None)
    return clean


def request_text(url, target=None):
    target = target or {}
    proxy_config = target_proxy_config(target)
    proxies = requests_proxies(proxy_config)
    headers = {"User-Agent": BROWSER_USER_AGENT}
    connect_timeout = float(target.get("request_connect_timeout", 10))
    read_timeout = float(target.get("request_read_timeout", 45))
    retries = int(target.get("request_retries", 2))
    retry_wait = float(target.get("request_retry_wait", 2))
    if connect_timeout <= 0 or read_timeout <= 0 or retries < 0 or retry_wait < 0:
        raise ValueError("Invalid HTTP request timeout or retry configuration")
    if DEBUG:
        eprint("request", url, "proxy protocols", sorted(proxies), "timeout", (connect_timeout, read_timeout))
    with requests.Session() as session:
        session.trust_env = False
        for attempt in range(retries + 1):
            try:
                response = session.get(url, headers=headers, timeout=(connect_timeout, read_timeout), proxies=proxies)
                response.raise_for_status()
                return response.text
            except (requests.Timeout, requests.ConnectionError) as error:
                if attempt >= retries:
                    raise
                print(f"WARN: HTTP request retry {attempt + 1}/{retries} for {url}: {error}", file=sys.stderr)
            except requests.HTTPError as error:
                code = error.response.status_code if error.response is not None else None
                retryable = code in (429, 500, 502, 503, 504)
                if not retryable or attempt >= retries:
                    raise
                print(f"WARN: HTTP request retry {attempt + 1}/{retries} for {url}: {error}", file=sys.stderr)
            sleep(retry_wait * (attempt + 1))


def find_all_links(url, target=None, tag="a", attr="href"):
    urls = []
    response = request_text(url, target)
    if "github.com/techarohq/anubis" in response.lower() and "techaro.lol" in response.lower():
        raise RuntimeError(f"Anti-bot protection (Anubis) blocks link discovery at {url}")
    data = bs4.BeautifulSoup(response, "lxml")
    for a in data.find_all(tag, recursive=True):
        if a.has_attr(attr):
            if str(a[attr]).startswith("http"):
                furl = a[attr]
            else:
                furl = urljoin(url, a[attr])
            urls.append(furl)
    return urls


def is_sourceforge_url(url):
    host = (urlparse(str(url)).hostname or "").lower()
    return host == "sourceforge.net" or host.endswith(".sourceforge.net")


def sanitize_filename(name):
    value = unquote(str(name)).strip()
    value = value.replace("\x00", "")
    value = value.replace("/", "_").replace("\\", "_")
    value = re.sub(r"\s+", " ", value)
    return value.strip(" .")


def filename_from_url(url):
    parsed = urlparse(url)
    parts = [part for part in parsed.path.rstrip("/").split("/") if part]
    if not parts:
        return ""
    if is_sourceforge_url(url) and parts[-1].lower() == "download":
        parts = parts[:-1]
    return sanitize_filename(parts[-1]) if parts else ""


def valid_download_filename(name):
    if not name:
        return False
    value = name.lower()
    if value in ("download", "latest", "files"):
        return False
    if "." not in name or re.fullmatch(r"\d+(?:\.\d+)+", name):
        return False
    return True


def sourceforge_project_name(url):
    parsed = urlparse(url)
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) >= 2 and parts[0] in ("projects", "project"):
        return parts[1]
    return ""


def sourceforge_is_release_request(url):
    parsed = urlparse(url)
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2 or parts[0] != "projects":
        return False
    return parts[2:] in ([], ["files"], ["files", "latest"], ["files", "latest", "download"])


def sourceforge_apply_mirror(url, target):
    mirror = str(target.get("sourceforge_mirror") or "").strip()
    if not mirror:
        return url
    parsed = urlsplit(url)
    if not is_sourceforge_url(url):
        raise ValueError(f"SourceForge mirror requires a SourceForge download URL: {url}")
    if not parsed.path.endswith("/download"):
        if "/files/" not in parsed.path:
            raise ValueError(f"SourceForge mirror requires a project file URL: {url}")
        parsed = parsed._replace(path=parsed.path.rstrip("/") + "/download")
    params = [(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True) if key != "use_mirror"]
    params.append(("use_mirror", mirror))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(params), parsed.fragment))


def resolve_sourceforge_download(url, target):
    if sourceforge_is_release_request(url):
        project = sourceforge_project_name(url)
        final_url = url if urlparse(url).path.rstrip("/").endswith("/files/latest/download") else f"https://sourceforge.net/projects/{project}/files/latest/download"
        filename = ""
        if target.get("sourceforge_platform"):
            print("WARN: sourceforge_platform does not constrain SourceForge latest/download; use a platform-specific file URL or rules", file=sys.stderr)
    else:
        final_url, filename = url, filename_from_url(url)
        if not valid_download_filename(filename):
            raise ValueError(f"SourceForge URL is not a file or release: {url}")
    return sourceforge_apply_mirror(final_url, target), filename


def is_documentfoundation_url(url):
    parsed = urlparse(str(url))
    return parsed.hostname == "download.documentfoundation.org" and parsed.path.startswith("/libreoffice/")


def is_github_release_page(url):
    parsed = urlsplit(url)
    return (parsed.hostname or "").lower() == "github.com" and re.fullmatch(
        r"/[^/]+/[^/]+/releases(?:/(?:latest|tag/[^/]+))?/?", parsed.path
    ) is not None


def resolve_file_redirect(url, proxy_config, provider):
    command = [
        "curl",
        "--location",
        "--silent",
        "--show-error",
        "--fail",
        "--range", "0-0",
        "--max-filesize", "1048576",
        "--connect-timeout", "10",
        "--max-time", "45",
        "--output", os.devnull,
        "--write-out", "%{url_effective}",
    ]
    if provider == "LibreOffice":
        command.extend(("--user-agent", BROWSER_USER_AGENT))
    proxy = proxy_config or {}
    proxy_url = proxy.get("https") or proxy.get("all")
    if proxy_url:
        command.extend(("--proxy", proxy_url))
    if proxy.get("no_proxy"):
        command.extend(("--noproxy", proxy["no_proxy"]))
    command.extend(("--", url))
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False, env=clean_proxy_env(os.environ))
    except FileNotFoundError as error:
        raise RuntimeError(f"curl is required for {provider} downloads") from error
    if result.returncode != 0:
        details = result.stderr.strip() or "no details"
        raise RuntimeError(f"{provider} redirect failed for {url}: curl exit {result.returncode}: {details}")
    final_url = result.stdout.strip()
    filename = filename_from_url(final_url)
    parsed_final = urlsplit(final_url)
    if is_github_release_page(final_url):
        raise RuntimeError(f"{provider} redirect returned a GitHub release page, not a file: {final_url}")
    if parsed_final.scheme != "https" or not valid_download_filename(filename):
        raise RuntimeError(f"{provider} redirect returned an invalid file URL: {final_url}")
    if filename.lower().endswith((".meta4", ".metalink")):
        raise RuntimeError(f"{provider} redirect returned a Metalink document instead of a file: {final_url}")
    return final_url, filename


def sourceforge_resolve_redirect(url, proxy_config):
    return resolve_file_redirect(url, proxy_config, "SourceForge")


def sourceforge_latest_filename(url, target):
    _, filename = sourceforge_resolve_redirect(url, target_proxy_config(target))
    return filename


def sourceforge_file_links(url, target):
    project = sourceforge_project_name(url)
    if not project:
        raise ValueError(f"Cannot determine SourceForge project: {url}")
    root = f"https://sourceforge.net/projects/{project}/files/"
    parsed = urlparse(url)
    if parsed.path.rstrip("/") in (f"/projects/{project}", f"/projects/{project}/files"):
        start_url = root
    else:
        if not parsed.path.startswith(f"/projects/{project}/files/"):
            raise ValueError(f"Not a SourceForge files directory: {url}")
        start_url = url
    pending = [(start_url, 0)]
    visited = set()
    found = set()
    while pending:
        page_url, depth = pending.pop(0)
        if page_url in visited:
            continue
        if len(visited) >= SOURCEFORGE_MAX_PAGES:
            raise RuntimeError(f"SourceForge listing exceeded {SOURCEFORGE_MAX_PAGES} pages: {start_url}")
        visited.add(page_url)
        html = request_text(page_url, target)
        soup = bs4.BeautifulSoup(html, "lxml")
        for tag in soup.find_all(True):
            for attr in ("href", "data-url", "data-href"):
                href = tag.get(attr)
                if not isinstance(href, str) or not href.strip():
                    continue
                candidate = urljoin(page_url, href.strip())
                candidate_parts = urlsplit(candidate)
                if candidate_parts.hostname != "sourceforge.net":
                    if is_sourceforge_url(candidate) and sourceforge_project_name(candidate) == project and valid_download_filename(filename_from_url(candidate)):
                        found.add(candidate)
                    continue
                if not candidate_parts.path.startswith(root.replace("https://sourceforge.net", "")):
                    continue
                if "/download" in candidate_parts.path and not candidate_parts.path.endswith("/download"):
                    continue
                name = filename_from_url(candidate)
                is_download = candidate_parts.path.endswith("/download")
                is_file = valid_download_filename(name) and (is_download or name.lower().endswith(SOURCEFORGE_EXTENSIONS))
                if is_file and not candidate_parts.path.endswith("/"):
                    if not candidate_parts.path.endswith("/download"):
                        candidate = urlunsplit((candidate_parts.scheme, candidate_parts.netloc, candidate_parts.path + "/download", candidate_parts.query, ""))
                    found.add(candidate)
                elif depth < SOURCEFORGE_MAX_DEPTH:
                    folder = urlunsplit((candidate_parts.scheme, candidate_parts.netloc, candidate_parts.path.rstrip("/") + "/", "", ""))
                    if folder not in visited:
                        pending.append((folder, depth + 1))
    if DEBUG:
        eprint("SourceForge pages", len(visited), "files", len(found))
    return natsorted(found, key=sort_key)


def recursive_file_links(url, target, failures=None):
    rules = target.get("rules") or []
    search_regex = target.get("search_regex")
    if not isinstance(search_regex, str) or not search_regex.strip():
        raise ValueError("type 3 requires a non-empty search_regex")
    if not isinstance(rules, list) or not any(rules):
        raise ValueError("type 3 requires non-empty rules")
    search_pattern = re.compile(search_regex, re.IGNORECASE)
    max_depth = int(target.get("max_depth", 3))
    max_pages = int(target.get("max_pages", 100))
    search_tail = int(target.get("search_tail", 0))
    if max_depth < 1 or max_pages < 1 or search_tail < 0:
        raise ValueError("Invalid type 3 max_depth, max_pages or search_tail")
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(f"type 3 requires an HTTP(S) directory URL: {url}")
    root_path = parsed.path.rstrip("/") + "/"
    root_url = urlunsplit((parsed.scheme, parsed.netloc, root_path, "", ""))
    pending = deque([(root_url, 0)])
    visited = set()
    found = set()
    while pending:
        page_url, depth = pending.popleft()
        if page_url in visited:
            continue
        if len(visited) >= max_pages:
            raise RuntimeError(f"type 3 exceeded max_pages={max_pages}: {root_url}")
        visited.add(page_url)
        try:
            links = find_all_links(page_url, target)
        except (requests.RequestException, RuntimeError, ValueError, OSError) as error:
            if depth == 0 or failures is None:
                raise
            failures.append(f"{target.get('_plugin_name') or root_url}: {page_url}")
            print(f"ERROR: Cannot scan directory {page_url}: {error}", file=sys.stderr)
            continue
        directories = set()
        for link in links:
            candidate = urlsplit(link)
            if (candidate.scheme, candidate.netloc.lower()) != (parsed.scheme, parsed.netloc.lower()):
                continue
            if not candidate.path.startswith(root_path):
                continue
            if candidate.path == root_path:
                continue
            name = unquote(candidate.path.rstrip("/").rsplit("/", 1)[-1])
            if not name:
                continue
            query_keys = {key.lower() for key, _ in parse_qsl(candidate.query, keep_blank_values=True)}
            if query_keys & {"stats", "mirrorlist"}:
                continue
            if not candidate.path.endswith("/") and checkurl(link, rules):
                found.add(urlunsplit((candidate.scheme, candidate.netloc, candidate.path, candidate.query, "")))
                continue
            folder_name = name + "/"
            folder_path = candidate.path.rstrip("/") + "/"
            if depth < max_depth and (
                search_pattern.search(folder_name) or search_pattern.search(unquote(folder_path))
            ):
                directories.add(urlunsplit((candidate.scheme, candidate.netloc, folder_path, "", "")))
        selected = natsorted(directories, key=sort_key)
        if search_tail:
            selected = selected[-search_tail:]
        for folder in selected:
            if folder not in visited:
                pending.append((folder, depth + 1))
    if DEBUG:
        eprint("type 3 scanned", len(visited), "page(s), found", len(found), "file(s)")
    return natsorted(found, key=sort_key)


def download_item(url, target):
    final_url = url
    out_name = sanitize_filename(target.get("out", "")) if isinstance(target, dict) else ""
    if is_sourceforge_url(url):
        final_url, resolved_name = resolve_sourceforge_download(url, target)
        if not out_name:
            out_name = resolved_name
    return {
        "url": final_url,
        "out": out_name,
        "proxy": target_proxy_config(target),
        "aria2": target.get("aria2", {}) if isinstance(target, dict) else {},
        "source": target.get("url", "") if isinstance(target, dict) else "",
        "cleanup_rules": tuple(target.get("rules") or ()) if isinstance(target, dict) else (),
    }


def select_tail(urls, tail):
    unique = natsorted(set(urls), key=sort_key)
    try:
        tail_value = int(tail)
    except Exception:
        tail_value = 0
    if tail_value > 0:
        return unique[-tail_value:]
    return unique


def github_api_url(link):
    parsed = urlparse(link)
    host = parsed.netloc.lower()
    if host == "api.github.com":
        return link
    if host == "github.com" or host.endswith(".github.com"):
        parts = [p for p in parsed.path.strip("/").split("/") if p]
        if len(parts) >= 2:
            owner = parts[0]
            repo = parts[1]
            rest = parts[2:]
            if rest[:2] == ["releases", "latest"]:
                return f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
            if rest[:1] == ["releases"]:
                return f"https://api.github.com/repos/{owner}/{repo}/releases"
            return f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
    return link.replace("/github.com/", "/api.github.com/repos/")


def github_sha256(value):
    match = re.fullmatch(r"sha256:([0-9a-fA-F]{64})", str(value or "").strip())
    return match.group(1).lower() if match else ""


def github_release_assets(link, target, digests=None):
    sleep(0.1)
    data = json.loads(request_text(github_api_url(link), target))
    if isinstance(data, dict):
        assets = data.get("assets", [])
    elif isinstance(data, list) and data:
        assets = data[0].get("assets", []) if isinstance(data[0], dict) else []
    else:
        assets = []
    urls = []
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        url = asset.get("browser_download_url", "")
        if not isinstance(url, str) or not url:
            continue
        urls.append(url)
        if digests is not None:
            checksum = github_sha256(asset.get("digest"))
            if checksum:
                digests[url] = checksum
    return urls


def github_asset_release_api(url):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or (parsed.hostname or "").lower() != "github.com":
        return None
    parts = parsed.path.strip("/").split("/")
    if len(parts) != 6 or parts[2] != "releases":
        return None
    owner, repo = parts[:2]
    if not owner or not repo:
        return None
    if parts[3:5] == ["latest", "download"]:
        endpoint = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
    elif parts[3] == "download":
        tag = unquote(parts[4])
        if not tag:
            return None
        endpoint = f"https://api.github.com/repos/{owner}/{repo}/releases/tags/{quote(tag, safe='')}"
    else:
        return None
    return endpoint, unquote(parts[5])


def prepare_github_checksums(items):
    cache = {}
    prepared = []
    for item in items:
        if item.get("github_sha256"):
            prepared.append(item)
            continue
        lookup = github_asset_release_api(item["url"])
        if lookup is None:
            prepared.append(item)
            continue
        endpoint, filename = lookup
        if endpoint not in cache:
            try:
                data = json.loads(request_text(endpoint, {"proxy": item.get("proxy")}))
                if not isinstance(data, dict):
                    raise ValueError("GitHub release API returned an unexpected response")
                cache[endpoint] = {
                    asset["name"]: github_sha256(asset.get("digest"))
                    for asset in data.get("assets", [])
                    if isinstance(asset, dict) and isinstance(asset.get("name"), str)
                }
            except (requests.RequestException, ValueError, TypeError, KeyError) as error:
                print(f"WARN: Cannot get GitHub release SHA-256 from {endpoint}: {error}", file=sys.stderr)
                cache[endpoint] = {}
        checksum = cache[endpoint].get(filename, "")
        if checksum:
            enriched = dict(item)
            enriched["github_sha256"] = checksum
            prepared.append(enriched)
            if DEBUG:
                eprint("GitHub SHA-256", filename, checksum)
        else:
            prepared.append(item)
            if DEBUG:
                eprint("GitHub SHA-256 unavailable for", filename)
    return prepared


def get_target_downloads(target, failures=None):
    link = target.get("url", "")
    if not link:
        return []
    if DEBUG:
        eprint("Target link", link)
    urls = []
    rules = target.get("rules", [])
    tail = target.get("tail", 0)
    release_name = ""
    github_digests = {}
    if target.get("type", 1) == 3:
        urls.extend(recursive_file_links(link, target, failures))
    elif "github.com" in link:
        for furl in github_release_assets(link, target, github_digests):
            if checkurl(furl, rules):
                urls.append(furl)
    elif is_sourceforge_url(link):
        if urlparse(link).path.rstrip("/").endswith("/files/latest/download"):
            resolved_link, release_name = resolve_sourceforge_download(link, target)
            if not release_name:
                release_name = sourceforge_latest_filename(link, target)
            if checkurl(resolved_link, rules, filename=release_name):
                urls.append(resolved_link)
        elif valid_download_filename(filename_from_url(link)):
            if checkurl(link, rules):
                urls.append(link)
        else:
            for u in sourceforge_file_links(link, target):
                if checkurl(u, rules):
                    urls.append(u)
    else:
        try:
            links = find_all_links(link, target)
        except RuntimeError as error:
            if (urlparse(link).hostname or "").lower() not in ("farmanager.com", "www.farmanager.com") or "Anubis" not in str(error):
                raise
            print("WARN: Far Manager website is protected by Anubis; trying official GitHub Releases", file=sys.stderr)
            links = github_release_assets("https://github.com/FarGroup/FarManager/releases/latest", target, github_digests)
            matched = [u for u in links if checkurl(u, rules)]
            if not matched:
                rule_text = " ".join(str(rule).lower() for rule in rules)
                architecture = "x64" if "x64" in rule_text else "x86" if "x86" in rule_text else ""
                if architecture and "msi" in rule_text:
                    fallback_rule = rf"^Far_.*_{architecture}_.*\.msi$"
                    matched = [u for u in links if re.match(fallback_rule, filename_from_url(u), re.IGNORECASE)]
                    if matched:
                        print(f"WARN: Far Manager plugin rules do not match current release filenames; using {architecture} MSI", file=sys.stderr)
            urls.extend(matched)
            links = []
        for u in links:
            furl = u if str(u).lower().startswith("http") else urljoin(link, u)
            if checkurl(furl, rules):
                urls.append(furl)
            elif (urlparse(link).hostname or "").lower() in ("inkscape.org", "www.inkscape.org"):
                name = filename_from_url(furl)
                if name.lower().endswith("-x64.signed.exe") and checkurl(furl, rules, filename=name[:-len(".signed.exe")] + ".exe"):
                    urls.append(furl)
    if not urls:
        raise RuntimeError(f"No downloadable files match the rules for {link}")
    if DEBUG:
        eprint("get_urls", set(urls))
    result = []
    for url in select_tail(urls, tail):
        try:
            item = download_item(url, target)
            if url in github_digests:
                item["github_sha256"] = github_digests[url]
            if is_sourceforge_url(link) and urlparse(link).path.rstrip("/").endswith("/files/latest/download") and not item["out"]:
                item["out"] = release_name
            result.append(item)
        except Exception as error:
            if failures is None:
                raise
            name = target.get("_plugin_name") or link
            failures.append(f"{name}: {url}")
            print(f"ERROR: Cannot prepare URL {url} from {name}: {error}", file=sys.stderr)
    return result


def get_urls(targets, failures=None):
    final = []
    for target in targets:
        try:
            final.extend(get_target_downloads(target, failures))
        except Exception as error:
            if failures is None:
                raise
            name = target.get("_plugin_name") or target.get("url", "")
            failures.append(name)
            print(f"ERROR: Cannot discover downloads for {name}: {error}", file=sys.stderr)
    seen = set()
    result = []
    for item in natsorted(final, key=lambda x: sort_key(x["url"])):
        key = (item["url"], item.get("out", ""), json.dumps(item["proxy"], sort_keys=True))
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def aria2_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def aria2_option(options, aliases, default=None):
    for alias in aliases:
        if alias in options and options[alias] is not None:
            return options[alias]
    return default


def item_aria2_options(item):
    custom = item.get("aria2") or {}
    url = str(item.get("url", "")).lower()
    source = str(item.get("source", "")).lower()
    is_sourceforge = is_sourceforge_url(url) or is_sourceforge_url(source)

    default_split = 2 if is_sourceforge else DEFAULT_ARIA2["split"]
    default_max_conn = 2 if is_sourceforge else DEFAULT_ARIA2["max_connection_per_server"]
    default_connect_timeout = 20 if is_sourceforge else DEFAULT_ARIA2["connect_timeout"]
    default_timeout = 120 if is_sourceforge else DEFAULT_ARIA2["timeout"]
    default_max_tries = 5 if is_sourceforge else DEFAULT_ARIA2["max_tries"]
    default_retry_wait = 5 if is_sourceforge else DEFAULT_ARIA2["retry_wait"]

    options = {
        "dir": item.get("download_dir") or workdir,
        "continue": "true",
        "allow-overwrite": "false",
        "auto-file-renaming": "false",
        "remote-time": "true",
        "conditional-get": "false",
        "content-disposition-default-utf8": "true",
        "max-tries": aria2_option(custom, ("max_tries", "max-tries"), default_max_tries),
        "retry-wait": aria2_option(custom, ("retry_wait", "retry-wait"), default_retry_wait),
        "connect-timeout": aria2_option(custom, ("connect_timeout", "connect-timeout"), default_connect_timeout),
        "timeout": aria2_option(custom, ("timeout",), default_timeout),
        "split": aria2_option(custom, ("split", "s"), default_split),
        "max-connection-per-server": aria2_option(custom, ("max_connection_per_server", "max-connection-per-server", "x"), default_max_conn),
    }

    if item.get("out"):
        options["out"] = item["out"]
    if item.get("github_sha256"):
        options["checksum"] = f"sha-256={item['github_sha256']}"
    if item.get("download_dir") == STAGING_DIRECTORY:
        options["auto-save-interval"] = aria2_option(custom, ("auto_save_interval", "auto-save-interval"), 10)

    if is_sourceforge:
        options["user-agent"] = aria2_option(custom, ("user_agent", "user-agent"), SOURCEFORGE_USER_AGENT)
        options["referer"] = aria2_option(custom, ("referer",), "*")
        options["min-split-size"] = aria2_option(custom, ("min_split_size", "min-split-size"), "5M")
    elif is_documentfoundation_url(source):
        options["user-agent"] = aria2_option(custom, ("user_agent", "user-agent"), BROWSER_USER_AGENT)
        options["no-want-digest-header"] = aria2_option(custom, ("no_want_digest_header", "no-want-digest-header"), "true")

    for src, dst in (
        ("min_split_size", "min-split-size"),
        ("min-split-size", "min-split-size"),
        ("file_allocation", "file-allocation"),
        ("file-allocation", "file-allocation"),
        ("lowest_speed_limit", "lowest-speed-limit"),
        ("lowest-speed-limit", "lowest-speed-limit"),
        ("user_agent", "user-agent"),
        ("user-agent", "user-agent"),
        ("referer", "referer"),
        ("conditional_get", "conditional-get"),
        ("conditional-get", "conditional-get"),
        ("content_disposition_default_utf8", "content-disposition-default-utf8"),
        ("content-disposition-default-utf8", "content-disposition-default-utf8"),
        ("no_want_digest_header", "no-want-digest-header"),
        ("no-want-digest-header", "no-want-digest-header"),
        ("http_accept_gzip", "http-accept-gzip"),
        ("http-accept-gzip", "http-accept-gzip"),
        ("out", "out"),
    ):
        if src in custom and custom[src] is not None:
            options[dst] = custom[src]

    proxy = item.get("proxy") or {}
    if proxy.get("all"):
        options["all-proxy"] = proxy["all"]
    if proxy.get("http"):
        options["http-proxy"] = proxy["http"]
    if proxy.get("https"):
        options["https-proxy"] = proxy["https"]
    if proxy.get("ftp"):
        options["ftp-proxy"] = proxy["ftp"]
    if proxy.get("no_proxy"):
        options["no-proxy"] = proxy["no_proxy"]

    return {k: aria2_value(v).replace("\n", " ").replace("\r", " ") for k, v in options.items() if v is not None and str(v) != ""}


def max_concurrent_downloads(items):
    values = [DEFAULT_ARIA2["max_concurrent_downloads"]]
    for item in items:
        custom = item.get("aria2") or {}
        value = aria2_option(custom, ("max_concurrent_downloads", "max-concurrent-downloads", "j"), None)
        if value is not None:
            try:
                values.append(int(value))
            except Exception:
                pass
    return max(values)


def write_aria2_input(items, path, failures=None):
    valid_items = []
    with open(path, "w", encoding="utf-8") as f:
        for item in items:
            try:
                url = str(item["url"]).replace("\n", "").replace("\r", "")
                if not url:
                    raise ValueError("Empty download URL")
                options = item_aria2_options(item)
            except Exception as error:
                if failures is None:
                    raise
                name = item.get("source") or item.get("url", "")
                failures.append(name)
                print(f"ERROR: Cannot configure aria2 download for {name}: {error}", file=sys.stderr)
                continue
            f.write(url + "\n")
            for key, value in options.items():
                f.write(f"  {key}={value}\n")
            valid_items.append(item)
    return valid_items


def download_output_path(item):
    options = item_aria2_options(item)
    filename = options.get("out") or filename_from_url(item["url"])
    if not options.get("out") and filename.lower().endswith((".php", ".asp", ".aspx", ".cgi", ".jsp")):
        values = dict(parse_qsl(urlsplit(item["url"]).query, keep_blank_values=True))
        filename = sanitize_filename(values.get("file") or values.get("filename") or "")
    if not valid_download_filename(filename) or os.path.basename(filename) != filename:
        return ""
    return os.path.join(options["dir"], filename)


def completed_download_exists(path):
    return os.path.isfile(path) and not os.path.islink(path) and os.path.getsize(path) > 0 and not os.path.exists(path + ".aria2")


def valid_download_content(path):
    with open(path, "rb") as file:
        header = file.read(4096)
    if path.lower().endswith(".msi") and not header.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return False
    prefix = header.lstrip()
    if prefix.startswith(b"\xef\xbb\xbf"):
        prefix = prefix[3:].lstrip()
    if not path.lower().endswith((".html", ".htm")):
        if re.match(rb"<!doctype\s+html\b|<html(?:\s|>)", prefix, re.IGNORECASE):
            return False
    return True


def quarantine_invalid_download(path):
    quarantine_directory = os.path.join(STAGING_DIRECTORY, ".invalid")
    if os.path.islink(quarantine_directory):
        raise ValueError(f"Invalid quarantine directory: {quarantine_directory}")
    os.makedirs(quarantine_directory, mode=0o700, exist_ok=True)
    if not os.path.isdir(quarantine_directory):
        raise ValueError(f"Invalid quarantine directory: {quarantine_directory}")
    fd, quarantine_path = tempfile.mkstemp(prefix=os.path.basename(path) + ".invalid-", dir=quarantine_directory)
    os.close(fd)
    try:
        os.replace(path, quarantine_path)
    except OSError:
        os.unlink(quarantine_path)
        raise
    return quarantine_path


def filename_has_version(filename, rules=()):
    if re.search(r"(?<!\d)\d+(?:\.\d+)+(?!\d)", filename):
        return True
    architecture = re.compile(r"(?:x86[-_]?64|amd64|aarch64|arm64|x64|x86|win(?:7|8|10|11|32|64)|windows(?:10|11)|w(?:32|64)|[36]2bit|64bit|ia32|i386|i686)", re.IGNORECASE)
    protected = [match.span() for match in architecture.finditer(filename)]
    patterns = [re.compile(str(rule), re.IGNORECASE) for rule in rules if rule]
    matched = [pattern for pattern in patterns if pattern.match(filename)]
    for token in re.finditer(r"\d+", filename):
        start, end = token.span()
        if any(start < right and end > left for left, right in protected):
            continue
        if len(token.group()) >= 4 and (start == 0 or not filename[start - 1].isalnum()) and (end == len(filename) or not filename[end].isalnum()):
            return True
        for pattern in matched:
            for index in range(start, end):
                digit = filename[index]
                changed = filename[:index] + str((int(digit) + 1) % 10) + filename[index + 1:]
                if pattern.match(changed):
                    return True
    return False


def replace_completed_download(source, destination):
    old = os.stat(destination, follow_symlinks=False)
    new = os.stat(source, follow_symlinks=False)
    if os.name != "nt" and (old.st_uid, old.st_gid) != (new.st_uid, new.st_gid):
        os.chown(source, old.st_uid, old.st_gid)
    os.chmod(source, stat.S_IMODE(old.st_mode))
    os.replace(source, destination)


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def update_completed_download(source, destination):
    if file_sha256(source) == file_sha256(destination):
        return False
    replace_completed_download(source, destination)
    return True


def plan_downloads(items, staging_directory, failures=None):
    planned = []
    staged = []
    destinations = set()
    for item in items:
        try:
            destination = download_output_path(item)
            if not destination:
                raise ValueError(f"Cannot determine download filename for {item.get('url', '')}")
            if destination in destinations:
                raise ValueError(f"Multiple downloads target the same file: {destination}")
            destinations.add(destination)
            if os.path.islink(destination):
                raise ValueError(f"Refusing to overwrite a symlink: {destination}")
            if os.path.lexists(destination) and not os.path.isfile(destination):
                raise ValueError(f"Output path is not a regular file: {destination}")
            filename = os.path.basename(destination)
            checksum = item.get("github_sha256", "")
            completed = completed_download_exists(destination)
            if checksum and completed and valid_download_content(destination):
                if file_sha256(destination) == checksum:
                    print(f"INFO: Skipped GitHub file (SHA-256 matched): {destination}")
                    continue
            versioned = filename_has_version(filename, item.get("cleanup_rules", ()))
            if versioned and not (checksum and completed):
                if completed and valid_download_content(destination):
                    print(f"INFO: Skipped existing versioned file: {destination}")
                    continue
                if DEBUG:
                    eprint("Download directly (versioned)", destination)
                planned.append(item)
                continue
            if checksum and completed and versioned:
                print(f"WARN: Existing GitHub file SHA-256 mismatch; replacing after verified download: {destination}", file=sys.stderr)
            if DEBUG:
                eprint("Download to staging", filename)
            staged_item = dict(item)
            staged_item["download_dir"] = staging_directory
            staged_item["out"] = filename
            staged_item["aria2"] = dict(item.get("aria2") or {}, out=filename)
            planned.append(staged_item)
            staged.append((staged_item, destination))
        except (ValueError, OSError, TypeError, re.error) as error:
            if failures is None:
                raise
            name = item.get("source") or item.get("url", "")
            failures.append(name)
            print(f"ERROR: Cannot plan download for {name}: {error}", file=sys.stderr)
    return planned, staged


def prepare_redirect_downloads(items, failures=None):
    prepared = []
    for item in items:
        try:
            if is_github_release_page(item["url"]):
                raise ValueError(f"GitHub release page is not a downloadable file: {item['url']}")
            if is_sourceforge_url(item["url"]):
                final_url, filename = sourceforge_resolve_redirect(item["url"], item.get("proxy"))
                resolved = dict(item)
                resolved["url"] = final_url
                if not resolved.get("out"):
                    resolved["out"] = filename
                if DEBUG:
                    eprint("SourceForge mirror", urlparse(final_url).hostname, "file", resolved["out"])
                prepared.append(resolved)
            elif is_documentfoundation_url(item["url"]) and valid_download_filename(filename_from_url(item["url"])):
                expected_name = filename_from_url(item["url"])
                final_url, filename = resolve_file_redirect(item["url"], item.get("proxy"), "LibreOffice")
                if filename != expected_name:
                    raise RuntimeError(f"LibreOffice mirror filename mismatch: expected {expected_name}, got {filename}")
                resolved = dict(item)
                resolved["url"] = final_url
                if not resolved.get("out"):
                    resolved["out"] = expected_name
                if DEBUG:
                    eprint("LibreOffice mirror", urlparse(final_url).hostname, "file", resolved["out"])
                prepared.append(resolved)
            elif not download_output_path(item):
                final_url, filename = resolve_file_redirect(item["url"], item.get("proxy"), "Download")
                resolved = dict(item)
                resolved["url"] = final_url
                resolved["out"] = filename
                if DEBUG:
                    eprint("Resolved download URL", final_url, "file", filename)
                prepared.append(resolved)
            else:
                prepared.append(item)
        except (RuntimeError, ValueError, OSError) as error:
            if failures is None:
                raise
            name = item.get("source") or item["url"]
            failures.append(name)
            print(f"ERROR: Cannot prepare download for {name}: {error}", file=sys.stderr)
    return prepared


def completed_root_files():
    candidates = []
    with os.scandir(workdir) as entries:
        for entry in entries:
            if entry.name.endswith(".aria2") or not entry.is_file(follow_symlinks=False):
                continue
            try:
                if completed_download_exists(entry.path) and valid_download_content(entry.path):
                    candidates.append((entry.name, entry.path))
            except OSError as error:
                print(f"WARN: Cannot inspect file {entry.path}: {error}", file=sys.stderr)
    return candidates


def release_version_family(filename):
    name = os.path.basename(filename).lower()
    dotted = re.search(r"(?<![a-z0-9])v?(\d+(?:\.\d+)+)(?![a-z0-9])", name)
    if dotted:
        matched = dotted.group(1)
        start, end = dotted.span(1)
    else:
        compact = re.search(r"(?<!\d)(\d{4,})(?!\d)", name)
        if not compact:
            return None
        matched = compact.group(1)
        start, end = compact.span(1)
    return name[:start] + "{version}" + name[end:], tuple(int(part) for part in matched.split("."))


def cleanup_version_sets(candidates, patterns, triggered_name=None):
    keep = set()
    delete = set()
    trigger_identity = release_version_family(triggered_name) if triggered_name else None
    if triggered_name and trigger_identity is None:
        return keep, delete
    for pattern in patterns:
        if triggered_name and not pattern.search(triggered_name):
            continue
        families = {}
        for name, path in candidates:
            if not pattern.search(name):
                continue
            identity = release_version_family(name)
            if identity is None:
                keep.add(path)
                continue
            family, version = identity
            if trigger_identity and family != trigger_identity[0]:
                continue
            families.setdefault(family, []).append((normalize_version_key(version), path))
        for members in families.values():
            newest = max(version for version, _ in members)
            for version, path in members:
                (delete if version < newest else keep).add(path)
    return keep, delete


def clear_old_for_download(item, downloaded_path, protected_paths=()):
    patterns = [re.compile(str(rule), re.IGNORECASE) for rule in item.get("cleanup_rules", ()) if rule]
    if not patterns:
        return 0
    candidates = completed_root_files()
    keep, remove = cleanup_version_sets(candidates, patterns, os.path.basename(downloaded_path))
    deleted = 0
    for path in natsorted(remove - keep - set(protected_paths), key=sort_key):
        if not completed_download_exists(path):
            continue
        os.remove(path)
        print(f"INFO: Removed older file: {path}")
        deleted += 1
    return deleted


def finalize_completed_download(item, source_path, destination, active_paths):
    if source_path and destination and source_path != destination:
        if os.path.islink(destination) or (os.path.lexists(destination) and not os.path.isfile(destination)):
            raise ValueError(f"Invalid destination path: {destination}")
        if os.path.isfile(destination):
            if update_completed_download(source_path, destination):
                print(f"INFO: Updated (SHA-256 changed): {destination}")
            else:
                os.remove(source_path)
                print(f"INFO: Unchanged (SHA-256 matched): {destination}")
        else:
            os.replace(source_path, destination)
            print(f"INFO: Downloaded: {destination}")
    elif destination:
        print(f"INFO: Downloaded: {destination}")
    if destination:
        active_paths.discard(destination)
        clear_old_for_download(item, destination, active_paths)


def download_one(item, destination, active_paths, finish_lock, output_lock):
    if not destination:
        return False, "Cannot determine download destination"
    try:
        with exclusive_lock(os.path.realpath(__file__), ("file:" + os.path.realpath(destination),)):
            source_path = download_output_path(item)
            if (source_path == destination and completed_download_exists(destination)
                    and valid_download_content(destination)
                    and (not item.get("github_sha256") or file_sha256(destination) == item["github_sha256"])):
                with finish_lock:
                    active_paths.discard(destination)
                print(f"INFO: Skipped already completed download: {destination}")
                return True, ""
            return download_one_locked(item, destination, active_paths, finish_lock, output_lock)
    except (OSError, RuntimeError, ValueError, TypeError) as error:
        with output_lock:
            print(f"ERROR: Cannot lock download for {destination}: {error}", file=sys.stderr)
        return False, f"{destination}: {error}"


def download_one_locked(item, destination, active_paths, finish_lock, output_lock):
    label = os.path.basename(destination) if destination else filename_from_url(item["url"]) or "download"
    try:
        source_path = download_output_path(item)
        options = item_aria2_options(item)
        if source_path and "out" not in options:
            options["out"] = os.path.basename(source_path)
        if source_path and completed_download_exists(source_path) and not valid_download_content(source_path):
            quarantine_path = quarantine_invalid_download(source_path)
            print(f"WARN: Invalid download moved to quarantine: {quarantine_path}", file=sys.stderr)
        if source_path and destination and source_path != destination:
            if os.path.islink(source_path) or os.path.islink(source_path + ".aria2"):
                raise ValueError(f"Refusing to use a symlink in staging: {source_path}")
            if os.path.lexists(source_path) and not os.path.isfile(source_path):
                raise ValueError(f"Staging output is not a regular file: {source_path}")
            if os.path.isfile(source_path) and not os.path.exists(source_path + ".aria2"):
                options["allow-overwrite"] = "true"
                print(f"WARN: Staged file has no aria2 control file; restarting download: {source_path}", file=sys.stderr)
        command = [
            "aria2c",
            "--no-conf=true",
            "--summary-interval=30",
            "--console-log-level=notice",
            "--download-result=full",
        ]
        command.extend(f"--{key}={value}" for key, value in options.items())
        command.extend(("--", str(item["url"])))
        if DEBUG:
            with output_lock:
                eprint("aria2 command", command)
        with subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            bufsize=1,
            env=clean_proxy_env(os.environ),
        ) as process:
            for line in process.stdout:
                with output_lock:
                    print(f"[{label}] {line}", end="", flush=True)
            returncode = process.wait()
        if returncode != 0:
            raise RuntimeError(f"aria2c exited with code {returncode}")
        if source_path and not completed_download_exists(source_path):
            raise RuntimeError(f"Download did not produce a complete file: {source_path}")
        if source_path and not valid_download_content(source_path):
            quarantine_path = quarantine_invalid_download(source_path)
            raise RuntimeError(f"Downloaded file has invalid content (HTML or MSI signature); moved to {quarantine_path}")
        if source_path and item.get("github_sha256") and file_sha256(source_path) != item["github_sha256"]:
            quarantine_path = quarantine_invalid_download(source_path)
            raise RuntimeError(f"GitHub SHA-256 mismatch; moved to {quarantine_path}")
        with finish_lock:
            finalize_completed_download(item, source_path, destination, active_paths)
        return True, ""
    except (OSError, RuntimeError, ValueError, TypeError, re.error) as error:
        with output_lock:
            print(f"ERROR: Download failed for {label}: {error}", file=sys.stderr)
        return False, f"{label}: {error}"


def download_all(items, failures=None):
    if not items:
        print("WARN: No download URLs found; old files will not be removed", file=sys.stderr)
        return False
    items = prepare_redirect_downloads(items, failures)
    items = prepare_github_checksums(items)
    if not items:
        print("ERROR: No usable download URLs remain", file=sys.stderr)
        return False
    os.makedirs(workdir, exist_ok=True)
    if os.path.islink(STAGING_DIRECTORY):
        raise ValueError(f"Staging directory must not be a symlink: {STAGING_DIRECTORY}")
    os.makedirs(STAGING_DIRECTORY, exist_ok=True)
    if os.name != "nt":
        os.chmod(STAGING_DIRECTORY, 0o777)
    successful = True
    items, staged = plan_downloads(items, STAGING_DIRECTORY, failures)
    if not items:
        return not failures
    staged_destinations = {id(item): destination for item, destination in staged}
    destinations = {id(item): staged_destinations.get(id(item), download_output_path(item)) for item in items}
    active_paths = {path for path in destinations.values() if path}
    finish_lock = Lock()
    output_lock = Lock()
    print(f"INFO: Attempting {len(items)} download(s) with aria2")
    with ThreadPoolExecutor(max_workers=max(1, max_concurrent_downloads(items))) as executor:
        futures = {
            executor.submit(download_one, item, destinations[id(item)], active_paths, finish_lock, output_lock): item
            for item in items
        }
        for future in as_completed(futures):
            try:
                ok, error_message = future.result()
            except Exception as error:
                ok, error_message = False, f"Unexpected download worker failure: {error}"
                print(f"ERROR: {error_message}", file=sys.stderr)
            if not ok:
                successful = False
                if failures is not None:
                    failures.append(error_message)
    rename_files()
    return successful and not failures


def rename_files():
    for root, _, files in os.walk(workdir):
        for file in files:
            if "?" in file:
                new_name = file.split("?")[0]
                old_file_path = os.path.join(root, file)
                new_file_path = os.path.join(root, new_name)
                try:
                    os.rename(old_file_path, new_file_path)
                    if DEBUG:
                        eprint(f"Renamed: {old_file_path} to {new_file_path}")
                except OSError as e:
                    eprint(f"Failed to rename {old_file_path} to {new_file_path}. Error: {e}")


def create_plugin(filename="plugin"):
    file_name = filename if filename.endswith(".json") else filename + ".json"
    os.makedirs(plugins_directory, exist_ok=True)
    file_path = os.path.join(plugins_directory, file_name)
    if os.path.exists(file_path):
        print("ERROR file already exists", file_path)
        sys.exit(1)
    data = r'''{
  // type: 0 - direct URL; 1 - HTML/GitHub/SourceForge; 2 - URL from JSON; 3 - recursive directory search.
  "type": 1,

  // url: search page, GitHub Releases URL, direct file URL for type=0, or JSON endpoint for type=2.
  "url": "https://github.com/owner/repo/releases/latest",

  // rules: list of regular expressions for filenames. The basename of each discovered URL is checked using re.match().
  "rules": [
    ".*linux.*amd64.*\\.tar\\.gz$"
  ],

  "search_regex": "^Blender[0-9]+\\.[0-9]+/$",

  "search_tail": 1,

  "max_depth": 3,
  "max_pages": 100,

  // path: used only for type=2. List elements are dictionary keys or list indices.
  "path": ["assets", 0, "browser_download_url"],

  // tail: number of last URLs to select after natural sorting. 1 - latest only, 0 - all discovered URLs.
  "tail": 1,

  // out: override the local filename. If empty, the filename is taken from the URL or the final HTTP redirect URL.
  "out": "",

  // proxy: HTTP proxy for this plugin only. An empty string disables the proxy.
  // Simple format: "http://user:pass@proxy.example.org:8080".
  // Extended format: {"all": "http://proxy:8080", "no_proxy": "localhost,127.0.0.1"}.
  "proxy": "",

  // aria2: optional download settings for files managed by this plugin.
  "aria2": {
    "split": 4,
    "max_connection_per_server": 4,
    "max_tries": 3,
    "retry_wait": 2,
    "connect_timeout": 10,
    "timeout": 10,
    "max_concurrent_downloads": 4,
    "conditional_get": false,
    "content_disposition_default_utf8": true
  }
}
'''
    with open(file_path, "w", encoding="utf-8") as outfile:
        outfile.write(data)
    print("New plugin created", file_path)
    editor = os.environ.get("EDITOR")
    if editor:
        try:
            subprocess.run([editor, file_path], env=os.environ)
        except Exception:
            pass
    sys.exit(0)


def edit_plugin(filename="plugin"):
    file_name = filename if filename.endswith(".json") else filename + ".json"
    file_path = os.path.join(plugins_directory, file_name)
    if not os.path.exists(file_path):
        create_plugin(filename)
    editor = os.environ.get("EDITOR")
    if editor:
        try:
            subprocess.run([editor, file_path], env=os.environ)
        except Exception:
            pass
    sys.exit(0)


def get_item(data, path):
    response = data
    for item in path:
        response = response[item]
    return response


def flatten_urls(value):
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        result = []
        for item in value:
            result.extend(flatten_urls(item))
        return result
    return [str(value)]


def get_from_json(target):
    link = target.get("url", "")
    try:
        response = request_text(link, target)
        data = json.loads(response)
        path = target.get("path", [])
        return flatten_urls(get_item(data, path))
    except Exception as e:
        raise RuntimeError(f"Cannot parse JSON from {link}: {e}") from e


def run_search(plugins_arg, initial_failures=None):
    failures = list(initial_failures or [])
    if isinstance(plugins_arg, str):
        selected_plugins = load_plugin(plugins_directory, plugins_arg, failures)
    else:
        selected_plugins = plugins_arg
    targets = []
    github_targets = []
    download_list = []
    has_targets = False
    for target in selected_plugins:
        if not isinstance(target, dict):
            continue
        has_targets = True
        name = target.get("_plugin_name") or target.get("url", "")
        try:
            target_type = target.get("type", 1)
            if target_type == 0:
                url = target.get("url", "")
                if url:
                    download_list.append(download_item(url, target))
            elif target_type == 2:
                for url in get_from_json(target):
                    if not url:
                        continue
                    try:
                        download_list.append(download_item(url, target))
                    except Exception as error:
                        failures.append(f"{name}: {url}")
                        print(f"ERROR: Cannot prepare URL {url} from {name}: {error}", file=sys.stderr)
            elif target_type == 3:
                targets.append(target)
            else:
                if "github.com" not in target.get("url", ""):
                    targets.append(target)
                else:
                    github_targets.append(target)
        except Exception as error:
            failures.append(name)
            print(f"ERROR: Cannot prepare plugin {name}: {error}", file=sys.stderr)
    download_list += get_urls(targets, failures)
    download_list += get_urls(github_targets, failures)
    print([urlsplit(item["url"])._replace(query="").geturl() if is_sourceforge_url(item["url"]) else item["url"] for item in download_list])
    if not has_targets:
        if failures:
            print(f"ERROR: Failed plugin(s) ({len(failures)}): {', '.join(failures)}", file=sys.stderr)
        return not failures
    success = download_all(download_list, failures)
    if failures:
        print(f"ERROR: Failed plugins or downloads ({len(failures)}): {', '.join(failures)}; only completed downloads trigger cleanup", file=sys.stderr)
    return success and not failures


def extract_version_key(s):
    identity = release_version_family(s)
    return identity[1] if identity else None


def normalize_version_key(parts, width=8):
    if parts is None:
        return None
    if len(parts) >= width:
        return parts[:width]
    return parts + tuple(0 for _ in range(width - len(parts)))


def clear_old(plugins_arg):
    selected_plugins = plugins_arg if isinstance(plugins_arg, list) else load_plugin(plugins_directory, plugins_arg)
    candidates = completed_root_files()
    delete_set = set()
    keep_set = set()
    for target in selected_plugins:
        if not isinstance(target, dict):
            continue
        try:
            patterns = [re.compile(str(rule), re.IGNORECASE) for rule in target.get("rules", []) if rule]
            keep, delete = cleanup_version_sets(candidates, patterns)
            keep_set.update(keep)
            delete_set.update(delete)
        except (TypeError, ValueError, re.error) as error:
            print(f"ERROR: Cannot evaluate cleanup rules for {target.get('_plugin_name', target.get('url', 'plugin'))}: {error}", file=sys.stderr)
    final_delete = delete_set - keep_set
    print("Will be deleted", final_delete)
    if DEBUG:
        eprint("clear_old keep", keep_set)
        eprint("clear_old delete", final_delete)
    for path in natsorted(final_delete, key=sort_key):
        if not completed_download_exists(path) or not valid_download_content(path):
            continue
        try:
            os.remove(path)
            print(f"INFO: Removed older file: {path}")
        except OSError as error:
            print(f"ERROR: Cannot remove older file {path}: {error}", file=sys.stderr)


def list_plugins(folder_path):
    final = []
    if not os.path.isdir(folder_path):
        return
    for file_name in os.listdir(folder_path):
        if file_name.endswith(".json"):
            final.append(file_name.replace(".json", ""))
    for f in natsorted(final):
        print(f)


def run_lock_names(args):
    if args.run is not None and all(args.run):
        return sorted({name.removesuffix(".json") for group in args.run for name in group})
    if args.run is None and (args.create is not None or args.edit is not None or args.list):
        return ["__maintenance__"]
    if not os.path.isdir(plugins_directory):
        return []
    with os.scandir(plugins_directory) as entries:
        return sorted(entry.name[:-5] for entry in entries if entry.is_file() and entry.name.endswith(".json"))


def run_log_file(args, plugin_names):
    if args.log_file:
        return args.log_file
    directory = os.path.dirname(os.path.realpath(__file__))
    if args.run is None or any(not group for group in args.run):
        return os.path.join(directory, "autodownload.log")
    label = "__".join(plugin_names)
    safe_label = re.sub(r"[^A-Za-z0-9_.-]", "_", label)
    if not safe_label or len(safe_label) > 80 or safe_label != label:
        suffix = hashlib.sha256(label.encode("utf-8", errors="surrogateescape")).hexdigest()[:10]
        safe_label = f"{safe_label[:64] or 'plugins'}-{suffix}"
    return os.path.join(directory, f"autodownload.{safe_label}.log")


def run(args):
    global DEBUG
    if args.debug:
        DEBUG = True
    plugin_failures = []
    plugins = load_plugins(plugins_directory, plugin_failures)
    if args.create is not None:
        create_plugin(args.create)
    elif args.edit is not None:
        edit_plugin(args.edit)
    elif args.clear:
        clear_old(plugins)
    elif args.run is not None:
        failures = []
        if any(not group for group in args.run):
            selected = plugins
            failures = plugin_failures
        else:
            selected = []
            for name in dict.fromkeys(name for group in args.run for name in group):
                selected.extend(load_plugin(plugins_directory, name, failures))
        if not run_search(selected, failures):
            sys.exit(1)
    elif args.list:
        list_plugins(plugins_directory)
    elif args.rename:
        rename_files()
    else:
        if not run_search(plugins, plugin_failures):
            sys.exit(1)


PLUGIN_HELP = """Download directory:
  AUTODOWNLOAD_DIR  Destination directory path (absolute or relative).
                    If unset, defaults to /mnt/hdd1/shares/autodownloads/.
                    Relative paths are resolved against the current working directory.
                    On Windows, AUTODOWNLOAD_DIR must be explicitly specified.
                    Windows: C:\\Downloads, D:/Downloads, \\\\server\\share\\Downloads.
                    Linux: /mnt/hdd1/shares/autodownloads or ~/Downloads.
                    Paths are interpreted by the current operating system; Windows paths
                    cannot be used on Linux without the corresponding mount.
                    .autodownload-stage/ is created in the same directory.
                    Linux example: AUTODOWNLOAD_DIR=/mnt/hdd1/shares/autodownloads ./autodownload.py --run
                    Windows example (PowerShell): $env:AUTODOWNLOAD_DIR = 'D:\\Downloads'
                    On Windows and Linux, aria2c and curl must be available in PATH.

Operating modes:
  ./autodownload.py                          Download updates for all plugins
  ./autodownload.py --run                    Same as above
  ./autodownload.py --run NAME               Run only plugins/NAME.json
  ./autodownload.py --run NAME1 NAME2        Run multiple selected plugins
  ./autodownload.py --run NAME1 --run NAME2  Same as above, using repeated --run options
  Different plugins run concurrently in separate processes.
  If at least one plugin overlaps, the second invocation waits for the first
  to finish instead of failing with a lock error.
  Overlapping files are protected by a separate download lock.
  --run NAME creates a separate autodownload.NAME.log; a general run
  uses autodownload.log. --log-file specifies an explicit log file path.
  Concurrent writes to the same explicitly specified log file are serialized.
  Linux: Unix sockets and flock; Windows: system-wide named mutexes.
  ./autodownload.py --list                   List plugin names
  ./autodownload.py --create [NAME]          Create a JSON template (default: plugin)
  ./autodownload.py --edit [NAME]            Open JSON using $EDITOR (if set); create it if missing
  ./autodownload.py --clear                  Remove older versions according to rules
                Only completed versioned files in the main directory are removed,
                separately for each filename family and architecture.
                Unversioned files, .aria2 files, and .autodownload-stage are not removed.
  ./autodownload.py --rename                 Remove the filename portion after the ? character
  ./autodownload.py --version                Display the script version
  ./autodownload.py --run --debug            Enable debugging and verbose logging
  ./autodownload.py --run --log-file PATH    Use a separate log file

Format of plugins/NAME.json (// and /* ... */ comments are supported):
  type          Source type (default: 1):
                0 - direct file URL;
                1 - links from HTML, GitHub Releases, or SourceForge;
                2 - URL from JSON using path;
                3 - recursive directory traversal using two regular expressions.
  url           File, HTML page, or JSON API URL.
  rules         Array of regular expressions for filenames (case-insensitive re.match).
                Used for types 1 and 3 and for removing older versions.
  tail          Select the last N discovered URLs after natural sorting; 0 - all.
  path          For type=2: sequence of JSON keys and/or array indices.
  out           Override the local filename; if empty, use the filename from the URL
                or the final HTTP redirect URL (using curl).
  proxy         Plugin-specific proxy: a URL string or an object
                with all, http, https, ftp, and no_proxy keys.
  aria2         Object containing aria2c settings for downloaded files.

Additional fields for type=3:
  search_regex  Required regular expression for directory discovery (re.search).
                The directory name and path are checked at each depth.
  search_tail   Number of last matching directories to scan at each level;
                0 - all (default: 0).
                Links with ?stats= and ?mirrorlist= are excluded from file discovery.
  max_depth     Maximum traversal depth from the initial URL (default: 3).
  max_pages     Maximum number of HTML pages to read (default: 100).

Advanced plugin fields:
  request_connect_timeout  Connection timeout during link discovery, seconds (10).
  request_read_timeout     HTML/JSON read timeout, seconds (45).
  request_retries          Number of HTTP request retries (2).
  request_retry_wait       Initial retry delay, seconds (2).
  sourceforge_mirror       SourceForge mirror name for the use_mirror parameter.
  sourceforge_platform     Does not constrain latest/download; a direct URL
                           for the desired platform or a rules filter is required.

Fields of the aria2 object (hyphenated names are also supported):
  split / s                     Number of parts per file.
  max_connection_per_server / x Number of connections per server.
  max_tries                     Maximum number of attempts.
  retry_wait                    Interval between attempts, seconds.
  connect_timeout               Connection timeout, seconds.
  timeout                       Data transfer timeout, seconds.
  max_concurrent_downloads / j  Number of simultaneous downloads.
  auto_save_interval            .aria2 control file save interval in the staging directory.
  min_split_size                Minimum part size.
  file_allocation               Disk space allocation method.
  lowest_speed_limit            Minimum download speed limit.
  user_agent / referer          HTTP User-Agent and Referer.
  conditional_get               Conditional HTTP request.
  content_disposition_default_utf8  UTF-8 for Content-Disposition.
  no_want_digest_header         Do not request the Digest header.
  http_accept_gzip              Accept compressed HTTP responses.
  out                           Override the output filename.

Download logic:
  Versioned files are downloaded by aria2c to the destination directory; existing
  completed versions are skipped (MSI files are checked by signature).
  Invalid MSI files and HTML pages returned instead of files are stored in
  .autodownload-stage/.invalid/ and are not treated as successful downloads.
  The output filename is always explicitly set for aria2c to prevent redirects
  from creating unintended files (for example, GitHub tags instead of EXE files).
  GitHub Releases pages and redirects to them are rejected as non-file URLs.
  Unversioned files are downloaded to the persistent .autodownload-stage/ directory,
  then compared using SHA-256 and replaced only
  if their contents have changed. For GitHub Releases, the SHA-256 digest
  is requested through the API; matching local files are skipped without downloading.
  If a digest is available, downloaded file integrity is verified using SHA-256.
  If the digest is missing or the API is unavailable, the previous logic applies.
  If the original direct URL does not contain a filename
  (for example, AIMP ?do=download.file), curl determines the final URL and filename.
  For URLs with opaque paths (for example, GitHub assets for Calibre),
  the filename is obtained from Content-Disposition or the rscd and
  response-content-disposition parameters. Files are downloaded only through aria2c.
  After a successful download, cleanup is performed according to the corresponding rules.
  Each run overwrites its log file at startup after acquiring the file lock.
  Separate log files do not interfere with concurrent runs.
"""
PLUGIN_HELP += "\nDEFAULT_ARIA2: " + ", ".join(f"{key}={value}" for key, value in DEFAULT_ARIA2.items()) + "\n"

def main():
    parser = argparse.ArgumentParser(
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Download and update files using JSON plugins and aria2c.",
        epilog=PLUGIN_HELP,
    )
    parser.add_argument("-h", "--help", action="help", help="Show operating modes and plugin fields")
    parser.add_argument("--version", action="version", version=f"%(prog)s {SCRIPT_VERSION}")
    parser.add_argument("--create", nargs="?", const="plugin", help="Create a plugin")
    parser.add_argument("--edit", nargs="?", const="plugin", help="Edit a plugin")
    parser.add_argument("--clear", action="store_true", help="Remove older files")
    parser.add_argument("--run", nargs="*", action="append", metavar="NAME", help="Run all or selected plugins")
    parser.add_argument("--list", action="store_true", help="List plugins")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--rename", action="store_true", help="Rename files containing ? in their names")
    parser.add_argument(
        "--log-file",
        default=None,
        help="Log file path (defaults to a separate log file for --run NAME)",
    )
    args = parser.parse_args()
    try:
        configured_dir = os.environ.get("AUTODOWNLOAD_DIR", "").strip()
        if os.name == "nt" and not configured_dir and not (args.list or args.create is not None or args.edit is not None):
            raise RuntimeError("Set AUTODOWNLOAD_DIR to a Windows path; the default directory is Linux-specific")
        if os.name != "nt" and (ntpath.splitdrive(configured_dir)[0] or configured_dir.startswith("\\\\")):
            raise RuntimeError("AUTODOWNLOAD_DIR contains a Windows path; use a mounted Linux path instead")
        names = run_lock_names(args)
        scopes = ["plugin:" + name for name in names]
        if args.run is None and (args.create is not None or args.edit is not None or args.list):
            scopes = ["maintenance"]
        with exclusive_lock(os.path.realpath(__file__), scopes):
            with capture_log(run_log_file(args, names)):
                try:
                    run(args)
                except (requests.RequestException, RuntimeError, ValueError, OSError) as error:
                    print(f"ERROR: {error}", file=sys.stderr)
                    sys.exit(1)
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except OSError as error:
        print(f"ERROR: Cannot write log file: {error}", file=sys.stderr)
        sys.exit(1)
