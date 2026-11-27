#!/usr/bin/python3

import argparse
from contextlib import ExitStack, contextmanager, nullcontext
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque
from datetime import datetime
import ctypes
from ctypes import wintypes
import hashlib
import json
import ntpath
import os
import re
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
SCRIPT_VERSION = "2026.11.28.3"
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
        if self.logfile is not None:
            self.logfile.write(safe_text)
        return len(text)

    def flush(self):
        self.terminal.flush()
        if self.logfile is not None:
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
    lock = windows_named_lock(path, ("log",)) if path and os.name == "nt" else nullcontext()
    with lock:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600) if path else None
        with (os.fdopen(fd, "w", encoding="utf-8", buffering=1) if fd is not None else nullcontext()) as logfile:
            if logfile is not None:
                if os.name != "nt":
                    fcntl.flock(fd, fcntl.LOCK_EX)
                os.ftruncate(fd, 0)
                os.lseek(fd, 0, os.SEEK_SET)
            original_stdout, original_stderr = sys.stdout, sys.stderr
            sys.stdout = TeeStream(original_stdout, logfile)
            sys.stderr = TeeStream(original_stderr, logfile)
            try:
                print(f"INFO: Run started at {datetime.now().astimezone().isoformat(timespec='seconds')}")
                if logfile is not None:
                    print(f"INFO: Log file: {path}")
                print(f"INFO: Script version: {SCRIPT_VERSION}")
                print(f"INFO: Download directory: {workdir}")
                yield
            finally:
                sys.stdout.flush()
                sys.stderr.flush()
                sys.stdout, sys.stderr = original_stdout, original_stderr


@contextmanager
def file_lock(path):
    lock_path = path + ".lock"
    try:
        fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        print(f"INFO: Skipped locked file: {path} ({lock_path})")
        yield False
        return
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as lock_file:
            lock_file.write(f"PID={os.getpid()}\n")
        yield True
    finally:
        os.unlink(lock_path)


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
    except (OSError, UnicodeError, ValueError, re.error) as error:
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
    headers = {"User-Agent": http_user_agent(target, BROWSER_USER_AGENT)}
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


def is_github_url(url):
    return (urlsplit(str(url)).hostname or "").lower() in ("github.com", "api.github.com")


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


def is_github_release_page(url):
    parsed = urlsplit(url)
    return (parsed.hostname or "").lower() == "github.com" and re.fullmatch(
        r"/[^/]+/[^/]+/releases(?:/(?:latest|tag/[^/]+))?/?", parsed.path
    ) is not None


def resolve_file_redirect(url, proxy_config, provider, user_agent=""):
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
    if user_agent:
        command.extend(("--user-agent", user_agent))
    proxy = proxy_config or {}
    proxy_url = proxy.get(urlsplit(url).scheme) or proxy.get("all")
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
    filename = download_filename_from_url(final_url)
    parsed_final = urlsplit(final_url)
    if is_github_release_page(final_url):
        raise RuntimeError(f"{provider} redirect returned a GitHub release page, not a file: {final_url}")
    if parsed_final.scheme != "https" or not valid_download_filename(filename):
        raise RuntimeError(f"{provider} redirect returned an invalid file URL: {final_url}")
    if filename.lower().endswith((".meta4", ".metalink")):
        raise RuntimeError(f"{provider} redirect returned a Metalink document instead of a file: {final_url}")
    return final_url, filename


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
        "resolve_redirect": target.get("resolve_redirect", False),
    }


def select_tail(urls, tail, rules=()):
    unique = natsorted(sorted(set(urls)), key=sort_key)
    unique = natsorted(unique, key=lambda url: sort_key(parse_release_filename(download_filename_from_url(url), rules)[0] or url))
    try:
        tail_value = int(tail)
    except Exception:
        tail_value = 0
    if tail_value > 0:
        return unique[-tail_value:]
    return unique


def github_api_url(link):
    parsed = urlparse(link)
    host = (parsed.hostname or "").lower()
    if host == "api.github.com":
        return link
    if host == "github.com":
        parts = [p for p in parsed.path.strip("/").split("/") if p]
        if len(parts) >= 2:
            owner = parts[0]
            repo = parts[1]
            rest = parts[2:]
            if rest[:2] == ["releases", "latest"]:
                return f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
            if len(rest) == 3 and rest[:2] == ["releases", "tag"]:
                return f"https://api.github.com/repos/{owner}/{repo}/releases/tags/{quote(unquote(rest[2]), safe='')}"
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
                data = json.loads(request_text(endpoint, {"proxy": item.get("proxy"), "aria2": item.get("aria2")}))
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
    target_type = target.get("type", 1)
    rules = target.get("rules", [])
    github_digests = {}
    if target_type == 0:
        urls = [link]
    elif target_type == 2:
        urls = get_from_json(target)
    elif target_type == 3:
        urls = recursive_file_links(link, target, failures)
    elif is_github_url(link):
        urls = [url for url in github_release_assets(link, target, github_digests) if checkurl(url, rules)]
    elif is_sourceforge_url(link):
        if urlparse(link).path.rstrip("/").endswith("/files/latest/download"):
            item = download_item(link, target)
            resolved = resolve_download(item)
            if not checkurl(item["url"], rules, filename=resolved["_redirect_filename"]):
                raise RuntimeError(f"No downloadable files match the rules for {link}")
            return [resolved]
        if valid_download_filename(filename_from_url(link)):
            urls = [link] if checkurl(link, rules) else []
        else:
            urls = [url for url in sourceforge_file_links(link, target) if checkurl(url, rules)]
    else:
        urls = [url for url in find_all_links(link, target) if checkurl(url, rules)]
    if target_type not in (0, 2):
        if not urls:
            raise RuntimeError(f"No downloadable files match the rules for {link}")
        urls = select_tail(urls, target.get("tail", 0), rules)
    if DEBUG:
        eprint("get_urls", urls)
    result = []
    for url in urls:
        if not url:
            continue
        try:
            item = download_item(url, target)
            if url in github_digests:
                item["github_sha256"] = github_digests[url]
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
            discovered = get_target_downloads(target, failures)
            if target.get("type", 1) in (0, 2):
                final.extend(discovered)
            else:
                seen = set()
                for item in discovered:
                    key = (item["url"], item.get("out", ""), json.dumps(item["proxy"], sort_keys=True))
                    if key not in seen:
                        seen.add(key)
                        final.append(item)
        except Exception as error:
            if failures is None:
                raise
            name = target.get("_plugin_name") or target.get("url", "")
            failures.append(name)
            print(f"ERROR: Cannot discover downloads for {name}: {error}", file=sys.stderr)
    return final


def aria2_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def aria2_option(options, aliases, default=None):
    for alias in aliases:
        if alias in options and options[alias] is not None:
            return options[alias]
    return default


def http_user_agent(item, default=""):
    return aria2_option(item.get("aria2") or {}, ("user-agent", "user_agent"), default)


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
        options["referer"] = aria2_option(custom, ("referer",), "*")
        options["min-split-size"] = aria2_option(custom, ("min_split_size", "min-split-size"), "5M")

    user_agent = http_user_agent(item, SOURCEFORGE_USER_AGENT if is_sourceforge else "")
    if user_agent:
        options["user-agent"] = user_agent

    for src, dst in (
        ("min_split_size", "min-split-size"),
        ("min-split-size", "min-split-size"),
        ("file_allocation", "file-allocation"),
        ("file-allocation", "file-allocation"),
        ("lowest_speed_limit", "lowest-speed-limit"),
        ("lowest-speed-limit", "lowest-speed-limit"),
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


def download_filename_from_url(url):
    filename = filename_from_url(url)
    if filename.lower().endswith((".php", ".asp", ".aspx", ".cgi", ".jsp")):
        values = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
        filename = sanitize_filename(values.get("file") or values.get("filename") or "")
    return filename


def download_output_path(item):
    options = item_aria2_options(item)
    filename = options.get("out") or download_filename_from_url(item["url"])
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
            if filename.lower().endswith(".lock"):
                raise ValueError(f"Reserved lock filename: {destination}")
            if os.path.lexists(destination + ".lock"):
                print(f"INFO: Skipped locked file: {destination} ({destination}.lock)")
                continue
            checksum = item.get("github_sha256", "")
            completed = completed_download_exists(destination)
            if checksum and completed and valid_download_content(destination):
                if file_sha256(destination) == checksum:
                    print(f"INFO: Skipped GitHub file (SHA-256 matched): {destination}")
                    continue
            _, _, version = parse_release_filename(filename, item.get("cleanup_rules", ()))
            versioned = version is not None
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


def resolve_download(item):
    url = item["url"]
    if is_github_release_page(url):
        raise ValueError(f"GitHub release page is not a downloadable file: {url}")
    if item.get("_redirect_filename"):
        return item
    sourceforge = is_sourceforge_url(url)
    explicit = item.get("resolve_redirect")
    if not sourceforge and not explicit and download_output_path(item):
        return item
    provider = "SourceForge" if sourceforge else "Download"
    user_agent = http_user_agent(item, SOURCEFORGE_USER_AGENT if sourceforge else BROWSER_USER_AGENT)
    final_url, filename = resolve_file_redirect(url, item.get("proxy"), provider, user_agent)
    expected_name = download_filename_from_url(url)
    if explicit and valid_download_filename(expected_name) and filename != expected_name:
        raise RuntimeError(f"Redirect filename mismatch: expected {expected_name}, got {filename}")
    resolved = dict(item, url=final_url, _redirect_filename=filename)
    if not resolved.get("out"):
        resolved["out"] = filename
    if DEBUG:
        eprint("Resolved download URL", final_url, "file", resolved["out"])
    return resolved


def prepare_redirect_downloads(items, failures=None):
    prepared = []
    for item in items:
        try:
            prepared.append(resolve_download(item))
        except (RuntimeError, ValueError, OSError) as error:
            if failures is None:
                raise
            name = item.get("source") or item["url"]
            failures.append(name)
            print(f"ERROR: Cannot prepare download for {name}: {error}", file=sys.stderr)
    return prepared


def completed_root_files(owned_path=None):
    candidates = []
    with os.scandir(workdir) as entries:
        for entry in entries:
            if entry.name.lower().endswith((".aria2", ".lock")) or not entry.is_file(follow_symlinks=False):
                continue
            if entry.path != owned_path and os.path.lexists(entry.path + ".lock"):
                continue
            try:
                if completed_download_exists(entry.path) and valid_download_content(entry.path):
                    candidates.append((entry.name, entry.path))
            except OSError as error:
                print(f"WARN: Cannot inspect file {entry.path}: {error}", file=sys.stderr)
    return candidates


def normalize_release_filename(filename):
    name = os.path.basename(filename).lower()
    metadata = re.search(r"[-_.](\d{8})[-_.]([0-9a-f]{7,40})(?=\.[a-z0-9]*[a-z][a-z0-9]*(?:\.[a-z0-9]*[a-z][a-z0-9]*)*$)", name)
    if not metadata or not re.search(r"[a-f]", metadata.group(2)):
        return name
    if not re.search(r"(?<![a-z0-9])v?\d+(?:\.\d+)+(?![a-z0-9])", name[:metadata.start()]):
        return name
    try:
        datetime.strptime(metadata.group(1), "%Y%m%d")
    except ValueError:
        return name
    return name[:metadata.start()] + name[metadata.end():]


def parse_release_filename(filename, rules=()):
    name = normalize_release_filename(filename)
    stem = os.path.splitext(name)[0]
    architecture = re.compile(r"(?:x86[-_]?64|amd64|aarch64|arm64|x64|x86|win(?:7|8|10|11|32|64)|windows(?:10|11)|w(?:32|64)|[36]2bit|64bit|ia32|i386|i686)", re.IGNORECASE)
    protected = [match.span() for match in architecture.finditer(stem)]
    dotted = [match for match in re.finditer(r"(?<!\d)\d+(?:\.\d+)+(?!\d)", stem)
              if not any(match.start() < right and match.end() > left for left, right in protected)]
    if len(dotted) > 1:
        return name, None, None
    if dotted:
        token = dotted[0]
    else:
        patterns = [rule if isinstance(rule, re.Pattern) else re.compile(str(rule), re.IGNORECASE) for rule in rules if rule]
        original = os.path.basename(filename).lower()
        matched = [pattern for pattern in patterns if pattern.match(original)]
        candidates = []
        for match in re.finditer(r"\d+", stem):
            start, end = match.span()
            if len(match.group()) < 4 or any(start < right and end > left for left, right in protected):
                continue
            separated = (start == 0 or not stem[start - 1].isalnum()) and (end == len(stem) or not stem[end].isalnum())
            if separated:
                candidates.append(match)
                continue
            if any(pattern.match(original[:index] + str((int(original[index]) + 1) % 10) + original[index + 1:])
                   for pattern in matched for index in range(start, end)):
                candidates.append(match)
        if len(candidates) != 1:
            return name, None, None
        token = candidates[0]
    family = name[:token.start()] + "{version}" + name[token.end():]
    version = tuple(int(part) for part in token.group().split("."))
    return name, family, version


def cleanup_version_sets(candidates, patterns, triggered_name=None):
    keep = set()
    delete = set()
    trigger_family = parse_release_filename(triggered_name, patterns)[1] if triggered_name else None
    if triggered_name and trigger_family is None:
        return keep, delete
    for pattern in patterns:
        if triggered_name and not pattern.search(triggered_name):
            continue
        families = {}
        for name, path in candidates:
            if not pattern.search(name):
                continue
            _, family, version = parse_release_filename(name, patterns)
            if version is None:
                keep.add(path)
                continue
            if trigger_family and family != trigger_family:
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
    candidates = completed_root_files(downloaded_path)
    keep, remove = cleanup_version_sets(candidates, patterns, os.path.basename(downloaded_path))
    deleted = 0
    for path in natsorted(remove - keep - set(protected_paths), key=sort_key):
        with (nullcontext(True) if path == downloaded_path else file_lock(path)) as acquired:
            if not acquired or not completed_download_exists(path) or not valid_download_content(path):
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
        with file_lock(destination) as acquired:
            if not acquired:
                return True, ""
            if os.path.islink(destination) or (os.path.lexists(destination) and not os.path.isfile(destination)):
                raise ValueError(f"Invalid destination path: {destination}")
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
    items = prepare_github_checksums(items)
    items = prepare_redirect_downloads(items, failures)
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
            if "?" in file and not file.lower().endswith(".lock"):
                new_name = file.split("?")[0]
                if new_name.lower().endswith(".lock"):
                    continue
                old_file_path = os.path.join(root, file)
                new_file_path = os.path.join(root, new_name)
                lock_directory = workdir if root == STAGING_DIRECTORY else root
                lock_paths = {os.path.join(lock_directory, name.removesuffix(".aria2")) for name in (file, new_name)}
                try:
                    with ExitStack() as stack:
                        if not all(stack.enter_context(file_lock(path)) for path in sorted(lock_paths)):
                            continue
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

  // Optional explicit redirect resolution.
  // "resolve_redirect": true,

  "search_regex": "^[0-9]+\\.[0-9]+/$",

  "search_tail": 1,

  "max_depth": 3,
  "max_pages": 100,

  // path: used only for type=2. List elements are dictionary keys or list indices.
  "path": ["assets", 0, "browser_download_url"],

  // tail: number of last URLs after natural sorting of normalized filenames. 0 - all discovered URLs.
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
    with open(file_path, "x", encoding="utf-8") as outfile:
        outfile.write(data)
    print("New plugin created", file_path)
    editor = os.environ.get("EDITOR")
    if editor:
        try:
            subprocess.run([editor, file_path], env=os.environ)
        except Exception:
            pass
    sys.exit(0)


def plugin_from_tui(values):
    name = values["name"].strip().removesuffix(".json")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name) or name.endswith("."):
        raise ValueError("Plugin name: use letters, digits, underscores, dots or hyphens")
    source_type = int(values["type"])
    if source_type not in (0, 1, 2, 3):
        raise ValueError("Type must be 0, 1, 2 or 3")
    url = values["url"].strip()
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or any(c.isspace() for c in url):
        raise ValueError("URL must be a valid HTTP(S) URL")
    raw_rules = values["rules"].strip()
    if not raw_rules or raw_rules == "[]":
        rules = []
    elif re.match(r'^\[\s*"', raw_rules):
        rules = json.loads(raw_rules)
    else:
        rules = [raw_rules]
    if not isinstance(rules, list) or any(not isinstance(rule, str) or not rule for rule in rules):
        raise ValueError("Rules must be a JSON array of non-empty regular expressions")
    if source_type in (1, 3) and not rules:
        raise ValueError("Rules are required for types 1 and 3")
    for rule in rules:
        re.compile(rule)
    data = {"type": source_type, "url": url, "rules": rules}
    if source_type in (1, 3):
        tail = int(values["tail"])
        if tail < 0:
            raise ValueError("Tail must be non-negative")
        data["tail"] = tail
    if source_type == 2:
        raw_path = values["path"].strip()
        if raw_path.startswith("["):
            path = json.loads(raw_path)
        elif raw_path:
            parts = raw_path.split(".")
            if any(not part for part in parts):
                raise ValueError("JSON path: use keys separated by dots, without empty keys")
            path = [int(part) if re.fullmatch(r"[0-9]+", part) else part for part in parts]
        else:
            path = []
        if not isinstance(path, list) or any(type(part) not in (str, int) for part in path):
            raise ValueError("Path must be a JSON array of keys and integer indices")
        data["path"] = path
    if source_type == 3:
        search_regex = values["search_regex"].strip()
        if not search_regex:
            raise ValueError("Search regex is required for type 3")
        re.compile(search_regex)
        data["search_regex"] = search_regex
        for key, minimum in (("search_tail", 0), ("max_depth", 1), ("max_pages", 1)):
            number = int(values[key])
            if number < minimum:
                raise ValueError(f"{key} must be at least {minimum}")
            data[key] = number
    out = values["out"].strip()
    if out:
        if sanitize_filename(out) != out or ntpath.basename(out) != out or out.lower().endswith((".lock", ".aria2")):
            raise ValueError("Out must be a plain filename without a reserved suffix")
        data["out"] = out
    proxy = values["proxy"].strip()
    if proxy:
        if proxy.startswith("{"):
            proxy = json.loads(proxy)
            if not isinstance(proxy, dict) or any(not isinstance(value, str) for value in proxy.values()):
                raise ValueError("Proxy must be a URL or a JSON object with string values")
        data["proxy"] = proxy
    aria2 = json.loads(values["aria2"] or "{}")
    if not isinstance(aria2, dict) or any(not isinstance(value, (str, int, float, bool)) for value in aria2.values()):
        raise ValueError("Aria2 must be a JSON object with scalar values")
    if aria2:
        data["aria2"] = aria2
    redirect = values["resolve_redirect"].strip().lower()
    if redirect not in ("true", "false"):
        raise ValueError("Resolve redirect must be true or false")
    if redirect == "true":
        data["resolve_redirect"] = True
    return name, data


def save_tui_plugin(values):
    name, data = plugin_from_tui(values)
    text = json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    os.makedirs(plugins_directory, exist_ok=True)
    path = os.path.join(plugins_directory, name + ".json")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise ValueError("Plugin already exists; choose another name") from error
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as outfile:
            outfile.write(text)
    except OSError:
        os.unlink(path)
        raise
    return path


def create_plugin_tui():
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise RuntimeError("--create-tui requires an interactive terminal")
    try:
        import curses
    except ImportError as error:
        raise RuntimeError("--create-tui requires curses (on Windows: install windows-curses)") from error

    from textwrap import wrap

    source_types = ("Direct file", "Website / releases", "JSON API", "Recursive directory")
    definitions = (
        ("name", "Plugin name", "", "Required. Name of the JSON plugin, e.g. example."),
        ("type", "Source type", "1", "Left/Right or 0-3: direct file, website/releases, JSON API or recursive directories."),
        ("url", "Source URL", "", "Required. HTTP(S) address of the file, website, repository, directory or API."),
        ("rules", "Filename regex", "", r"File matching and cleanup. Example: ^app-.*\.exe$ (no JSON escaping). Multiple rules: JSON array."),
        ("tail", "Latest files", "1", "Number of latest matching files to download. 0 = all matches."),
        ("path", "JSON path", "", "Keys separated by dots, e.g. architecture.64bit.url. Digits are indices; use a JSON array for literal keys."),
        ("search_regex", "Directory regex", "", r"Required. Match subdirectories to visit, e.g. ^[0-9.]+/$ or ^(?:win|x64)/$."),
        ("search_tail", "Latest directories", "0", "Number of latest matching directories per level. 0 = all."),
        ("max_depth", "Max depth", "3", "Maximum number of directory levels to follow."),
        ("max_pages", "Max pages", "100", "Maximum number of pages to scan."),
        ("out", "Output filename", "", "Optional. Save using this local filename instead of the name from the URL."),
        ("proxy", "Proxy", "", "Optional. Proxy URL, e.g. http://127.0.0.1:1080, or a JSON object."),
        ("aria2", "Aria2 settings", "{}", 'Optional JSON object, e.g. {"split": 2, "timeout": 120}.'),
        ("resolve_redirect", "Resolve redirect", "false", "true = resolve the final download URL before downloading; false = automatic."),
    )
    values = {key: default for key, _, default, _ in definitions}

    def form(screen):
        selected, cursor, top = 0, 0, 0
        advanced = False
        status = ""
        while True:
            source_type = int(values["type"])
            keys = {"name", "type", "url", "rules"}
            if source_type in (1, 3):
                keys.add("tail")
            if source_type == 2:
                keys.add("path")
            if source_type == 3:
                keys.add("search_regex")
            if advanced:
                keys.update(("out", "proxy", "aria2", "resolve_redirect"))
                if source_type == 3:
                    keys.update(("search_tail", "max_depth", "max_pages"))
            fields = [field for field in definitions if field[0] in keys]
            selected = min(selected, len(fields) - 1)
            height, width = screen.getmaxyx()
            screen.erase()
            if height < 12 or width < 60:
                screen.addnstr(0, 0, "Resize terminal to 60x12 or press Esc", max(0, width - 1))
                screen.refresh()
                if screen.get_wch() == "\x1b":
                    return None
                continue
            cols = min(width - 2, 100)
            left = (width - cols) // 2
            visible = min(len(fields), height - 8)
            if selected < top:
                top = selected
            elif selected >= top + visible:
                top = selected - visible + 1
            top = min(top, len(fields) - visible)
            label_width = 19
            value_width = cols - label_width - 5
            screen.addstr(0, left, "+" + "-" * (cols - 2) + "+")
            heading = " Create plugin - " + ("Advanced" if advanced else "Basic") + " "
            screen.addstr(1, left, "|" + heading.center(cols - 2) + "|")
            for row, index in enumerate(range(top, top + visible), 2):
                key, label, _, _ = fields[index]
                value = values[key].encode("ascii", "replace").decode("ascii")
                if key == "type":
                    value = f"{source_type}: {source_types[source_type]}"
                offset = max(0, cursor - value_width + 1) if index == selected and key != "type" else 0
                screen.addstr(row, left, "| " + label.ljust(label_width))
                screen.addstr(row, left + label_width + 2, value[offset:offset + value_width].ljust(value_width), curses.A_REVERSE if index == selected else curses.A_NORMAL)
                screen.addstr(row, left + cols - 1, "|")
            footer = visible + 2
            screen.addstr(footer, left, "+" + "-" * (cols - 2) + "+")
            key, _, _, hint = fields[selected]
            if key == "rules" and source_type in (1, 3):
                hint = "Required. " + hint
            elif key == "rules":
                hint = "Optional. " + hint
            for row, line in enumerate(wrap(hint, cols)[:2], footer + 1):
                screen.addnstr(row, left, line, cols)
            screen.addnstr(footer + 3, left, "Tab/Arrows: move | F2 Save | F3 Options | Esc Cancel", cols)
            for row, line in enumerate(wrap(status.encode("ascii", "replace").decode("ascii"), cols)[:2], footer + 4):
                screen.addnstr(row, left, line, cols, curses.A_BOLD)
            screen.move(selected - top + 2, left + label_width + 2 + (0 if key == "type" else min(cursor, value_width - 1)))
            screen.refresh()
            pressed = screen.get_wch()
            value = values[key]
            if pressed == "\x1b":
                return None
            if pressed == curses.KEY_F2:
                try:
                    return save_tui_plugin(values)
                except (ValueError, OSError, re.error) as error:
                    status = f"ERROR: {error}"
                continue
            if pressed == curses.KEY_F3:
                advanced = not advanced
                if not advanced:
                    selected, cursor, top = 0, 0, 0
                status = ""
                continue
            if pressed in ("\t", "\n", "\r", curses.KEY_ENTER, curses.KEY_DOWN, curses.KEY_UP, curses.KEY_BTAB):
                direction = -1 if pressed in (curses.KEY_UP, curses.KEY_BTAB) else 1
                selected = (selected + direction) % len(fields)
                cursor = len(values[fields[selected][0]])
            elif key == "type":
                if pressed in ("0", "1", "2", "3"):
                    values[key] = pressed
                elif pressed in (curses.KEY_LEFT, curses.KEY_RIGHT):
                    values[key] = str((source_type + (-1 if pressed == curses.KEY_LEFT else 1)) % len(source_types))
                cursor = 0
            elif pressed == curses.KEY_LEFT:
                cursor = max(0, cursor - 1)
            elif pressed == curses.KEY_RIGHT:
                cursor = min(len(value), cursor + 1)
            elif pressed == curses.KEY_HOME:
                cursor = 0
            elif pressed == curses.KEY_END:
                cursor = len(value)
            elif pressed in ("\b", "\x7f", curses.KEY_BACKSPACE):
                if cursor:
                    values[key] = value[:cursor - 1] + value[cursor:]
                    cursor -= 1
            elif pressed == curses.KEY_DC:
                values[key] = value[:cursor] + value[cursor + 1:]
            elif pressed == "\x15":
                values[key] = ""
                cursor = 0
            elif isinstance(pressed, str) and pressed.isprintable():
                values[key] = value[:cursor] + pressed + value[cursor:]
                cursor += len(pressed)
            status = ""

    try:
        path = curses.wrapper(form)
    except KeyboardInterrupt:
        print("INFO: Plugin creation cancelled")
        return
    except curses.error as error:
        raise RuntimeError(f"Cannot open plugin TUI: {error}") from error
    if path is None:
        print("INFO: Plugin creation cancelled")
    else:
        print(f"New plugin created {path}")


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
    targets = [target for target in selected_plugins if isinstance(target, dict)]
    has_targets = bool(targets)
    download_list = get_urls(targets, failures)
    print([urlsplit(item["url"])._replace(query="").geturl() if is_sourceforge_url(item["url"]) else item["url"] for item in download_list])
    if not has_targets:
        if failures:
            print(f"ERROR: Failed plugin(s) ({len(failures)}): {', '.join(failures)}", file=sys.stderr)
        return not failures
    success = download_all(download_list, failures)
    if failures:
        print(f"ERROR: Failed plugins or downloads ({len(failures)}): {', '.join(failures)}; only completed downloads trigger cleanup", file=sys.stderr)
    return success and not failures


def normalize_version_key(parts):
    end = len(parts)
    while end > 1 and parts[end - 1] == 0:
        end -= 1
    return parts[:end]


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
        try:
            with file_lock(path) as acquired:
                if not acquired or not completed_download_exists(path) or not valid_download_content(path):
                    continue
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


def run_plugin_names(args):
    if args.clear is not None:
        return ["__maintenance__"]
    if args.run is not None and all(args.run):
        return sorted({name.removesuffix(".json") for group in args.run for name in group})
    if args.run is None and (args.create is not None or args.create_tui or args.edit is not None or args.list):
        return ["__maintenance__"]
    if not os.path.isdir(plugins_directory):
        return []
    with os.scandir(plugins_directory) as entries:
        return [entry.name[:-5] for entry in entries if entry.name.endswith(".json")]


def run_log_file(args, plugin_names):
    if args.log_file:
        return args.log_file
    if not args.log and os.environ.get("AUTODOWNLOAD_LOG", "").strip().lower() not in ("1", "true", "yes", "on"):
        return None
    directory = os.path.dirname(os.path.realpath(__file__))
    if args.run is None or any(not group for group in args.run):
        return os.path.join(directory, "autodownload.log")
    label = "__".join(plugin_names)
    safe_label = re.sub(r"[^A-Za-z0-9_.-]", "_", label)
    if not safe_label or len(safe_label) > 80 or safe_label != label:
        suffix = hashlib.sha256(label.encode("utf-8", errors="surrogateescape")).hexdigest()[:10]
        safe_label = f"{safe_label[:64] or 'plugins'}-{suffix}"
    return os.path.join(directory, f"autodownload.{safe_label}.log")


def run_plugins(plugin_names):
    successful = True
    for name in plugin_names:
        try:
            failures = []
            selected = load_plugin(plugins_directory, name + ".json", failures)
            if not run_search(selected, failures):
                successful = False
        except (requests.RequestException, RuntimeError, ValueError, OSError) as error:
            print(f"ERROR: Plugin {name} failed: {error}", file=sys.stderr)
            successful = False
    return successful


def run(args, plugin_names):
    global DEBUG
    if args.debug:
        DEBUG = True
    if args.create_tui:
        create_plugin_tui()
    elif args.create is not None:
        create_plugin(args.create)
    elif args.edit is not None:
        edit_plugin(args.edit)
    elif args.clear is not None:
        names = list(dict.fromkeys(name.removesuffix(".json") for group in args.clear for name in group))
        if names:
            failures = []
            selected = []
            for name in names:
                selected.extend(load_plugin(plugins_directory, name + ".json", failures))
            if failures:
                sys.exit(1)
            clear_old(selected)
        else:
            clear_old(load_plugins(plugins_directory))
    elif args.run is not None:
        if all(args.run):
            plugin_names = list(dict.fromkeys(name.removesuffix(".json") for group in args.run for name in group))
        if not run_plugins(plugin_names):
            sys.exit(1)
    elif args.list:
        list_plugins(plugins_directory)
    elif args.rename:
        rename_files()
    else:
        if not run_plugins(plugin_names):
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
  Plugins run sequentially within one invocation, with parallel file downloads.
  Plugins and discovery are not locked. Each active download creates a
  <destination>.lock file atomically, next to the final destination, including
  staged downloads. If the lock already exists, the file is skipped without waiting.
  Locks contain the owner PID and are removed on normal completion or handled errors.
  After a forced termination, a stale lock may remain; remove it manually only
  after verifying that no process is still writing the file.
  Cleanup and rename skip locked files and acquire locks before changing files.
  The .lock suffix is reserved for lock files.
  File logging is disabled by default. Console output is always available.
  Enable file logging with --log, --log-file PATH, or AUTODOWNLOAD_LOG=1
  (also accepts true, yes, or on, case-insensitive).
  When enabled, --run NAME uses autodownload.NAME.log; a general run uses
  autodownload.log. --log-file specifies an explicit log file path.
  Concurrent writes to the same explicitly specified log file are serialized.
  Log serialization: Linux uses flock; Windows uses named mutexes.
  ./autodownload.py --list                   List plugin names
  ./autodownload.py --create [NAME]          Create a JSON template (default: plugin)
  ./autodownload.py --create-tui             Create a plugin in an interactive terminal (F2 save, F3 options, Esc cancel)
  ./autodownload.py --edit [NAME]            Open JSON using $EDITOR (if set); create it if missing
  ./autodownload.py --clear                  Remove older versions using all plugin rules
  ./autodownload.py --clear NAME [NAME ...]  Remove older versions using only selected plugin rules
                --clear can be repeated; if any names are supplied, only those plugins are used.
                Plugin names may include the .json suffix. A failed selected plugin load aborts cleanup.
                Only completed versioned files in the main directory are removed,
                separately for each filename family and architecture.
                A trailing build date and hexadecimal commit hash are ignored when comparing dotted versions.
                Unversioned files, .aria2 files, .lock files, and .autodownload-stage are not removed.
  ./autodownload.py --rename                 Remove the filename portion after the ? character
  ./autodownload.py --version                Display the script version
  ./autodownload.py --run --debug            Enable debug output without enabling file logging
  ./autodownload.py --run --log              Enable file logging
  ./autodownload.py --run --log-file PATH    Enable file logging at the specified path
  AUTODOWNLOAD_LOG=1 ./autodownload.py --run  Enable file logging via the environment
  Windows (PowerShell): $env:AUTODOWNLOAD_LOG = '1'

Format of plugins/NAME.json (// and /* ... */ comments are supported):
  type          Source type (default: 1):
                0 - direct file URL;
                1 - links from HTML, GitHub Releases, or SourceForge;
                2 - URL from JSON using path;
                3 - recursive directory traversal using two regular expressions.
  url           File, HTML page, or JSON API URL.
  rules         Array of regular expressions for filenames (case-insensitive re.match).
                Used for types 1 and 3 and for removing older versions.
  resolve_redirect  Resolve the file URL explicitly, checking its filename (default: false).
  tail          Select the last N URLs after natural sorting of normalized filenames; 0 - all.
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
  user_agent / referer          HTTP User-Agent and Referer. User-Agent also applies to discovery and redirects.
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
  If the original direct URL does not contain a filename,
  curl determines the final URL and filename.
  For script URLs, file or filename query parameters can supply the filename.
  Metalink redirects are rejected. Files are downloaded only through aria2c.
  Release filename parsing is shared by sorting, download planning and cleanup.
  Recognized build date/hash suffixes are ignored for comparison only.
  Ambiguous versions are treated as unversioned and are not removed by cleanup.
  After a successful download, cleanup is performed according to the corresponding rules.
  When file logging is enabled, each run overwrites its log file at startup after acquiring the file lock.
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
    parser.add_argument("--create-tui", action="store_true", help="Create a plugin in an interactive terminal")
    parser.add_argument("--edit", nargs="?", const="plugin", help="Edit a plugin")
    parser.add_argument("--clear", nargs="*", action="append", metavar="NAME", help="Remove older files for all or selected plugins")
    parser.add_argument("--run", nargs="*", action="append", metavar="NAME", help="Run all or selected plugins")
    parser.add_argument("--list", action="store_true", help="List plugins")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--log", action="store_true", help="Enable file logging (disabled by default)")
    parser.add_argument("--rename", action="store_true", help="Rename files containing ? in their names")
    parser.add_argument(
        "--log-file",
        default=None,
        help="Enable file logging at the specified path",
    )
    args = parser.parse_args()
    if args.create_tui and (args.create is not None or args.edit is not None or args.clear is not None or args.run is not None or args.list or args.rename):
        parser.error("--create-tui cannot be combined with another operating mode")
    try:
        configured_dir = os.environ.get("AUTODOWNLOAD_DIR", "").strip()
        if os.name == "nt" and not configured_dir and not (args.list or args.create is not None or args.create_tui or args.edit is not None):
            raise RuntimeError("Set AUTODOWNLOAD_DIR to a Windows path; the default directory is Linux-specific")
        if os.name != "nt" and (ntpath.splitdrive(configured_dir)[0] or configured_dir.startswith("\\\\")):
            raise RuntimeError("AUTODOWNLOAD_DIR contains a Windows path; use a mounted Linux path instead")
        names = run_plugin_names(args)
        with capture_log(run_log_file(args, names)):
            try:
                run(args, names)
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
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
