# Autodownload

`autodownload.py` is a JSON plugin-based file downloader and updater for Linux and Windows. The script discovers current links to installers and other artifacts, downloads files using `aria2c`, resumes interrupted downloads, and removes older completed versions according to plugin rules.

This documentation applies to script version **`2026.11.27.3`**.

## Features

- Four source types: direct URL, HTML/GitHub/SourceForge, JSON API, and recursive directory traversal.
- Run all plugins, a single plugin, or multiple selected plugins.
- Parallel downloads, retries, and download resumption using `aria2c` and `.aria2` control files.
- Skip existing completed versioned files; for GitHub Releases, check SHA-256 before downloading if the API provides a `digest`.
- For files with fixed names, download to a staging directory and replace only when the SHA-256 hash changes.
- Check MSI signatures and reject HTML pages incorrectly returned instead of files.
- Remove outdated versions after successful downloads or manually using `--clear`.
- Protect individual destination files with `.lock` files; optionally maintain separate logs for selected plugins.

## Requirements

- Linux and Windows: atomic creation of `.lock` files is used for download locking. Optional log serialization uses `fcntl.flock` on Linux and named mutexes on Windows.
- Python **3.9+**.
- Python packages: `requests`, `beautifulsoup4`, `lxml`, and `natsort`.
- `aria2c` and `curl` utilities available in `PATH`.
- Read access to the plugin directory and write access to the download directory and, when file logging is enabled, the log directory.

### Getting started (Debian/Ubuntu)

The following instructions assume that `autodownload.py`, `requirements.txt`, and the `plugins/` directory are located in `/scripts`. Run system package installation commands as `root` (or using `sudo`). The download directory must be writable by the user running the script.

**Option 1 — system Python packages (for running `./autodownload.py` directly):**

```bash
apt-get update
apt-get install -y python3 python3-requests python3-bs4 python3-lxml python3-natsort aria2 curl
mkdir -p /mnt/hdd1/shares/autodownloads
chmod +x /scripts/autodownload.py
cd /scripts
./autodownload.py --list
```

**Option 2 — Python virtual environment and `requirements.txt`:**

```bash
apt-get update
apt-get install -y python3 python3-venv python3-pip aria2 curl
cd /scripts
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
mkdir -p /mnt/hdd1/shares/autodownloads
.venv/bin/python autodownload.py --list
```

When using `venv`, run the script through `.venv/bin/python`: the `#!/usr/bin/python3` shebang selects the system Python when the script is executed directly. A virtual environment allows dependencies to be installed with `pip` without modifying system Python packages (particularly relevant for Debian 12+).

Verify the dependencies for the selected option:

```bash
python3 -c 'import requests, bs4, lxml, natsort'
command -v aria2c
command -v curl
```

For the `venv` option, replace `python3` in the first verification command with `.venv/bin/python`.

First run after setup:

```bash
./autodownload.py --run ollama
```

When using `venv`, run `.venv/bin/python autodownload.py --run ollama` instead of the last command.

## Directory layout

Example project structure:

```text
/scripts/
├── autodownload.py
├── autodownload.bash
├── requirements.txt
├── plugins/
│   ├── ollama.json
│   ├── blender.json
│   └── tesseract.json
└── autodownload.log
```

The script uses the following default paths:

| Purpose | Path |
| --- | --- |
| Plugin configurations | `plugins/` next to the script |
| Downloaded files | `/mnt/hdd1/shares/autodownloads/` (Linux default); `AUTODOWNLOAD_DIR` |
| Persistent staging directory | `.autodownload-stage/` inside the download directory |
| Quarantine for invalid files | `.autodownload-stage/.invalid/` |
| General log (optional) | `autodownload.log` next to the script |

The download directory is configured using the `AUTODOWNLOAD_DIR` environment variable (an absolute or relative path). On Linux, the default is `/mnt/hdd1/shares/autodownloads/`; on Windows, the variable is required for downloads and cleanup. Relative paths are resolved against the current working directory. There is no separate CLI option. The staging directory is created inside the download directory; on Linux, its permissions are set to `0777`. Consider access by other local users to this directory.

## Usage

The commands below assume Linux, `/scripts` as the current directory, and an executable script (`chmod +x autodownload.py`). You can use `python3 autodownload.py` instead of `./autodownload.py`. On Windows, install dependencies using `python -m pip install -r requirements.txt`, ensure `aria2c` and `curl` are available in `PATH`, set `$env:AUTODOWNLOAD_DIR = 'D:\Downloads'` in PowerShell, and use `python autodownload.py --run`. On Linux, override the directory using `AUTODOWNLOAD_DIR=/path/to/downloads ./autodownload.py --run`.

| Command | Purpose |
| --- | --- |
| `./autodownload.py` | Download files for all plugins |
| `./autodownload.py --run` | Same as above |
| `./autodownload.py --run ollama` | Run one plugin |
| `./autodownload.py --run ollama blender` | Run multiple plugins |
| `./autodownload.py --run ollama --run blender` | Alternative syntax for multiple plugins |
| `./autodownload.py --list` | List plugin names |
| `./autodownload.py --create example` | Create the `plugins/example.json` template |
| `./autodownload.py --edit example` | Open the plugin using `$EDITOR`, if set; create it if missing |
| `./autodownload.py --clear` | Remove older completed versions using all plugin rules |
| `./autodownload.py --clear farmanager` | Remove older versions using only the selected plugin rules |
| `./autodownload.py --clear farmanager blender` | Remove older versions using multiple selected plugins |
| `./autodownload.py --rename` | Remove the filename portion after the `?` character |
| `./autodownload.py --version` | Display the script version |
| `./autodownload.py --help` / `./autodownload.py -h` | Display the complete built-in help |

Additional options:

```bash
./autodownload.py --run ollama blender --debug
./autodownload.py --run ollama --log
AUTODOWNLOAD_LOG=1 ./autodownload.py --run ollama
./autodownload.py --run ollama --log-file /scripts/ollama-run.log
```

`--debug` enables detailed discovery and download planning messages without enabling file logging. File logging is disabled by default; existing log files are left untouched. Use `--log`, `--log-file PATH`, or set `AUTODOWNLOAD_LOG=1` to enable it. The environment variable also accepts `true`, `yes`, or `on` (case-insensitive); other values, including `0`, leave file logging disabled unless a logging option is supplied. On Windows (PowerShell), use `$env:AUTODOWNLOAD_LOG = '1'`. `--log-file` enables logging and takes precedence over the default log path; the log directory must already exist.

> **Warning:** `--clear` immediately removes matching older files. There is no separate `--dry-run` mode in this version. `--rename` also changes filenames in subdirectories of the download directory.

### Bash completion

The `autodownload.bash` file provides completion for all command-line options of `autodownload.py`, including `-h`, `--help`, `--version`, `--create`, `--edit`, `--clear`, `--run`, `--list`, `--debug`, `--log`, `--rename`, and `--log-file`. It requires Bash 4+ and GNU `readlink` (provided by `coreutils` on Linux). No Python process, plugin parsing, or network requests are required for completion.

To enable completion in the current Bash session:

```bash
cd /scripts
source ./autodownload.bash
```

To enable it automatically in future sessions, add `source /scripts/autodownload.bash` to `~/.bashrc`. For system-wide installation on Debian/Ubuntu, run the following commands as root or with `sudo`:

```bash
apt-get install -y bash-completion
install -m 0644 /scripts/autodownload.bash /etc/bash_completion.d/autodownload
```

The system-wide configuration is loaded by `bash-completion` in new interactive Bash sessions where that package is enabled. To use it immediately, source the file as shown above.

Examples (`<TAB>` means pressing Tab):

```text
./autodownload.py --<TAB>
./autodownload.py --run <TAB>
./autodownload.py --run ollama <TAB>
./autodownload.py --run ollama --run <TAB>
./autodownload.py --edit <TAB>
./autodownload.py --create pl<TAB>
./autodownload.py --log-file /tmp/<TAB>
./autodownload.py --run=ol<TAB>
./autodownload.py --clear <TAB>
./autodownload.py --clear farmanager <TAB>
./autodownload.py --clear=far<TAB>
./autodownload.py --clear farmanager --clear <TAB>
```

- `--run`, `--clear`, and `--edit` complete existing plugin names from the `plugins/` directory next to the resolved script, including when called through a symbolic link. Both `--run` and `--clear` accept multiple plugin names and repeated options.
- `--create` suggests the default name `plugin` only if `plugin.json` does not exist; enter any new name manually. Existing plugin names are not suggested for creation.
- `--log-file` completes local files and directories. A new log filename can be entered manually.
- Completion works for direct invocations (`./autodownload.py`, `/scripts/autodownload.py`, or `autodownload.py` in `PATH`). It does not override completion for `python`, `python3`, or other interpreters, including explicit `venv` interpreter invocations.

### Concurrent runs

Plugins are processed sequentially within one invocation, while files belonging to the current plugin can be downloaded in parallel. Plugin names and link discovery are no longer locked: separate processes can run the same or different plugins concurrently.

Before downloading, the script atomically creates `<destination>.lock` next to the final file in the main download directory (for example, `OllamaSetup.exe.lock`). This also applies to files downloaded via `.autodownload-stage/`. If the lock exists, the file is skipped immediately without waiting or reporting a download error. Other files continue to be processed. The `.lock` suffix is reserved and cannot be used for download destinations.

The lock contains the owner process PID (`PID=12345`) and is removed on normal completion or handled errors. Forced termination or a power failure can leave a stale lock. It is not removed automatically: check that neither the owning script nor its download process is still writing the file before manually removing the lock. PID reuse and shared directories make the PID alone insufficient to prove that the lock is stale. Do not delete active locks.

Automatic cleanup, `--clear`, and `--rename` skip locked files and acquire file-specific locks before modifying files. Lock markers themselves are never cleaned up or renamed. No plugin-wide or directory-wide download lock is used.

When file logging is enabled and one or more selected plugins are run, the default log is named `autodownload.ollama.log` or `autodownload.blender__ollama.log` (names are sorted). A full run uses `autodownload.log`. When the same `--log-file` is specified, writes are serialized using a file lock on Linux or a named mutex on Windows. **The log is overwritten at the start of each run with file logging enabled**, not appended to.

## Plugins

Each `plugins/NAME.json` file is a separate plugin. JSON with `//` and `/* ... */` comments is supported. All `.json` plugins in the directory are considered during a full run.

### Source types

| `type` | Source | How it works |
| --- | --- | --- |
| `0` | Direct URL | Passes the URL to the downloader; if the filename cannot be determined, resolves the HTTP redirect using `curl` first |
| `1` | HTML, GitHub Releases, SourceForge | Discovers links and filters them using `rules`; uses the Releases API for GitHub |
| `2` | JSON API or manifest | Extracts URLs using the `path` field |
| `3` | Nested HTML directories | Traverses subdirectories using `search_regex` and filters files using `rules` |

If `type` is not specified, it defaults to `1`.

### Plugin fields

| Field | Purpose |
| --- | --- |
| `url` | Source URL of a file, page, directory, or JSON API |
| `type` | Source type: `0`, `1`, `2`, or `3` |
| `rules` | Array of filename regular expressions; used for discovery with `type: 1` and `type: 3`, and for outdated version cleanup with all types |
| `tail` | Number of last links after natural sorting (`0` means all); used for discovery with `type: 1` and `type: 3` |
| `path` | Array of JSON keys and array indices; used only with `type: 2` |
| `out` | Override the local filename; an empty string uses the filename from the URL or final redirect |
| `proxy` | Plugin-specific proxy: a URL string or an object with `all`, `http`, `https`, `ftp`, and `no_proxy` keys |
| `aria2` | Object containing custom `aria2c` settings |
| `request_connect_timeout` | Connection timeout for metadata requests, in seconds (default: `10`) |
| `request_read_timeout` | HTML/JSON read timeout, in seconds (default: `45`) |
| `request_retries` | Number of metadata request retries (default: `2`) |
| `request_retry_wait` | Base delay between retries, in seconds (default: `2`) |
| `sourceforge_mirror` | Select a SourceForge mirror using `use_mirror` |
| `sourceforge_platform` | Informational platform setting; does **not constrain** `latest/download` by itself |

Regular expressions in `rules` are matched against filenames case-insensitively. Discovery uses `re.match()`, which matches from the beginning of the filename; cleanup uses `re.search()`. In JSON, backslashes must be escaped: `\\.` instead of `\.`.

With `type: 0` and `type: 2`, `rules` **does not filter downloaded URLs**; it determines which filenames are considered during subsequent cleanup. In the current implementation, `tail` also does not limit the list of URLs obtained from JSON (`type: 2`).

#### Additional fields for `type: 3`

| Field | Purpose | Default |
| --- | --- | --- |
| `search_regex` | Required `re.search()` expression for subdirectory names or paths | None |
| `search_tail` | Number of last matching directories at each level; `0` means all | `0` |
| `max_depth` | Maximum recursive traversal depth | `3` |
| `max_pages` | Maximum number of HTML pages processed | `100` |

Traversal is restricted to the original host and directory tree. Auxiliary links containing `?stats=` and `?mirrorlist=` parameters are excluded. Directories are selected using natural sorting.

### Examples

#### Type 0: direct URL with a fixed filename

`plugins/aimp.json`:

```json
{
  "type": 0,
  "url": "https://aimp.ru/?do=download.file&id=3",
  "rules": [
    "^aimp_[0-9.]+_w64\\.exe$"
  ]
}
```

Because the original URL does not contain the installer filename, the script first resolves the final URL using `curl` and downloads the file using `aria2c`.

#### Type 1: GitHub Releases

`plugins/ollama.json`:

```json
{
  "type": 1,
  "url": "https://github.com/ollama/ollama/releases/latest",
  "rules": [
    "^OllamaSetup\\.exe$"
  ],
  "tail": 1
}
```

The script selects the required release asset using the GitHub API. If GitHub provides a `digest` for the selected file, its SHA-256 hash is compared with the local copy before downloading.

#### Type 2: JSON manifest

`plugins/tesseract.json`:

```json
{
  "type": 2,
  "url": "https://raw.githubusercontent.com/ScoopInstaller/Main/master/bucket/tesseract.json",
  "path": ["architecture", "64bit", "url"],
  "rules": [
    "^tesseract-ocr-w64-setup-v?[0-9]+(?:\\.[0-9]+)+\\.exe$"
  ]
}
```

`path` sequentially selects `architecture` → `64bit` → `url` from the JSON document. The result must contain a single URL or an array of URLs. File availability and freshness depend on updates to the third-party manifest.

#### Type 3: recursive search for Blender MSI

`plugins/blender.json`:

```json
{
  "type": 3,
  "url": "https://mirror.blender.org/release/",
  "search_regex": "^Blender[0-9]+\\.[0-9]+/$",
  "rules": [
    "^blender-[0-9]+(?:\\.[0-9]+){2}-windows-x64\\.msi$"
  ],
  "search_tail": 2,
  "tail": 1,
  "max_depth": 2,
  "max_pages": 20
}
```

The script checks the two latest Blender branches and selects the latest matching MSI file. Neither the filename nor the version is hardcoded in the plugin URL. This is an example configuration; remote server availability depends on the network.

## aria2 settings

The `DEFAULT_ARIA2` values in the script:

```json
{
  "split": 4,
  "max_connection_per_server": 4,
  "max_tries": 3,
  "retry_wait": 2,
  "connect_timeout": 10,
  "timeout": 10,
  "max_concurrent_downloads": 4
}
```

Each plugin can override the required settings within `aria2`. For example:

```json
{
  "aria2": {
    "split": 4,
    "timeout": 120,
    "max_tries": 5
  }
}
```

This snippet shows only the `aria2` object; it must be included within a complete JSON plugin when used.

Additional supported settings include `auto_save_interval`, `min_split_size`, `file_allocation`, `lowest_speed_limit`, `user_agent`, `referer`, `conditional_get`, `content_disposition_default_utf8`, `no_want_digest_header`, `http_accept_gzip`, and `out`. Most options accept both underscore-separated and hyphenated names; the aliases `s`, `x`, and `j` are also available for their corresponding numeric settings.

For SourceForge, the script uses separate default connection and timeout settings; a custom `aria2` object takes precedence. The `max_concurrent_downloads` setting controls the number of parallel download tasks within the script; the maximum of the current plugin's downloads' settings and the default value (`4`) is used.

## Downloaded file handling

### Files with a version in the filename

Examples: `blender-5.3.0-windows-x64.msi`, `7z2600-x64.exe`, `OpenShot-v3.5.1-x86_64.exe`.

- If a completed file already exists and passes the applicable validation checks, it is not downloaded again.
- A new version is downloaded directly to the main directory.
- If the GitHub API provides SHA-256, the hash is checked before downloading; if an existing versioned file has a different hash, the new file is downloaded through the staging directory and replaces the old file only after verification.
- `.aria2` control files are used to resume interrupted downloads.

### Files without a version in the filename

Examples: `OllamaSetup.exe`, `Keet.msix`, `Element Setup.exe`.

- Downloads are written to the persistent `.autodownload-stage/` directory.
- After a successful download, SHA-256 is compared with the file in the main directory.
- If the hashes match, the staged copy is removed and the local file remains unchanged.
- If the hashes differ, the staged file replaces the main copy after the download is complete.
- If an error occurs, the previous main copy is preserved; an incomplete download with a `.aria2` control file may be resumed on the next run.

### Content validation

- For `.msi` files, the OLE/CFB container signature is checked.
- HTML documents returned instead of downloadable artifacts are rejected.
- Invalid completed files are moved to `.autodownload-stage/.invalid/`.
- For GitHub Releases, SHA-256 is checked after downloading if a `digest` is available; files with mismatched hashes are rejected.

**Limitation:** MSI signature and HTML checks are not a substitute for cryptographic verification of all file types. If the server does not publish a SHA-256 hash, the script cannot guarantee the authenticity of an arbitrary EXE or ZIP file.

## Cleanup of older versions

After a successful download, the script removes older **completed** versions matching the applicable `rules`. Filename families are considered during comparison to keep different variants and architectures separate.

Manual cleanup:

```bash
./autodownload.py --clear
./autodownload.py --clear farmanager
./autodownload.py --clear farmanager blender
./autodownload.py --clear farmanager --clear blender
```

Without names, `--clear` uses all plugin rules. If at least one name is supplied, only the selected plugin rules are used, even when the option is repeated. The `.json` suffix is optional. If any explicitly selected plugin cannot be loaded, cleanup is aborted with a nonzero exit status. Files are selected by `rules`, not download history: overlapping rules can match the same files.

The current implementation considers only files directly inside the main download directory. `.aria2` files, `.lock` markers, files locked by another process, incomplete downloads, files with no identifiable version, and the contents of `.autodownload-stage/` are not removed. If a download fails, previous files are not cleaned up as a result of that download.

Before using `--clear` for the first time, review the current `rules` in the plugins and back up the directory if it contains important files.

## Logs and errors

`INFO`, `WARN`, `ERROR`, and `DEBUG` messages, including `aria2c` output, are written to the console and, only when file logging is enabled, to the log. Potentially sensitive values of certain URL parameters are masked in both modes.

- When running multiple plugins, execution continues if one plugin fails; the overall download run exits with a nonzero status if errors are recorded.
- An empty or unresolvable discovery result is recorded as an error for the corresponding plugin.
- Download failures should not cause a previous valid copy of a file to be removed.
- When troubleshooting downloads, run the relevant plugin separately with `--debug --log` and inspect its log.

```bash
./autodownload.py --run ollama --debug --log
./autodownload.py --help
```

## Limitations

- `type: 3` traversal works with ordinary HTML links but does not execute page JavaScript.
- The availability of checksums in GitHub release assets depends on the data published by GitHub; if no `digest` is available, the previous download logic applies.
- New version detection depends on source links, plugin rules, and sorting; third-party JSON manifests may be updated with a delay.
- The script is not a general-purpose browser and does not bypass CAPTCHA or other interactive anti-bot protection.
- All paths and limitations should be checked against the installed `autodownload.py` version; the built-in `--help` describes the options of the current instance.
