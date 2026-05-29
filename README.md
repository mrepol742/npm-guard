# NPM Guard

NPM Guard scans the local npm cache for suspicious packages and known issues. It supports one time scans, watcher mode, cron scheduling, and a hybrid mode that runs both.

## Requirements

- Python 3
- Linux environment
- npm cache directory (default is `~/.npm`)

## Installation

Install via aur:

```bash
yay -S npm-guard
```

or if you prefer manual installation:

Clone the repository and install dependencies:

```bash
git clone https://github.com/mrepol742/npm-guard.git --depth=1
cd npm-guard
```

Create a virtual environment and install requirements:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Edit `config.yaml` to match your environment and desired scan mode.

Key fields:

- `scan_mode`: `manual`, `watcher`, `cron`, or `hybrid`
- `cron.expression`: 5 field cron expression used in `cron` and `hybrid` modes
- `paths.npm_cache`: path to your npm cache
- `paths.quarantine`: directory for quarantined files
- `security.quarantine_enabled`: enable or disable quarantine
- `security.risk_threshold`: minimum score to quarantine

Example:

```yaml
scan_mode: manual

cron:
  expression: "0 */6 * * *"

paths:
  npm_cache: "/home/you/.npm"
  quarantine: "/home/you/.npm-quarantine"

security:
  quarantine_enabled: true
  risk_threshold: 50
```

## Running

The entry point is `main.py`. It uses `scan_mode` from `config.yaml`.

One time deep scan:

```bash
python main.py
```

Watcher mode (real-time monitoring):

```bash
# set scan_mode: watcher
python main.py
```

Cron mode (scheduled scans):

```bash
# set scan_mode: cron
python main.py
```

Hybrid mode (watcher + cron):

```bash
# set scan_mode: hybrid
python main.py
```

## Stats and Maintenance

Show database stats:

```bash
python main.py --stats
```

Clear the database:

```bash
python main.py --clear
```

## Systemd

You have two options.

Option A: Arch Linux package

Use `PKGBUILD`. It installs the /usr/bin/npm-guard wrapper and the systemd service.

Option B: Manual install

```bash
sudo rsync -av --exclude='.git' --exclude='venv' ./ /opt/npm-guard/

cd /opt/npm-guard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

sudo tee /usr/bin/npm-guard >/dev/null <<'SCRIPT'
#!/usr/bin/env bash
cd /opt/npm-guard
exec /opt/npm-guard/venv/bin/python3 /opt/npm-guard/main.py
SCRIPT
sudo chmod +x /usr/bin/npm-guard

sudo install -Dm644 systemd/npm-guard.service /etc/systemd/system/npm-guard.service
sudo systemctl daemon-reload
sudo systemctl enable npm-guard.service --now
```

## Note

- Deep scans and watcher mode detect tarballs even when the npm cache stores them without a `.tgz` extension, including entries under `_cacache/content-v2`.
- Large npm caches can take time to scan.
- This project is tested on Arch Linux only and might require adjustments for other Linux distributions.

## Performance

Since this tool is designed to run on a local npm cache, performance can vary based on the size of the cache and the number of packages.
The deep scan mode can be resource-intensive, especially for large caches, while watcher mode is optimized for real-time monitoring with minimal overhead.
Cron mode allows for scheduled scans during off-peak hours to minimize impact on system performance.

Now you know why anti-virus software is so expensive and why it needs to be updated so frequently.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

This project is for educational purposes only. Use it at your own risk.
The author is not responsible for any damage or loss caused by this software.
