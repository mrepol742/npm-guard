# NPM Guard

THE NPM Guard Supply Chain Security Daemon.

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/mrepol742/npm-guard.git --depth=1
cd npm-guard
```

Initialize Python virtual environment and install dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

Run the NPM Guard Manually:

```bash
python3 main.py
```

Using Systemd Service:

```bash
sudo rsync -av --exclude='.venv' --exclude='.git' ./ /opt/npm-guard/

# configure python venv
cd /opt/npm-guard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# start the Service
sudo systemctl enable npm-guard.service --now
```

## Warning

This project is in early development and should not be used in production environments. Use at your own risk.
The scan might took a while, depending on the size of the `.npm` directory and the number of packages installed.

This is made for Linux environments, and it is not tested on Windows or MacOS. It is recommended to run this project on a Linux server or a virtual machine.
