# Maintainer: Melvin Jones Repol <mrepol742@email.com>

pkgname=npm-guard
pkgver=1.0.0
pkgrel=1
pkgdesc="NPM Guard Supply Chain Security Daemon - monitors npm cache for malicious packages"
arch=('any')
url="https://github.com/mrepol742/npm-guard"
license=('MIT')
depends=(
  'python'
  'python-pip'
  'python-pyaml'
  'python-requests'
  'python-watchdog'
  'python-apscheduler'
  'python-rich'
  'python-levenshtein'
)
makedepends=('git')
conflicts=()
source=("${pkgname}::git+${url}.git")
sha256sums=('SKIP')

package() {
  cd "${srcdir}/${pkgname}"

  # Install main package files to /opt/npm-guard
  install -d "${pkgdir}/opt/npm-guard"
  cp -r . "${pkgdir}/opt/npm-guard/"
  rm -rf "${pkgdir}/opt/npm-guard/.git"
  rm -rf "${pkgdir}/opt/npm-guard/venv"
  rm -f "${pkgdir}/opt/npm-guard/npmguard.db"

  # Create wrapper script for CLI access
  install -d "${pkgdir}/usr/bin"
  cat > "${pkgdir}/usr/bin/npm-guard" << 'SCRIPT'
#!/usr/bin/env python3
import sys
import os

os.chdir("/opt/npm-guard")
sys.path.insert(0, "/opt/npm-guard")

from main import main
main()
SCRIPT
  chmod +x "${pkgdir}/usr/bin/npm-guard"

  # Install systemd service
  install -Dm644 systemd/npm-guard.service "${pkgdir}/usr/lib/systemd/system/npm-guard.service"
}
