# Maintainer: Joseph Sierengowski
pkgname=jett
pkgver=0.1.0
pkgrel=1
pkgdesc='Local AI-powered Endpoint Detection and Response engine'
arch=('x86_64')
url='https://github.com/sierengowskisierengowski-cpu/jeTT'
license=('custom')
depends=('glibc' 'gcc-libs' 'systemd')
makedepends=('cargo' 'cmake' 'python')
source=(
  "${pkgname}-${pkgver}.tar.gz::https://github.com/sierengowskisierengowski-cpu/jeTT/archive/refs/tags/v${pkgver}.tar.gz"
  "jett"
  "jett-daemon.service"
)
sha256sums=('SKIP' 'SKIP' 'SKIP')

build() {
  cd "${srcdir}/jeTT-${pkgver}"
  cargo build --release
}

package() {
  cd "${srcdir}/jeTT-${pkgver}"

  install -Dm755 "target/release/jeTT" "${pkgdir}/usr/lib/jett/jeTT"
  install -Dm755 "target/release/jett-daemon" "${pkgdir}/usr/bin/jett-daemon"
  install -Dm755 "${srcdir}/jett" "${pkgdir}/usr/bin/jett"
  install -Dm644 "${srcdir}/jett-daemon.service" "${pkgdir}/usr/lib/systemd/system/jett-daemon.service"

  install -d "${pkgdir}/var/log/jett" "${pkgdir}/var/jett/quarantine"
}
