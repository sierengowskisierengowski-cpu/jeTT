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
sha256sums=('SKIP'
            'b8d3762fd90062f4ff5afafc2529ef12a40b7ca8e3a2b418c39cf221b3c79634'
            '0e5b5f34236637bd204684172a079894de5323e844ad54ad614dcfc175dfa8c9')

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
}
