# Copyright 2020 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
PYTHON_COMPAT=( python3_{8,9} )
DISTUTILS_USE_SETUPTOOLS=rdepend

SCM=""
if [ "${PV#9999}" != "${PV}" ] ; then
	SCM="git-r3"
	EGIT_REPO_URI="https://github.com/spacefreak86/${PN}"
fi

inherit ${SCM} distutils-r1 systemd

DESCRIPTION="A pymilter based sendmail/postfix pre-queue filter."
HOMEPAGE="https://github.com/spacefreak86/pyquarantine"
if [ "${PV#9999}" != "${PV}" ] ; then
	SRC_URI=""
	KEYWORDS=""
	# Needed for tests
	S="${WORKDIR}/${PN}"
	EGIT_CHECKOUT_DIR="${S}"
else
	SRC_URI="https://github.com/spacefreak86/${PN}/archive/${PV}.tar.gz -> ${P}.tar.gz"
	KEYWORDS="amd64 x86"
fi

LICENSE="GPL-3"
SLOT="0"
IUSE="lxml systemd"

RDEPEND="
	dev-python/beautifulsoup[${PYTHON_USEDEP}]
	dev-python/jsonschema[${PYTHON_USEDEP}]
	lxml? ( dev-python/lxml[${PYTHON_USEDEP}] )
	dev-python/netaddr[${PYTHON_USEDEP}]
	dev-python/peewee[${PYTHON_USEDEP}]
	dev-python/pymilter[${PYTHON_USEDEP}]"

python_install_all() {
	distutils-r1_python_install_all

	dodir /etc/${PN}
	insinto /etc/${PN}
	doins pyquarantine/docs/pyquarantine.conf.example
	doins -r pyquarantine/docs/templates

	use systemd && systemd_dounit ${PN}/misc/${PN}-milter.service
	newinitd ${PN}/misc/openrc/${PN}-milter.initd ${PN}-milter
	newconfd ${PN}/misc/openrc/${PN}-milter.confd ${PN}-milter
}
