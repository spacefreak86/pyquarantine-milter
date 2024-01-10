# Copyright 2020 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
PYTHON_COMPAT=( python3_{10..11} )
DISTUTILS_USE_SETUPTOOLS=rdepend

SCM=""
if [ "${PV#9999}" != "${PV}" ] ; then
	SCM="git-r3"
	EGIT_REPO_URI="https://github.com/spacefreak86/${PN}"
	EGIT_BRANCH="master"
fi

inherit ${SCM} distutils-r1 systemd

DESCRIPTION="A pymilter based sendmail/postfix pre-queue filter."
HOMEPAGE="https://github.com/spacefreak86/pyquarantine-milter"
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
IUSE="+lxml systemd"

RDEPEND="
	dev-python/beautifulsoup4[${PYTHON_USEDEP}]
	dev-python/jsonschema[${PYTHON_USEDEP}]
	lxml? ( dev-python/lxml[${PYTHON_USEDEP}] )
	dev-python/netaddr[${PYTHON_USEDEP}]
	dev-python/peewee[${PYTHON_USEDEP}]
	>=dev-python/pymilter-1.5[${PYTHON_USEDEP}]"

python_install_all() {
	distutils-r1_python_install_all
	use systemd && systemd_dounit pyquarantine/misc/systemd/${PN}.service
	newinitd pyquarantine/misc/openrc/${PN}.initd ${PN}
	newconfd pyquarantine/misc/openrc/${PN}.confd ${PN}
}

pkg_postinst() {
	elog "You will need to set up your /etc/pyquarantine/pyquarantine.conf file before"
	elog "running pyquarantine-milter for the first time."
}
