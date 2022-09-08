# pyquarantine is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# pyquarantine is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with pyquarantine.  If not, see <http://www.gnu.org/licenses/>.
#

__all__ = ["main"]

import Milter
import argparse
import logging
import logging.handlers
import sys

from pyquarantine._install import install, uninstall
from pyquarantine import mailer
from pyquarantine import QuarantineMilter
from pyquarantine import __version__ as version
from pyquarantine.config import get_milter_config


def main():
    python_version = ".".join([str(v) for v in sys.version_info[0:3]])
    python_version = f"{python_version}-{sys.version_info[3]}"

    "Run pyquarantine."
    parser = argparse.ArgumentParser(
        description="pyquarantine-milter daemon",
        formatter_class=lambda prog: argparse.HelpFormatter(
            prog, max_help_position=45, width=140))
    parser.add_argument(
        "-c", "--config", help="Config file to read.",
        default="/etc/pyquarantine/pyquarantine.conf")
    parser.add_argument(
        "-s",
        "--socket",
        help="Socket used to communicate with the MTA.",
        default="")
    parser.add_argument(
        "-d",
        "--debug",
        help="Log debugging messages.",
        action="store_true")

    exclusive = parser.add_mutually_exclusive_group()
    exclusive.add_argument(
        "-v", "--version",
        help="Print version.",
        action="version",
        version=f"%(prog)s {version} (python {python_version})")
    exclusive.add_argument(
        "-i",
        "--install",
        help="install service files and config",
        action="store_true")
    exclusive.add_argument(
        "-u",
        "--uninstall",
        help="uninstall service files and unmodified config",
        action="store_true")
    exclusive.add_argument(
        "-t",
        "--test",
        help="Check configuration.",
        action="store_true")

    args = parser.parse_args()

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    # setup console log
    stdouthandler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("%(levelname)s: %(message)s")
    stdouthandler.setFormatter(formatter)
    root_logger.addHandler(stdouthandler)

    logger = logging.getLogger(__name__)

    if not args.debug:
        logger.setLevel(logging.INFO)

    name = "pyquarantine"
    if args.install:
        sys.exit(install(name))

    if args.uninstall:
        sys.exit(uninstall(name))

    try:
        logger.debug("read milter configuration")
        cfg = get_milter_config(args.config)
        logger.setLevel(cfg.get_loglevel(args.debug))

        if args.socket:
            socket = args.socket
        elif "socket" in cfg:
            socket = cfg["socket"]
        else:
            raise RuntimeError(
                "listening socket is neither specified on the command line "
                "nor in the configuration file")

        if not cfg["rules"]:
            raise RuntimeError("no rules configured")

        for rule in cfg["rules"]:
            if not rule["actions"]:
                raise RuntimeError(
                    f"{rule['name']}: no actions configured")
        QuarantineMilter.set_config(cfg, args.debug)

    except (RuntimeError, AssertionError) as e:
        logger.error(f"config error: {e}")
        sys.exit(255)

    if args.test:
        print("Configuration OK")
        sys.exit(0)

    # setup console log for runtime
    formatter = logging.Formatter("%(asctime)s - %(levelname)s: %(message)s")
    stdouthandler.setFormatter(formatter)
    stdouthandler.setLevel(logging.DEBUG)

    # setup syslog
    sysloghandler = logging.handlers.SysLogHandler(
        address="/dev/log", facility=logging.handlers.SysLogHandler.LOG_MAIL)
    sysloghandler.setFormatter(
        logging.Formatter(f"{name}[%(process)d]: %(message)s"))
    root_logger.addHandler(sysloghandler)

    logger.info("milter starting")

    # register milter factory class
    Milter.factory = QuarantineMilter
    Milter.set_exception_policy(Milter.TEMPFAIL)

    if args.debug:
        Milter.setdbg(1)

    # increase the recursion limit so that BeautifulSoup can
    # parse larger html content
    sys.setrecursionlimit(4000)

    rc = 0
    try:
        Milter.runmilter("pyquarantine", socketname=socket, timeout=600)
    except Milter.milter.error as e:
        logger.error(e)
        rc = 255

    mailer.queue.put(None)
    logger.info("milter stopped")

    sys.exit(rc)


if __name__ == "__main__":
    main()
