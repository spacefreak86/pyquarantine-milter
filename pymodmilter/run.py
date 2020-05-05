# PyMod-Milter is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# PyMod-Milter is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with PyMod-Milter.  If not, see <http://www.gnu.org/licenses/>.
#


import Milter
import argparse
import logging
import logging.handlers
import sys

from json import loads
from re import sub

from pymodmilter import Rule, ModifyMilter
from pymodmilter.version import __version__ as version


def main():
    "Run PyMod-Milter."
    # parse command line
    parser = argparse.ArgumentParser(
        description="PyMod milter daemon",
        formatter_class=lambda prog: argparse.HelpFormatter(
            prog, max_help_position=45, width=140))
    parser.add_argument(
        "-c", "--config", help="Config file to read.",
        default="/etc/pymodmilter/pymodmilter.conf")
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
    parser.add_argument(
        "-t",
        "--test",
        help="Check configuration.",
        action="store_true")
    parser.add_argument(
        "-v", "--version",
        help="Print version.",
        action="version",
        version=f"%(prog)s ({version})")
    args = parser.parse_args()

    # setup logging
    loglevel = logging.INFO
    logname = "pymodmilter"
    syslog_name = logname
    if args.debug:
        loglevel = logging.DEBUG
        logname = f"{logname}[%(name)s]"
        syslog_name = f"{syslog_name}: [%(name)s] %(levelname)s"

    root_logger = logging.getLogger()
    root_logger.setLevel(loglevel)

    # setup console log
    stdouthandler = logging.StreamHandler(sys.stdout)
    stdouthandler.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(message)s")
    stdouthandler.setFormatter(formatter)
    root_logger.addHandler(stdouthandler)
    logger = logging.getLogger(__name__)

    try:
        # read config file
        logger.debug("parsing config file")
        try:
            with open(args.config, "r") as fh:
                config = loads(
                    sub(r"(?m)^\s*#.*\n?", "", fh.read()))
        except Exception as e:
            raise RuntimeError(
                f"unable to parse config file: {e}")

        logger.debug("preparing milter configuration ...")

        # default values for global config if not set
        if "global" not in config:
            config["global"] = {}

        if args.socket:
            socket = args.socket
        elif "socket" in config["global"]:
            socket = config["global"]["socket"]
        else:
            raise RuntimeError(
                f"listening socket is neither specified on the command line "
                f"nor in the configuration file")

        if "local_addrs" not in config["global"]:
            config["global"]["local_addrs"] = [
                "127.0.0.0/8",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16"]

        if "log" not in config["global"]:
            config["global"]["log"] = True

        if "pretend" not in config["global"]:
            config["global"]["pretend"] = False

        # check if mandatory sections are present in config
        for section in ["rules"]:
            if section not in config:
                raise RuntimeError(
                    f"mandatory config section '{section}' not found")

        if not config["rules"]:
            raise RuntimeError("no rules configured")

        rules = []
        # iterate configured rules
        for rule_idx, rule in enumerate(config["rules"]):
            params = {}
            # set default values if not specified in config
            if "name" in rule:
                params["name"] = rule["name"]
            else:
                params["name"] = f"Rule #{rule_idx}"

            if "log" in rule:
                params["log"] = rule["log"]
            else:
                params["log"] = config["global"]["log"]

            if "pretend" in rule:
                params["pretend"] = rule["pretend"]
            else:
                params["pretend"] = config["global"]["pretend"]

            if "local_addrs" in rule:
                params["local_addrs"] = rule["local_addrs"]
            else:
                params["local_addrs"] = config["global"]["local_addrs"]

            if "conditions" in rule:
                params["conditions"] = rule["conditions"]

            if "modifications" in rule:
                params["modifications"] = rule["modifications"]
            else:
                raise RuntimeError(
                    f"{rule['name']}: mandatory config section "
                    f"'modifications' not found")

            rules.append(Rule(**params))

    except RuntimeError as e:
        logger.error(e)
        sys.exit(255)

    if args.test:
        print("Configuration ok")
        sys.exit(0)

    # change log format for runtime
    formatter = logging.Formatter(
        f"%(asctime)s {logname}: [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S")
    stdouthandler.setFormatter(formatter)

    # setup syslog
    sysloghandler = logging.handlers.SysLogHandler(
        address="/dev/log", facility=logging.handlers.SysLogHandler.LOG_MAIL)
    sysloghandler.setLevel(loglevel)
    formatter = logging.Formatter(f"{syslog_name}: %(message)s")
    sysloghandler.setFormatter(formatter)
    root_logger.addHandler(sysloghandler)

    logger.info("pymodmilter starting")
    ModifyMilter.set_rules(rules)

    # register milter factory class
    Milter.factory = ModifyMilter
    Milter.set_exception_policy(Milter.TEMPFAIL)

    rc = 0
    try:
        Milter.runmilter("pymodmilter", socketname=socket, timeout=30)
    except Milter.milter.error as e:
        logger.error(e)
        rc = 255
    logger.info("pymodmilter terminated")
    sys.exit(rc)


if __name__ == "__main__":
    main()
