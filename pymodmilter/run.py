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
from pymodmilter.actions import Action


def main():
    "Run PyMod-Milter."
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

    loglevels = {
        "error": logging.ERROR,
        "warning": logging.WARNING,
        "info": logging.INFO,
        "debug": logging.DEBUG
    }

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    # setup console log
    stdouthandler = logging.StreamHandler(sys.stdout)
    stdouthandler.setFormatter(
        logging.Formatter("%(asctime)s - %(levelname)s: %(message)s"))
    root_logger.addHandler(stdouthandler)

    # setup syslog
    sysloghandler = logging.handlers.SysLogHandler(
        address="/dev/log", facility=logging.handlers.SysLogHandler.LOG_MAIL)
    sysloghandler.setFormatter(
        logging.Formatter("pymodmilter: %(message)s"))
    root_logger.addHandler(sysloghandler)

    logger = logging.getLogger(__name__)

    if not args.debug:
        logger.setLevel(logging.INFO)

    try:
        try:
            with open(args.config, "r") as fh:
                config = sub(r"(?m)^\s*#.*\n?", "", fh.read())
                config = loads(config)
        except Exception as e:
            for num, line in enumerate(config.splitlines()):
                logger.error(f"{num+1}: {line}")
            raise RuntimeError(
                f"unable to parse config file: {e}")

        if "global" not in config:
            config["global"] = {}

        if args.debug:
            loglevel = logging.DEBUG
        else:
            if "loglevel" not in config["global"]:
                config["global"]["loglevel"] = "info"
            loglevel = loglevels[config["global"]["loglevel"]]

        logger.setLevel(loglevel)

        logger.debug("prepar milter configuration")

        if "pretend" not in config["global"]:
            config["global"]["pretend"] = False

        if args.socket:
            socket = args.socket
        elif "socket" in config["global"]:
            socket = config["global"]["socket"]
        else:
            raise RuntimeError(
                f"listening socket is neither specified on the command line "
                f"nor in the configuration file")

        if "local_addrs" in config["global"]:
            local_addrs = config["global"]["local_addrs"]
        else:
            local_addrs = [
                "::1/128",
                "127.0.0.0/8",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16"]

        if "rules" not in config:
            raise RuntimeError(
                f"mandatory config section 'rules' not found")

        if not config["rules"]:
            raise RuntimeError("no rules configured")

        logger.debug("initialize rules ...")

        rules = []
        for rule_idx, rule in enumerate(config["rules"]):
            if "name" in rule:
                rule_name = rule["name"]
            else:
                rule_name = f"Rule #{rule_idx}"

            logger.debug(f"prepare rule {rule_name} ...")

            if "actions" not in rule:
                raise RuntimeError(
                    f"{rule_name}: mandatory config "
                    f"section 'actions' not found")

            if not rule["actions"]:
                raise RuntimeError("{rule_name}: no actions configured")

            if args.debug:
                rule_loglevel = logging.DEBUG
            elif "loglevel" in rule:
                rule_loglevel = loglevels[rule["loglevel"]]
            else:
                rule_loglevel = loglevels[config["global"]["loglevel"]]

            if "pretend" in rule:
                rule_pretend = rule["pretend"]
            else:
                rule_pretend = config["global"]["pretend"]

            actions = []
            for action_idx, action in enumerate(rule["actions"]):
                if "name" in action:
                    action_name = f"{rule_name}: {action['name']}"
                else:
                    action_name = f"Action #{action_idx}"

                if args.debug:
                    action_loglevel = logging.DEBUG
                elif "loglevel" in action:
                    action_loglevel = loglevels[action["loglevel"]]
                else:
                    action_loglevel = rule_loglevel

                if "pretend" in action:
                    action_pretend = action["pretend"]
                else:
                    action_pretend = rule_pretend

                if "type" not in action:
                    raise RuntimeError(
                        f"{rule_name}: {action_name}: mandatory config "
                        f"section 'actions' not found")

                if "conditions" not in action:
                    action["conditions"] = {}

                try:
                    actions.append(
                        Action(
                            name=action_name,
                            local_addrs=local_addrs,
                            conditions=action["conditions"],
                            action_type=action["type"],
                            args=action,
                            loglevel=action_loglevel,
                            pretend=action_pretend))
                except RuntimeError as e:
                    logger.error(f"{action_name}: {e}")
                    sys.exit(253)

            if "conditions" not in rule:
                rule["conditions"] = {}

            try:
                rules.append(
                    Rule(
                        name=rule_name,
                        local_addrs=local_addrs,
                        conditions=rule["conditions"],
                        actions=actions,
                        loglevel=rule_loglevel,
                        pretend=rule_pretend))
            except RuntimeError as e:
                logger.error(f"{rule_name}: {e}")
                sys.exit(254)

    except RuntimeError as e:
        logger.error(e)
        sys.exit(255)

    if args.test:
        print("Configuration ok")
        sys.exit(0)

    # setup console log for runtime
    formatter = logging.Formatter("%(asctime)s - %(levelname)s: %(message)s")
    stdouthandler.setFormatter(formatter)
    stdouthandler.setLevel(logging.DEBUG)

    logger.info("pymodmilter starting")
    ModifyMilter.set_rules(rules)
    ModifyMilter.set_loglevel(loglevel)

    # register milter factory class
    Milter.factory = ModifyMilter
    Milter.set_exception_policy(Milter.TEMPFAIL)

    if args.debug:
        Milter.setdbg(1)

    rc = 0
    try:
        Milter.runmilter("pymodmilter", socketname=socket, timeout=30)
    except Milter.milter.error as e:
        logger.error(e)
        rc = 255
    sys.exit(rc)


if __name__ == "__main__":
    main()
