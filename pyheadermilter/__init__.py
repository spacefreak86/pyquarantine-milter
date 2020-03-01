# PyHeader-Milter is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# PyHeader-Milter is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with PyHeader-Milter.  If not, see <http://www.gnu.org/licenses/>.
#

__all__ = ["HeaderRule", "HeaderMilter"]

import Milter
import argparse
import configparser
import logging
import logging.handlers
import re
import sys

from Milter.utils import parse_addr
from email.message import EmailMessage
from email.parser import HeaderParser
from email.policy import default as default_policy
from netaddr import IPAddress, IPNetwork, AddrFormatError


class HeaderRule:
    """HeaderRule to implement a rule to apply on e-mail headers."""

    def __init__(self, name, action, header, search="", value="",
                 ignore_hosts=[], ignore_envfrom=None, only_hosts=[],
                 log=True):
        self.logger = logging.getLogger(__name__)
        self.name = name
        self.action = action
        self.header = header
        self.search = search
        self.value = value
        self.ignore_hosts = ignore_hosts
        self.ignore_envfrom = ignore_envfrom
        self.only_hosts = only_hosts
        self.log = log

        if action in ["del", "mod"]:
            # compile header regex
            try:
                self.header = re.compile(
                    header, re.MULTILINE + re.DOTALL + re.IGNORECASE)
            except re.error as e:
                raise RuntimeError(
                    f"unable to parse option 'header' of rule '{name}': {e}")

            if action == "mod":
                # compile search regex
                try:
                    self.search = re.compile(
                        search, re.MULTILINE + re.DOTALL + re.IGNORECASE)
                except re.error as e:
                    raise RuntimeError(
                        f"unable to parse option 'search' of "
                        f"rule '{name}': {e}")

        if action in ["add", "mod"] and not value:
            raise RuntimeError("value of option 'value' is empty")

        # replace strings in ignore_hosts and only_hosts with IPNetwork
        # instances
        try:
            for index, ignore in enumerate(ignore_hosts):
                self.ignore_hosts[index] = IPNetwork(ignore)
        except AddrFormatError as e:
            raise RuntimeError(
                f"unable to parse option 'ignore_hosts' of rule '{name}': {e}")

        if self.ignore_envfrom:
            try:
                self.ignore_envfrom = re.compile(ignore_envfrom, re.IGNORECASE)
            except re.error as e:
                raise RuntimeError(
                    f"unable to parse option 'ignore_envfrom' of "
                    f"rule '{name}': {e}")

        try:
            for index, only in enumerate(only_hosts):
                self.only_hosts[index] = IPNetwork(only)
        except AddrFormatError as e:
            raise RuntimeError(
                f"unable to parse option 'only_hosts' of rule '{name}': {e}")

    def ignore_host(self, host):
        ip = IPAddress(host)
        ignore = False

        # check if host matches ignore_hosts
        for ignored in self.ignore_hosts:
            if ip in ignored:
                ignore = True
                break

        if not ignore and self.only_hosts:
            # host does not match ignore_hosts, check if it matches only_hosts
            ignore = True
            for only in self.only_hosts:
                if ip in only:
                    ignore = False
                    break

        if ignore:
            self.logger.debug(f"host {host} is ignored by rule {self.name}")
        return ignore

    def ignore_from(self, envfrom):
        ignore = False

        if self.ignore_envfrom:
            if self.ignore_envfrom.search(envfrom):
                ignore = True
                self.logger.debug(
                    f"envelope-from {envfrom} is ignored by rule {self.name}")
        return ignore

    def execute(self, headers):
        """
        Execute rule on given headers and return list
        with modified headers.
        """
        if self.action == "add":
            return [(self.header, self.value, 0, 1)]

        modified = []
        index = 0
        occurrences = {}

        # iterate headers
        for name, header in headers:
            # keep track of the occurrence of each header, needed by
            # Milter.Base.chgheader
            if name not in occurrences.keys():
                occurrences[name] = 1
            else:
                occurrences[name] += 1

            value = header[name]
            # check if header line matches regex
            if self.header.search(f"{name}: {value}"):
                if self.action == "del":
                    # set an empty value to delete the header
                    new_value = ""
                else:
                    # Remove line breaks from new_value, EmailMessage object
                    # does not like them
                    new_value = self.search.sub(self.value, value).replace(
                            "\n", "").replace(
                            "\r", "")
                if value != new_value:
                    header = EmailMessage(policy=default_policy)
                    header.add_header(name, new_value)
                    modified.append((name, header, index, occurrences[name]))
            index += 1
        return modified


class HeaderMilter(Milter.Base):
    """HeaderMilter based on Milter.Base to implement milter communication"""

    _rules = []

    @staticmethod
    def set_rules(rules):
        HeaderMilter._rules = rules

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # save rules, it must not change during runtime
        self.rules = HeaderMilter._rules.copy()

    def connect(self, IPname, family, hostaddr):
        self.logger.debug(
            f"accepted milter connection from {hostaddr[0]} "
            f"port {hostaddr[1]}")
        ip = IPAddress(hostaddr[0])

        # remove rules which ignore this host
        for rule in self.rules.copy():
            if rule.ignore_host(ip):
                self.rules.remove(rule)

        if not self.rules:
            self.logger.debug(
                f"host {hostaddr[0]} is ignored by all rules, "
                f"skip further processing")
            return Milter.ACCEPT
        return Milter.CONTINUE

    def envfrom(self, mailfrom, *str):
        mailfrom = "@".join(parse_addr(mailfrom)).lower()
        for rule in self.rules.copy():
            if rule.ignore_from(mailfrom):
                self.rules.remove(rule)

        if not self.rules:
            self.logger.debug(
                f"mail from {mailfrom} is ignored by all rules, "
                f"skip further processing")
            return Milter.ACCEPT
        return Milter.CONTINUE

    @Milter.noreply
    def data(self):
        self.qid = self.getsymval('i')
        self.logger.debug(f"{self.qid}: received queue-id from MTA")
        self.headers = []
        return Milter.CONTINUE

    @Milter.noreply
    def header(self, name, value):
        # remove surrogates from value
        value = value.encode(errors="surrogateescape").decode(errors="replace")
        self.logger.debug(f"{self.qid}: received header: {name}: {value}")
        header = HeaderParser(
            policy=default_policy).parsestr(f"{name}: {value}")
        self.logger.debug(
            f"{self.qid}: decoded header: {name}: {header[name]}")
        self.headers.append((name, header))
        return Milter.CONTINUE

    def eom(self):
        try:
            for rule in self.rules:
                self.logger.debug(f"{self.qid}: executing rule '{rule.name}'")
                modified = rule.execute(self.headers)

                for name, header, index, occurrence in modified:
                    value = header[name]
                    # remove illegal characters, pymilter does not like them
                    enc_value = header.as_string().replace(
                        "\r", "").replace(
                        "\n", "").replace(
                        "\x00", "").split(
                        ":", 1)[1].strip()
                    mod_header = f"{name}: {value}"
                    if rule.action == "add":
                        if rule.log:
                            self.logger.info(
                                f"{self.qid}: add: header: {mod_header[0:70]}")
                        else:
                            self.logger.debug(
                                f"{self.qid}: add: header: {mod_header}")
                        self.headers.insert(0, (name, header))
                        self.addheader(name, enc_value, 1)
                    else:
                        if rule.action == "mod":
                            old_value = self.headers[index][1][name]
                            old_header = f"{name}: {old_value}"
                            if rule.log:
                                self.logger.info(
                                    f"{self.qid}: modify: header: "
                                    f"{old_header[0:70]}: {mod_header[0:70]}")
                            else:
                                self.logger.debug(
                                    f"{self.qid}: modify: header "
                                    f"(occ. {occurrence}): {old_header}: "
                                    f"{mod_header}")
                            self.headers[index] = (name, header)
                        elif rule.action == "del":
                            if rule.log:
                                self.logger.info(
                                    f"{self.qid}: delete: header: "
                                    f"{mod_header[0:70]}")
                            else:
                                self.logger.debug(
                                    f"{self.qid}: delete: header "
                                    f"(occ. {occurrence}): {mod_header}")
                            del self.headers[index]

                        self.chgheader(name, occurrence, enc_value)
            return Milter.ACCEPT
        except Exception as e:
            self.logger.exception(
                f"an exception occured in eom function: {e}")
            return Milter.TEMPFAIL


def main():
    "Run PyHeader-Milter."
    # parse command line
    parser = argparse.ArgumentParser(
        description="PyHeader milter daemon",
        formatter_class=lambda prog: argparse.HelpFormatter(
            prog, max_help_position=45, width=140))
    parser.add_argument(
        "-c", "--config", help="Config file to read.",
        default="/etc/pyheader-milter.conf")
    parser.add_argument(
        "-s",
        "--socket",
        help="Socket used to communicate with the MTA.",
        required=True)
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
    args = parser.parse_args()

    # setup logging
    loglevel = logging.INFO
    logname = "pyheader-milter"
    syslog_name = logname
    if args.debug:
        loglevel = logging.DEBUG
        logname = f"{logname}[%(name)s]"
        syslog_name = f"{syslog_name}: [%(name)s] %(levelname)s"

    # set config files for milter class
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
        parser = configparser.ConfigParser()
        if not parser.read(args.config):
            raise RuntimeError("config file not found")

        # check if mandatory config options in global section are present
        if "global" not in parser.sections():
            raise RuntimeError(
                "mandatory section 'global' not present in config file")
        for option in ["rules"]:
            if not parser.has_option("global", option):
                raise RuntimeError(
                    f"mandatory option '{option}' not present in config "
                    f"section 'global'")

        # read global config section
        global_config = dict(parser.items("global"))

        # read active rules
        active_rules = [r.strip() for r in global_config["rules"].split(",")]
        if len(active_rules) != len(set(active_rules)):
            raise RuntimeError(
                "at least one rule is specified multiple times "
                "in 'rules' option")
        if "global" in active_rules:
            active_rules.remove("global")
            logger.warning(
                "removed illegal rule name 'global' from list of "
                "active rules")
        if not active_rules:
            raise RuntimeError("no rules configured")

        logger.debug("preparing milter configuration ...")
        rules = []
        # iterate active rules
        for rule_name in active_rules:
            # check if config section exists
            if rule_name not in parser.sections():
                raise RuntimeError(
                    f"config section '{rule_name}' does not exist")
            config = dict(parser.items(rule_name))

            # check if mandatory option action is present in config
            option = "action"
            if option not in config.keys() and \
                    option in global_config.keys():
                config[option] = global_config[option]
            if option not in config.keys():
                raise RuntimeError(
                    f"mandatory option '{option}' not specified for "
                    f"rule '{rule_name}'")
            config["action"] = config["action"].lower()
            if config["action"] not in ["add", "del", "mod"]:
                raise RuntimeError(
                    f"invalid action specified for rule '{rule_name}'")

            # check if mandatory options are present in config
            mandatory = ["header"]
            if config["action"] == "add":
                mandatory += ["value"]
            elif config["action"] == "mod":
                mandatory += ["search", "value"]
            for option in mandatory:
                if option not in config.keys() and \
                        option in global_config.keys():
                    config[option] = global_config[option]
                if option not in config.keys():
                    raise RuntimeError(
                        f"mandatory option '{option}' not specified for "
                        f"rule '{rule_name}'")

            # check if optional config options are present in config
            defaults = {
                "ignore_hosts": [],
                "ignore_envfrom": None,
                "only_hosts": [],
                "log": "true"
            }
            for option in defaults.keys():
                if option not in config.keys() and \
                        option in global_config.keys():
                    config[option] = global_config[option]
                if option not in config.keys():
                    config[option] = defaults[option]
            if config["ignore_hosts"]:
                config["ignore_hosts"] = [
                    h.strip() for h in config["ignore_hosts"].split(",")]
            if config["only_hosts"]:
                config["only_hosts"] = [
                    h.strip() for h in config["only_hosts"].split(",")]
            config["log"] = config["log"].lower()
            if config["log"] == "true":
                config["log"] = True
            elif config["log"] == "false":
                config["log"] = False
            else:
                raise RuntimeError(
                    f"invalid value specified for option 'log' for "
                    f"rule '{rule_name}'")

            # add rule
            logging.debug(f"adding rule '{rule_name}'")
            rules.append(HeaderRule(name=rule_name, **config))

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

    logger.info("PyHeader-Milter starting")
    HeaderMilter.set_rules(rules)

    # register milter factory class
    Milter.factory = HeaderMilter
    Milter.set_exception_policy(Milter.TEMPFAIL)

    rc = 0
    try:
        Milter.runmilter("pyheader-milter", socketname=args.socket, timeout=30)
    except Milter.milter.error as e:
        logger.error(e)
        rc = 255
    logger.info("PyHeader-Milter terminated")
    sys.exit(rc)


if __name__ == "__main__":
    main()
