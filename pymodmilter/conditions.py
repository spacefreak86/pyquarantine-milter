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

__all__ = [
    "ConditionsConfig",
    "Conditions"]

import re

from netaddr import IPAddress, IPNetwork, AddrFormatError
from pymodmilter import BaseConfig, CustomLogger
from pymodmilter.whitelist import DatabaseWhitelist


class ConditionsConfig(BaseConfig):
    def __init__(self, cfg, local_addrs, debug):
        super().__init__(cfg, debug)

        self.local_addrs = local_addrs

        if "local" in cfg:
            self.add_bool_arg(cfg, "local")

        if "hosts" in cfg:
            assert isinstance(cfg["hosts"], list) and all(
                [isinstance(host, str) for host in cfg["hosts"]]), \
                f"{self.name}: hosts: invalid value, " \
                f"should be list of strings"

            self.args["hosts"] = cfg["hosts"]

        for arg in ("envfrom", "envto"):
            if arg in cfg:
                self.add_string_arg(cfg, arg)

        if "header" in cfg:
            self.add_string_arg(cfg, "header")

        if "var" in cfg:
            self.add_string_arg(cfg, "var")

        if "metavar" in cfg:
            self.add_string_arg(cfg, "metavar")

        if "whitelist" in cfg:
            assert isinstance(cfg["whitelist"], dict), \
                f"{self.name}: whitelist: invalid value, " \
                f"should be dict"
            whitelist = cfg["whitelist"]
            assert "type" in whitelist, \
                f"{self.name}: whitelist: mandatory parameter 'type' not found"
            assert isinstance(whitelist["type"], str), \
                f"{self.name}: whitelist: type: invalid value, " \
                f"should be string"
            self.args["whitelist"] = {
                "type": whitelist["type"],
                "name": f"{self.name}: whitelist"}
            if whitelist["type"] == "db":
                for arg in ["connection", "table"]:
                    assert arg in whitelist, \
                        f"{self.name}: whitelist: mandatory parameter " \
                        f"'{arg}' not found"
                    assert isinstance(whitelist[arg], str), \
                        f"{self.name}: whitelist: {arg}: invalid value, " \
                        f"should be string"
                    self.args["whitelist"][arg] = whitelist[arg]

            else:
                raise RuntimeError(
                    f"{self.name}: whitelist: type: invalid type")

        self.logger.debug(f"{self.name}: "
                          f"loglevel={self.loglevel}, "
                          f"args={self.args}")


class Conditions:
    """Conditions to implement conditions for rules and actions."""

    def __init__(self, cfg):
        self.logger = cfg.logger
        self.name = cfg.name
        self.local_addrs = cfg.local_addrs

        for arg in ("local", "hosts", "envfrom", "envto", "header", "metavar",
                    "var"):
            value = cfg.args[arg] if arg in cfg.args else None
            setattr(self, arg, value)
            if value is None:
                continue
            elif arg == "hosts":
                try:
                    hosts = []
                    for host in self.hosts:
                        hosts.append(IPNetwork(host))
                except AddrFormatError as e:
                    raise RuntimeError(e)

                self.hosts = hosts
            elif arg in ("envfrom", "envto"):
                try:
                    setattr(self, arg, re.compile(
                        getattr(self, arg), re.IGNORECASE))
                except re.error as e:
                    raise RuntimeError(e)

            elif arg == "header":
                try:
                    self.header = re.compile(
                        self.header, re.IGNORECASE + re.DOTALL + re.MULTILINE)
                except re.error as e:
                    raise RuntimeError(e)

        if "whitelist" in cfg.args:
            wl_cfg = cfg.args["whitelist"]
            if wl_cfg["type"] == "db":
                self.whitelist = DatabaseWhitelist(wl_cfg)
            else:
                raise RuntimeError("invalid storage type")

    def match_host(self, host):
        logger = CustomLogger(
            self.logger, {"name": self.name})

        ip = IPAddress(host)

        if self.local is not None:
            is_local = False
            for addr in self.local_addrs:
                if ip in addr:
                    is_local = True
                    break

            if is_local != self.local:
                logger.debug(
                    f"ignore host {host}, "
                    f"condition local does not match")
                return False

            logger.debug(
                f"condition local matches for host {host}")

        if self.hosts is not None:
            found = False
            for addr in self.hosts:
                if ip in addr:
                    found = True
                    break

            if not found:
                logger.debug(
                    f"ignore host {host}, "
                    f"condition hosts does not match")
                return False

            logger.debug(
                f"condition hosts matches for host {host}")

        return True

    def get_wl_rcpts(self, mailfrom, rcpts):
        if not self.whitelist:
            return {}

        wl_rcpts = []
        for rcpt in rcpts:
            if self.whitelist.check(mailfrom, rcpt):
                wl_rcpts.append(rcpt)

        return wl_rcpts

    def match(self, milter):
        logger = CustomLogger(
            self.logger, {"qid": milter.qid, "name": self.name})

        if self.envfrom is not None:
            envfrom = milter.msginfo["mailfrom"]
            if not self.envfrom.match(envfrom):
                logger.debug(
                    f"ignore envelope-from address {envfrom}, "
                    f"condition envfrom does not match")
                return False

            logger.debug(
                f"condition envfrom matches for "
                f"envelope-from address {envfrom}")

        if self.envto is not None:
            envto = milter.msginfo["rcpts"]
            if not isinstance(envto, list):
                envto = [envto]

            for to in envto:
                if not self.envto.match(to):
                    logger.debug(
                        f"ignore envelope-to address {envto}, "
                        f"condition envto does not match")
                    return False

            logger.debug(
                f"condition envto matches for "
                f"envelope-to address {envto}")

        if self.header is not None:
            match = None
            for field, value in milter.msg.items():
                header = f"{field}: {value}"
                match = self.header.search(header)
                if match:
                    logger.debug(
                        f"condition header matches for "
                        f"header: {header}")
                    if self.metavar is not None:
                        named_subgroups = match.groupdict(default=None)
                        for group, value in named_subgroups.items():
                            if value is None:
                                continue
                            name = f"{self.metavar}_{group}"
                            milter.msginfo["vars"][name] = value
                    break

            if not match:
                logger.debug(
                    "ignore message, "
                    "condition header does not match")
                return False

        if self.var is not None:
            if self.var not in milter.msginfo["vars"]:
                return False

        return True
