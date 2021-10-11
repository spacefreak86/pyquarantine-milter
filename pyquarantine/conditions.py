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

__all__ = ["Conditions"]

import logging
import re

from netaddr import IPAddress, IPNetwork, AddrFormatError
from pyquarantine import CustomLogger
from pyquarantine.whitelist import DatabaseWhitelist


class Conditions:
    """Conditions to implement conditions for rules and actions."""

    def __init__(self, cfg, local_addrs, debug):
        self.cfg = cfg
        self.local_addrs = local_addrs

        self.logger = logging.getLogger(cfg["name"])
        self.logger.setLevel(cfg.get_loglevel(debug))

        for arg in ("local", "hosts", "envfrom", "envto", "headers", "metavar",
                    "var"):
            if arg not in cfg:
                setattr(self, arg, None)
                continue

            if arg == "hosts":
                try:
                    self.hosts = []
                    for host in cfg["hosts"]:
                        self.hosts.append(IPNetwork(host))
                except AddrFormatError as e:
                    raise RuntimeError(e)
            elif arg in ("envfrom", "envto"):
                try:
                    setattr(self, arg, re.compile(
                        cfg[arg], re.IGNORECASE))
                except re.error as e:
                    raise RuntimeError(e)
            elif arg == "headers":
                try:
                    self.headers = []
                    for header in cfg["headers"]:
                        self.headers.append(re.compile(
                            header, re.IGNORECASE + re.DOTALL + re.MULTILINE))
                except re.error as e:
                    raise RuntimeError(e)
            else:
                setattr(self, arg, cfg[arg])

        self.whitelist = cfg["whitelist"] if "whitelist" in cfg else None
        if self.whitelist is not None:
            self.whitelist["name"] = f"{cfg['name']}: whitelist"
            self.whitelist["loglevel"] = cfg["loglevel"]
            if self.whitelist["type"] == "db":
                self.whitelist = DatabaseWhitelist(self.whitelist, debug)
            else:
                raise RuntimeError("invalid whitelist type")

    def __str__(self):
        cfg = []
        for arg in ("local", "hosts", "envfrom", "envto", "headers",
                    "var", "metavar"):
            if arg in self.cfg:
                cfg.append(f"{arg}={self.cfg[arg]}")
        if self.whitelist is not None:
            cfg.append(f"whitelist={self.whitelist}")
        return "Conditions(" + ", ".join(cfg) + ")"

    def get_whitelist(self):
        return self.whitelist

    def match_host(self, host):
        logger = CustomLogger(
            self.logger, {"name": self.cfg["name"]})
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
                    f"local does not match")
                return False

            logger.debug(
                f"local matches for host {host}")

        if self.hosts is not None:
            found = False
            for addr in self.hosts:
                if ip in addr:
                    found = True
                    break

            if not found:
                logger.debug(
                    f"ignore host {host}, "
                    f"hosts does not match")
                return False

            logger.debug(
                f"hosts matches for host {host}")

        return True

    def get_wl_rcpts(self, mailfrom, rcpts, logger):
        if not self.whitelist:
            return {}

        wl_rcpts = []
        for rcpt in rcpts:
            if self.whitelist.check(mailfrom, rcpt, logger):
                wl_rcpts.append(rcpt)

        return wl_rcpts

    def update_msginfo_from_match(self, milter, match):
        if self.metavar is None:
            return

        named_subgroups = match.groupdict(default=None)
        for group, value in named_subgroups.items():
            if value is None:
                continue
            name = f"{self.metavar}_{group}"
            milter.msginfo["vars"][name] = value

    def match(self, milter):
        logger = CustomLogger(
            self.logger, {"qid": milter.qid, "name": self.cfg["name"]})

        if self.envfrom is not None:
            envfrom = milter.msginfo["mailfrom"]
            if match := self.envfrom.match(envfrom):
                logger.debug(
                    f"envfrom matches for "
                    f"envelope-from address {envfrom}")
                self.update_msginfo_from_match(milter, match)
            else:
                logger.debug(
                    f"ignore envelope-from address {envfrom}, "
                    f"envfrom does not match")
                return False

        if self.envto is not None:
            envto = milter.msginfo["rcpts"]
            if not isinstance(envto, list):
                envto = [envto]

            for to in envto:
                match = self.envto.match(to)
                if not match:
                    logger.debug(
                        f"ignore envelope-to address {envto}, "
                        f"envto does not match")
                    return False

            logger.debug(
                f"envto matches for "
                f"envelope-to address {envto}")
            self.update_msginfo_from_match(milter, match)

        if self.headers is not None:
            headers = map(lambda h: f"{h[0]}: {h[1]}", milter.msg.items())
            for hdr in self.headers:
                matches = filter(None, map(lambda h: hdr.search(h), headers))
                if match := next(matches, None):
                    logger.debug(
                        f"headers matches for "
                        f"header: {match.string}")
                    self.update_msginfo_from_match(milter, match)
                    continue

                logger.debug(
                    "ignore message, "
                    "headers does not match")
                return False

        if self.var is not None:
            if self.var not in milter.msginfo["vars"]:
                return False

        return True
