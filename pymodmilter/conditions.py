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
from pymodmilter import BaseConfig


class ConditionsConfig(BaseConfig):
    def __init__(self, parent_cfg, cfg, debug):
        if "loglevel" not in cfg:
            cfg["loglevel"] = parent_cfg["loglevel"]

        cfg["name"] = f"{parent_cfg['name']}: condition"

        super().__init__(cfg, debug)

        if "local" in cfg:
            self.add_bool_arg(cfg, "local")

        if "hosts" in cfg:
            hosts = cfg["hosts"]
            assert isinstance(hosts, list) and all(
                [isinstance(host, str) for host in hosts]), \
                f"{self['name']}: hosts: invalid value, " \
                f"should be list of strings"

            self["args"]["hosts"] = []
            try:
                for host in cfg["hosts"]:
                    self["args"]["hosts"].append(IPNetwork(host))
            except AddrFormatError as e:
                raise ValueError(f"{self['name']}: hosts: {e}")

        for arg in ("envfrom", "envto"):
            if arg in cfg:
                self.add_string_arg(cfg, arg)
                try:
                    self["args"][arg] = re.compile(
                        self["args"][arg],
                        re.IGNORECASE)
                except re.error as e:
                    raise ValueError(f"{self['name']}: {arg}: {e}")

        self.logger.debug(f"{self['name']}: "
                          f"loglevel={self['loglevel']}, "
                          f"args={self['args']}")


class Conditions:
    """Conditions to implement conditions for rules and actions."""

    def __init__(self, milter_cfg, cfg):
        self.logger = cfg.logger

        self._local_addrs = milter_cfg["local_addrs"]
        self._args = cfg["args"]

    def match(self, args):
        if "host" in args:
            ip = IPAddress(args["host"])

            if "local" in self._args:
                is_local = False
                for addr in self._local_addrs:
                    if ip in addr:
                        is_local = True
                        break

                if is_local != self._args["local"]:
                    self.logger.debug(
                        f"ignore host {args['host']}, "
                        f"condition local does not match")
                    return False

                self.logger.debug(
                    f"condition local matches for host {args['host']}")

            if "hosts" in self._args:
                found = False
                for addr in self._args["hosts"]:
                    if ip in addr:
                        found = True
                        break

                if not found:
                    self.logger.debug(
                        f"ignore host {args['host']}, "
                        f"condition hosts does not match")
                    return False

                self.logger.debug(
                    f"condition hosts matches for host {args['host']}")

        if "envfrom" in args and "envfrom" in self._args:
            if not self._args["envfrom"].match(args["envfrom"]):
                self.logger.debug(
                    f"ignore envelope-from address {args['envfrom']}, "
                    f"condition envfrom does not match")
                return False

            self.logger.debug(
                f"condition envfrom matches for "
                f"envelope-from address {args['envfrom']}")

        if "envto" in args and "envto" in self._args:
            if not isinstance(args["envto"], list):
                args["envto"] = [args["envto"]]

            for envto in args["envto"]:
                if not self._args["envto"].match(envto):
                    self.logger.debug(
                        f"ignore envelope-to address {args['envto']}, "
                        f"condition envto does not match")
                    return False

            self.logger.debug(
                f"condition envto matches for "
                f"envelope-to address {args['envto']}")

        return True
