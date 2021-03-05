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
    "BaseConfig",
    "ActionConfig",
    "RuleConfig",
    "ModifyMilterConfig"]

import json
import logging
import re

from bs4 import BeautifulSoup
from netaddr import IPNetwork, AddrFormatError


class BaseConfig:
    def __init__(self, cfg={}, debug=False):
        self._cfg = {}
        if "name" in cfg:
            assert isinstance(cfg["name"], str), \
                "rule: name: invalid value, should be string"
            self["name"] = cfg["name"]
        else:
            self["name"] = ""

        if debug:
            self["loglevel"] = logging.DEBUG
        elif "loglevel" in cfg:
            level = getattr(logging, cfg["loglevel"].upper(), None)
            assert isinstance(level, int), \
                f"{self['name']}: loglevel: invalid value"
            self["loglevel"] = level
        else:
            self["loglevel"] = logging.INFO

        # the keys/values of args are used as parameters
        # to functions
        self["args"] = {}

    def __setitem__(self, key, value):
        self._cfg[key] = value

    def __getitem__(self, key):
        return self._cfg[key]

    def __delitem__(self, key):
        del self._cfg[key]

    def __contains__(self, key):
        return key in self._cfg

    def add_string_arg(self, cfg, args):
        if isinstance(args, str):
            args = [args]

        for arg in args:
            assert arg in cfg, \
                f"{self['name']}: mandatory parameter '{arg}' not found"
            assert isinstance(cfg[arg], str), \
                f"{self['name']}: {arg}: invalid value, should be string"
            self["args"][arg] = cfg[arg]

    def add_bool_arg(self, cfg, args):
        if isinstance(args, str):
            args = [args]

        for arg in args:
            assert arg in cfg, \
                f"{self['name']}: mandatory parameter '{arg}' not found"
            assert isinstance(cfg[arg], bool), \
                f"{self['name']}: {arg}: invalid value, should be bool"
            self["args"][arg] = cfg[arg]


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


class ActionConfig(BaseConfig):
    def __init__(self, idx, rule_cfg, cfg, debug):
        if "name" in cfg:
            cfg["name"] = f"{rule_cfg['name']}: {cfg['name']}"
        else:
            cfg["name"] = f"{rule_cfg['name']}: Action #{idx}"

        if "loglevel" not in cfg:
            cfg["loglevel"] = rule_cfg["loglevel"]

        super().__init__(cfg, debug)

        self["pretend"] = rule_cfg["pretend"]
        self["conditions"] = None
        self["type"] = ""
        self["need_body"] = False

        if "pretend" in cfg:
            pretend = cfg["pretend"]
            assert isinstance(pretend, bool), \
                f"{self['name']}: pretend: invalid value, should be bool"
            self["pretend"] = pretend

        assert "type" in cfg, \
            f"{self['name']}: type: invalid value, should be string"
        assert cfg["type"] in \
            ("add_header", "del_header", "mod_header", "add_disclaimer",
             "rewrite_links", "store"), \
            f"{self['name']}: type: invalid action type"
        self["type"] = cfg["type"]

        if self["type"] == "add_header":
            self.add_string_arg(cfg, ("field", "value"))

        elif self["type"] == "mod_header":
            args = ["field", "value"]
            if "search" in cfg:
                args.append("search")

            for arg in args:
                self.add_string_arg(cfg, arg)
                if arg in ("field", "search"):
                    try:
                        self["args"][arg] = re.compile(
                            self["args"][arg],
                            re.MULTILINE + re.DOTALL + re.IGNORECASE)
                    except re.error as e:
                        raise ValueError(f"{self['name']}: {arg}: {e}")

        elif self["type"] == "del_header":
            args = ["field"]
            if "value" in cfg:
                args.append("value")

            for arg in args:
                self.add_string_arg(cfg, arg)
                try:
                    self["args"][arg] = re.compile(
                        self["args"][arg],
                        re.MULTILINE + re.DOTALL + re.IGNORECASE)
                except re.error as e:
                    raise ValueError(f"{self['name']}: {arg}: {e}")

        elif self["type"] == "add_disclaimer":
            if "error_policy" not in cfg:
                cfg["error_policy"] = "wrap"

            self.add_string_arg(
                cfg, ("action", "html_template", "text_template",
                      "error_policy"))
            assert self["args"]["action"] in ("append", "prepend"), \
                f"{self['name']}: action: invalid value, " \
                f"should be 'append' or 'prepend'"
            assert self["args"]["error_policy"] in ("wrap",
                                                    "ignore",
                                                    "reject"), \
                f"{self['name']}: error_policy: invalid value, " \
                f"should be 'wrap', 'ignore' or 'reject'"

            try:
                with open(self["args"]["html_template"], "r") as f:
                    html = BeautifulSoup(f.read(), "html.parser")
                    body = html.find('body')
                    if body:
                        # just use content within the body tag if present
                        html = body
                    self["args"]["html_template"] = html

                with open(self["args"]["text_template"], "r") as f:
                    self["args"]["text_template"] = f.read()

            except IOError as e:
                raise RuntimeError(
                    f"{self['name']}: unable to open/read template file: {e}")

            self["need_body"] = True

        elif self["type"] == "rewrite_links":
            self.add_string_arg(cfg, "repl")
            self["need_body"] = True

        elif self["type"] == "store":
            self.add_string_arg(cfg, "storage_type")
            assert self["storage_type"] in ("file"), \
                f"{self['name']}: storage_type: invalid value, " \
                f"should be 'file'"

            if self["args"]["storage_type"] == "file":
                self.add_string_arg(cfg, "directory")

            self["need_body"] = True


class RuleConfig(BaseConfig):
    def __init__(self, idx, milter_cfg, cfg, debug=False):
        if "name" not in cfg:
            cfg["name"] = f"Rule #{idx}"

        if "loglevel" not in cfg:
            cfg["loglevel"] = milter_cfg["loglevel"]

        super().__init__(cfg, debug)

        self["pretend"] = milter_cfg["pretend"]
        self["conditions"] = None
        self["actions"] = []

        if "pretend" in cfg:
            pretend = cfg["pretend"]
            assert isinstance(pretend, bool), \
                f"{self['name']}: pretend: invalid value, should be bool"
            self["pretend"] = pretend

        assert "actions" in cfg, \
            f"{self['name']}: mandatory parameter 'actions' not found"
        actions = cfg["actions"]
        assert isinstance(actions, list), \
            f"{self['name']}: actions: invalid value, should be list"

        for idx, action_cfg in enumerate(cfg["actions"]):
            self["actions"].append(
                ActionConfig(idx, self, action_cfg, debug))


class ModifyMilterConfig(BaseConfig):
    def __init__(self, cfgfile, debug=False):
        try:
            with open(cfgfile, "r") as fh:
                # remove lines with leading # (comments), they
                # are not allowed in json
                cfg = re.sub(r"(?m)^\s*#.*\n?", "", fh.read())
        except IOError as e:
            raise RuntimeError(f"unable to open/read config file: {e}")

        try:
            cfg = json.loads(cfg)
        except json.JSONDecodeError as e:
            cfg_text = [f"{n+1}: {l}" for n, l in enumerate(cfg.splitlines())]
            msg = "\n".join(cfg_text)
            e.msg = f"{msg}\n{e.msg}"
            raise e

        if "global" in cfg:
            assert isinstance(cfg["global"], dict), \
                "global: invalid type, should be dict"

            super().__init__(cfg["global"], debug)

            if "pretend" in cfg["global"]:
                pretend = cfg["global"]["pretend"]
                assert isinstance(pretend, bool), \
                    "global: pretend: invalid value, should be bool"
                self["pretend"] = pretend
            else:
                self["pretend"] = False

            if "socket" in cfg["global"]:
                socket = cfg["global"]["socket"]
                assert isinstance(socket, str), \
                    "global: socket: invalid value, should be string"
                self["socket"] = socket
            else:
                self["socket"] = None

            if "local_addrs" in cfg["global"]:
                local_addrs = cfg["global"]["local_addrs"]
                assert isinstance(local_addrs, list) and all(
                    [isinstance(addr, str) for addr in local_addrs]), \
                    "global: local_addrs: invalid value, " \
                    "should be list of strings"
                self["local_addrs"] = local_addrs
            else:
                self["local_addrs"] = [
                    "::1/128",
                    "127.0.0.0/8",
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16"]

        assert "rules" in cfg, \
            "mandatory parameter 'rules' not found"
        assert isinstance(cfg["rules"], list), \
            "rules: invalid value, should be list"

        self["rules"] = []
        for idx, rule_cfg in enumerate(cfg["rules"]):
            self["rules"].append(
                RuleConfig(idx, self, rule_cfg, debug))
