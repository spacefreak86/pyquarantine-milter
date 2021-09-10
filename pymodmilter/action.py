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
    "ActionConfig",
    "Action"]

import os

from pymodmilter import CustomLogger, BaseConfig
from pymodmilter.conditions import ConditionsConfig, Conditions
from pymodmilter import modify, storage


class ActionConfig(BaseConfig):
    def __init__(self, idx, rule_cfg, cfg, debug):
        if "name" in cfg:
            assert isinstance(cfg["name"], str), \
                f"{rule_cfg['name']}: Action #{idx}: name: invalid value, " \
                f"should be string"
            cfg["name"] = f"{rule_cfg['name']}: {cfg['name']}"
        else:
            cfg["name"] = f"{rule_cfg['name']}: Action #{idx}"

        if "loglevel" not in cfg:
            cfg["loglevel"] = rule_cfg["loglevel"]

        super().__init__(cfg, debug)

        self["pretend"] = rule_cfg["pretend"]
        self["conditions"] = None
        self["type"] = ""

        if "pretend" in cfg:
            pretend = cfg["pretend"]
            assert isinstance(pretend, bool), \
                f"{self['name']}: pretend: invalid value, should be bool"
            self["pretend"] = pretend

        assert "type" in cfg, \
            f"{self['name']}: mandatory parameter 'type' not found"
        assert isinstance(cfg["type"], str), \
            f"{self['name']}: type: invalid value, should be string"
        self["type"] = cfg["type"]

        if self["type"] == "add_header":
            self["class"] = modify.AddHeader
            self["headersonly"] = True
            self.add_string_arg(cfg, ["field", "value"])
        elif self["type"] == "mod_header":
            self["class"] = modify.ModHeader
            self["headersonly"] = True
            args = ["field", "value"]
            if "search" in cfg:
                args.append("search")

            self.add_string_arg(cfg, args)
        elif self["type"] == "del_header":
            self["class"] = modify.DelHeader
            self["headersonly"] = True
            args = ["field"]
            if "value" in cfg:
                args.append("value")

            self.add_string_arg(cfg, args)
        elif self["type"] == "add_disclaimer":
            self["class"] = modify.AddDisclaimer
            self["headersonly"] = False
            if "error_policy" not in cfg:
                cfg["error_policy"] = "wrap"

            self.add_string_arg(
                cfg, ["action", "html_template", "text_template",
                      "error_policy"])
            assert self["args"]["action"] in ["append", "prepend"], \
                f"{self['name']}: action: invalid value, " \
                f"should be 'append' or 'prepend'"
            assert self["args"]["error_policy"] in ("wrap",
                                                    "ignore",
                                                    "reject"), \
                f"{self['name']}: error_policy: invalid value, " \
                f"should be 'wrap', 'ignore' or 'reject'"

        elif self["type"] == "rewrite_links":
            self["class"] = modify.RewriteLinks
            self["headersonly"] = False
            self.add_string_arg(cfg, "repl")

        elif self["type"] == "store":
            self["headersonly"] = False

            assert "storage_type" in cfg, \
                f"{self['name']}: mandatory parameter 'storage_type' not found"
            assert isinstance(cfg["type"], str), \
                f"{self['name']}: storage_type: invalid value, " \
                f"should be string"
            self["storage_type"] = cfg["storage_type"]

            if "original" in cfg:
                self.add_bool_arg(cfg, "original")

            if self["storage_type"] == "file":
                self["class"] = storage.FileMailStorage
                self.add_string_arg(cfg, "directory")
                # check if directory exists and is writable
                if not os.path.isdir(self["args"]["directory"]) or \
                        not os.access(self["args"]["directory"], os.W_OK):
                    raise RuntimeError(
                        f"{self['name']}: file quarantine directory "
                        f"'{self['directory']}' does not exist or is "
                        f"not writable")

                if "skip_metadata" in cfg:
                    self.add_bool_arg(cfg, "skip_metadata")

                if "metavar" in cfg:
                    self.add_string_arg(cfg, "metavar")

            else:
                raise RuntimeError(
                    f"{self['name']}: storage_type: invalid storage type")

        else:
            raise RuntimeError(f"{self['name']}: type: invalid action type")

        if "conditions" in cfg:
            conditions = cfg["conditions"]
            assert isinstance(conditions, dict), \
                f"{self['name']}: conditions: invalid value, should be dict"
            self["conditions"] = ConditionsConfig(self, conditions, debug)

        self.logger.debug(f"pretend={self['pretend']}, "
                          f"loglevel={self['loglevel']}, "
                          f"type={self['type']}, "
                          f"args={self['args']}")


class Action:
    """Action to implement a pre-configured action to perform on e-mails."""

    def __init__(self, milter_cfg, cfg):
        self.logger = cfg.logger

        if cfg["conditions"] is None:
            self.conditions = None
        else:
            self.conditions = Conditions(milter_cfg, cfg["conditions"])

        self.pretend = cfg["pretend"]
        self._name = cfg["name"]
        self._class = cfg["class"](**cfg["args"])
        self._headersonly = cfg["headersonly"]

    def headersonly(self):
        """Return the needs of this action."""
        return self._headersonly

    def execute(self, milter):
        """Execute configured action."""
        if self.conditions is None or \
                self.conditions.match(envfrom=milter.mailfrom,
                                      envto=[*milter.rcpts],
                                      headers=milter.msg.items()):
            logger = CustomLogger(
                self.logger, {"name": self._name, "qid": milter.qid})
            return self._class.execute(
                milter=milter, pretend=self.pretend, logger=logger)
