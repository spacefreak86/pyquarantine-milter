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

from pymodmilter import BaseConfig
from pymodmilter import modify, notify, storage
from pymodmilter.base import CustomLogger
from pymodmilter.conditions import ConditionsConfig, Conditions


class ActionConfig(BaseConfig):
    TYPES = {"add_header": "_add_header",
             "mod_header": "_mod_header",
             "del_header": "_del_header",
             "add_disclaimer": "_add_disclaimer",
             "rewrite_links": "_rewrite_links",
             "store": "_store",
             "notify": "_notify",
             "quarantine": "_quarantine"}

    def __init__(self, cfg, local_addrs, debug):
        super().__init__(cfg, debug)

        self.local_addrs = local_addrs
        self.debug = debug

        self.pretend = False
        if "pretend" in cfg:
            assert isinstance(cfg["pretend"], bool), \
                f"{self.name}: pretend: invalid value, should be bool"
            self.pretend = cfg["pretend"]

        assert "type" in cfg, \
            f"{self.name}: mandatory parameter 'type' not found"
        assert isinstance(cfg["type"], str), \
            f"{self.name}: type: invalid value, should be string"
        assert cfg["type"] in ActionConfig.TYPES, \
            f"{self.name}: type: invalid action type"

        getattr(self, ActionConfig.TYPES[cfg["type"]])(cfg)

        if "conditions" in cfg:
            assert isinstance(cfg["conditions"], dict), \
                f"{self.name}: conditions: invalid value, should be dict"
            cfg["conditions"]["name"] = f"{self.name}: condition"
            if "loglevel" not in cfg["conditions"]:
                cfg["conditions"]["loglevel"] = self.loglevel
            self.conditions = ConditionsConfig(
                cfg["conditions"], local_addrs, debug)
        else:
            self.conditions = None

        self.logger.debug(f"{self.name}: pretend={self.pretend}, "
                          f"loglevel={self.loglevel}, "
                          f"type={cfg['type']}, "
                          f"args={self.args}")

    def _add_header(self, cfg):
        self.action = modify.AddHeader
        self.add_string_arg(cfg, ["field", "value"])

    def _mod_header(self, cfg):
        self.action = modify.ModHeader
        args = ["field", "value"]
        if "search" in cfg:
            args.append("search")

        self.add_string_arg(cfg, args)

    def _del_header(self, cfg):
        self.action = modify.DelHeader
        args = ["field"]
        if "value" in cfg:
            args.append("value")

        self.add_string_arg(cfg, args)

    def _add_disclaimer(self, cfg):
        self.action = modify.AddDisclaimer
        if "error_policy" not in cfg:
            cfg["error_policy"] = "wrap"

        self.add_string_arg(
            cfg, ["action", "html_template", "text_template",
                  "error_policy"])
        assert self.args["action"] in ["append", "prepend"], \
            f"{self.name}: action: invalid value, " \
            f"should be 'append' or 'prepend'"
        assert self.args["error_policy"] in ("wrap",
                                             "ignore",
                                             "reject"), \
            f"{self.name}: error_policy: invalid value, " \
            f"should be 'wrap', 'ignore' or 'reject'"

    def _rewrite_links(self, cfg):
        self.action = modify.RewriteLinks
        self.add_string_arg(cfg, "repl")

    def _store(self, cfg):
        assert "storage_type" in cfg, \
            f"{self.name}: mandatory parameter 'storage_type' not found"
        assert isinstance(cfg["storage_type"], str), \
            f"{self.name}: storage_type: invalid value, " \
            f"should be string"

        if "original" in cfg:
            self.add_bool_arg(cfg, "original")

        if cfg["storage_type"] == "file":
            self.action = storage.FileMailStorage
            self.add_string_arg(cfg, "directory")

            if "metavar" in cfg:
                self.add_string_arg(cfg, "metavar")

        else:
            raise RuntimeError(
                f"{self.name}: storage_type: invalid storage type")

    def _notify(self, cfg):
        self.action = notify.EMailNotification

        args = ["smtp_host", "envelope_from", "from_header", "subject",
                "template"]
        if "repl_img" in cfg:
            args.append("repl_img")
        self.add_string_arg(cfg, args)

        self.add_int_arg(cfg, "smtp_port")

        if "embed_imgs" in cfg:
            assert isinstance(cfg["embed_imgs"], list) and all(
                [isinstance(img, str) for img in cfg["embed_imgs"]]), \
                f"{self.name}: embed_imgs: invalid value, " \
                f"should be list of strings"
            self.args["embed_imgs"] = cfg["embed_imgs"]

    def _quarantine(self, cfg):
        self.action = storage.Quarantine
        assert "storage" in cfg, \
            f"{self.name}: mandatory parameter 'storage' not found"
        assert isinstance(cfg["storage"], dict), \
            f"{self.name}: storage: invalid value, " \
            f"should be dict"
        cfg["storage"]["type"] = "store"
        cfg["storage"]["name"] = f"{self.name}: storage"

        args = ["storage"]
        if "notification" in cfg:
            assert isinstance(cfg["notification"], dict), \
                f"{self.name}: notification: invalid value, " \
                f"should be dict"
            cfg["notification"]["type"] = "notify"
            cfg["notification"]["name"] = f"{self.name}: notification"
            args.append("notification")

        for arg in args:
            if "loglevel" not in cfg[arg]:
                cfg[arg]["loglevel"] = self.loglevel
            if "pretend" not in cfg[arg]:
                cfg[arg]["pretend"] = self.pretend

            self.args[arg] = ActionConfig(
                cfg[arg], self.local_addrs, self.debug)

        if "milter_action" in cfg:
            self.add_string_arg(cfg, "milter_action")
            self.args["milter_action"] = self.args["milter_action"].upper()
            assert self.args["milter_action"] in ["REJECT", "DISCARD",
                                                  "ACCEPT"], \
                f"{self.name}: milter_action: invalid value, " \
                f"should be 'ACCEPT', 'REJECT' or 'DISCARD'"
            if self.args["milter_action"] == "REJECT":
                if "reject_reason" in cfg:
                    self.add_string_arg(cfg, "reject_reason")

        if "whitelist" in cfg:
            wl = {"whitelist": cfg["whitelist"]}
            wl["name"] = f"{self.name}: whitelist"
            if "loglevel" not in wl:
                wl["loglevel"] = self.loglevel
            self.args["whitelist"] = ConditionsConfig(
                wl, self.local_addrs, self.debug)


class Action:
    """Action to implement a pre-configured action to perform on e-mails."""

    def __init__(self, cfg):
        self.logger = cfg.logger
        if cfg.conditions is None:
            self.conditions = None
        else:
            self.conditions = Conditions(cfg.conditions)

        self.pretend = cfg.pretend
        self.name = cfg.name
        self.action = cfg.action(**cfg.args)

    def headersonly(self):
        """Return the needs of this action."""
        return self.action._headersonly

    def execute(self, milter):
        """Execute configured action."""
        logger = CustomLogger(
            self.logger, {"qid": milter.qid, "name": self.name})
        if self.conditions is None or \
                self.conditions.match(milter):
            return self.action.execute(
                milter=milter, pretend=self.pretend, logger=logger)
