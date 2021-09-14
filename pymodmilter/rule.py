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
    "RuleConfig",
    "Rule"]

from pymodmilter import BaseConfig
from pymodmilter.action import ActionConfig, Action
from pymodmilter.conditions import ConditionsConfig, Conditions


class RuleConfig(BaseConfig):
    def __init__(self, idx, milter_cfg, cfg, debug=False):
        if "name" in cfg:
            assert isinstance(cfg["name"], str), \
                f"Rule #{idx}: name: invalid value, should be string"
        else:
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

        self.logger.debug(f"{self['name']}: pretend={self['pretend']}, "
                          f"loglevel={self['loglevel']}")

        if "conditions" in cfg:
            conditions = cfg["conditions"]
            assert isinstance(conditions, dict), \
                f"{self['name']}: conditions: invalid value, should be dict"
            self["conditions"] = ConditionsConfig(self, conditions, debug)

        for idx, action_cfg in enumerate(cfg["actions"]):
            self["actions"].append(
                ActionConfig(idx, self, action_cfg, debug))


class Rule:
    """
    Rule to implement multiple actions on emails.
    """

    def __init__(self, milter_cfg, cfg):
        self.logger = cfg.logger

        if cfg["conditions"] is None:
            self.conditions = None
        else:
            self.conditions = Conditions(milter_cfg, cfg["conditions"])

        self.actions = []
        for action_cfg in cfg["actions"]:
            self.actions.append(Action(milter_cfg, action_cfg))

        self.pretend = cfg["pretend"]

    def execute(self, milter):
        """Execute all actions of this rule."""
        if self.conditions is None or \
                self.conditions.match(milter):
            for action in self.actions:
                milter_action = action.execute(milter)
                if milter_action is not None:
                    return milter_action
