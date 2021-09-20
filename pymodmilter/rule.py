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
    def __init__(self, cfg, debug=False):
        super().__init__(cfg, debug)

        self.conditions = None
        self.actions = []

        self.pretend = False
        if "pretend" in cfg:
            assert isinstance(cfg["pretend"], bool), \
                f"{self.name}: pretend: invalid value, should be bool"
            self.pretend = cfg["pretend"]

        assert "actions" in cfg, \
            f"{self.name}: mandatory parameter 'actions' not found"
        actions = cfg["actions"]
        assert isinstance(actions, list), \
            f"{self.name}: actions: invalid value, should be list"

        self.logger.debug(f"{self.name}: pretend={self.pretend}, "
                          f"loglevel={self.loglevel}")

        if "conditions" in cfg:
            assert isinstance(cfg["conditions"], dict), \
                f"{self.name}: conditions: invalid value, should be dict"
            cfg["conditions"]["name"] = f"{self.name}: condition"
            if "loglevel" not in cfg["conditions"]:
                cfg["conditions"]["loglevel"] = self.loglevel
            self.conditions = ConditionsConfig(cfg["conditions"], debug)
        else:
            self.conditions = None

        for idx, action_cfg in enumerate(cfg["actions"]):
            if "name" in action_cfg:
                assert isinstance(action_cfg["name"], str), \
                    f"{self.name}: Action #{idx}: name: invalid value, " \
                    f"should be string"
                action_cfg["name"] = f"{self.name}: {action_cfg['name']}"
            else:
                action_cfg["name"] = f"{self.name}: Action #{idx}"

            if "loglevel" not in action_cfg:
                action_cfg["loglevel"] = self.loglevel
            if "pretend" not in action_cfg:
                action_cfg["pretend"] = self.pretend
            self.actions.append(
                ActionConfig(action_cfg, debug))


class Rule:
    """
    Rule to implement multiple actions on emails.
    """

    def __init__(self, cfg, local_addrs):
        self.logger = cfg.logger

        if cfg.conditions is None:
            self.conditions = None
        else:
            self.conditions = Conditions(cfg.conditions, local_addrs)

        self.actions = []
        for action_cfg in cfg.actions:
            self.actions.append(Action(action_cfg, local_addrs))

        self.pretend = cfg.pretend

    def execute(self, milter):
        """Execute all actions of this rule."""
        if self.conditions is None or \
                self.conditions.match(milter):
            for action in self.actions:
                milter_action = action.execute(milter)
                if milter_action is not None:
                    return milter_action
