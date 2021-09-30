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

__all__ = ["Rule"]

from pyquarantine.action import Action
from pyquarantine.conditions import Conditions


class Rule:
    """
    Rule to implement multiple actions on emails.
    """
    def __init__(self, cfg, local_addrs, debug):
        self.cfg = cfg

        self.conditions = cfg["conditions"] if "conditions" in cfg else None
        if self.conditions is not None:
            self.conditions["name"] = f"{cfg['name']}: condition"
            self.conditions["loglevel"] = cfg["loglevel"]
            self.conditions = Conditions(self.conditions, local_addrs, debug)

        self.actions = []
        for idx, action_cfg in enumerate(cfg["actions"]):
            action_cfg["name"] = f"{cfg['name']}: {action_cfg['name']}"
            self.actions.append(Action(action_cfg, local_addrs, debug))

    def __str__(self):
        cfg = []
        for key in ["name", "loglevel", "pretend"]:
            value = self.cfg[key]
            cfg.append(f"{key}={value}")
        if self.conditions is not None:
            cfg.append(f"conditions={self.conditions}")
        actions = []
        for action in self.actions:
            actions.append(str(action))
        cfg.append("actions=[" + ", ".join(actions) + "]")
        return "Rule(" + ", ".join(cfg) + ")"

    def execute(self, milter):
        """Execute all actions of this rule."""
        if self.conditions is None or \
                self.conditions.match(milter):
            for action in self.actions:
                milter_action = action.execute(milter)
                if milter_action is not None:
                    return milter_action
