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

__all__ = ["Action"]

from pyquarantine import modify, notify, storage
from pyquarantine.conditions import Conditions


class Action:
    """Action to implement a pre-configured action to perform on e-mails."""
    ACTION_TYPES = {
        "add_header": modify.Modify,
        "mod_header": modify.Modify,
        "del_header": modify.Modify,
        "add_disclaimer": modify.Modify,
        "rewrite_links": modify.Modify,
        "store": storage.Store,
        "notify": notify.Notify,
        "quarantine": storage.Quarantine}

    def __init__(self, cfg, local_addrs, debug):
        self.cfg = cfg

        self.conditions = cfg["conditions"] if "conditions" in cfg else None
        if self.conditions is not None:
            self.conditions["name"] = f"{cfg['name']}: conditions"
            self.conditions["loglevel"] = cfg["loglevel"]
            self.conditions = Conditions(self.conditions, local_addrs, debug)

        action_type = cfg["type"]
        self.action = self.ACTION_TYPES[action_type](
            cfg, local_addrs, debug)

    def __str__(self):
        cfg = []
        for key in ["name", "loglevel", "pretend", "type"]:
            value = self.cfg[key]
            cfg.append(f"{key}={value}")
        if self.conditions is not None:
            cfg.append(f"conditions={self.conditions}")
        cfg.append(f"action={self.action}")
        return "Action(" + ", ".join(cfg) + ")"

    def headersonly(self):
        """Return the needs of this action."""
        return self.action._headersonly

    def execute(self, milter):
        """Execute configured action."""
        if self.conditions is None or \
                self.conditions.match(milter):
            return self.action.execute(milter)
