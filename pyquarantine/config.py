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

__all__ = [
    "BaseConfig",
    "ConditionsConfig",
    "AddHeaderConfig",
    "ModHeaderConfig",
    "DelHeaderConfig",
    "AddDisclaimerConfig",
    "RewriteLinksConfig",
    "StoreConfig",
    "NotifyConfig",
    "WhitelistConfig",
    "QuarantineConfig",
    "ActionConfig",
    "RuleConfig",
    "QuarantineMilterConfig",
    "get_milter_config"]

import json
import jsonschema
import logging
import re


class BaseConfig:
    JSON_SCHEMA = {
        "type": "object",
        "required": [],
        "additionalProperties": True,
        "properties": {
            "loglevel": {"type": "string", "default": "info"}}}

    def __init__(self, config):
        required = self.JSON_SCHEMA["required"]
        properties = self.JSON_SCHEMA["properties"]
        for p in properties.keys():
            if p in required:
                continue
            elif p not in config and "default" in properties[p]:
                config[p] = properties[p]["default"]
        try:
            jsonschema.validate(config, self.JSON_SCHEMA)
        except jsonschema.exceptions.ValidationError as e:
            raise RuntimeError(e)

        self._config = config

    def __getitem__(self, key):
        return self._config[key]

    def __setitem__(self, key, value):
        self._config[key] = value

    def __delitem__(self, key):
        del self._config[key]

    def __contains__(self, key):
        return key in self._config

    def keys(self):
        return self._config.keys()

    def items(self):
        return self._config.items()

    def get_loglevel(self, debug):
        if debug:
            level = logging.DEBUG
        else:
            level = getattr(logging, self["loglevel"].upper(), None)
            assert isinstance(level, int), \
                "loglevel: invalid value"
        return level

    def get_config(self):
        return self._config


class WhitelistConfig(BaseConfig):
    JSON_SCHEMA = {
        "type": "object",
        "required": ["type"],
        "additionalProperties": True,
        "properties": {
            "type": {"enum": ["db"]}},
        "if": {"properties": {"type": {"const": "db"}}},
        "then": {
            "required": ["connection", "table"],
            "additionalProperties": False,
            "properties": {
                "type": {"type": "string"},
                "connection": {"type": "string"},
                "table": {"type": "string"}}}}


class ConditionsConfig(BaseConfig):
    JSON_SCHEMA = {
        "type": "object",
        "required": [],
        "additionalProperties": False,
        "properties": {
            "metavar": {"type": "string"},
            "local": {"type": "boolean"},
            "hosts": {"type": "array",
                      "items": {"type": "string"}},
            "envfrom": {"type": "string"},
            "envto": {"type": "string"},
            "headers": {"type": "array",
                        "items": {"type": "string"}},
            "var": {"type": "string"},
            "whitelist": {"type": "object"}}}

    def __init__(self, config, rec=True):
        super().__init__(config)
        if not rec:
            return
        if "whitelist" in self:
            self["whitelist"] = WhitelistConfig(self["whitelist"])


class AddHeaderConfig(BaseConfig):
    JSON_SCHEMA = {
        "type": "object",
        "required": ["field", "value"],
        "additionalProperties": False,
        "properties": {
            "field": {"type": "string"},
            "value": {"type": "string"}}}


class ModHeaderConfig(BaseConfig):
    JSON_SCHEMA = {
        "type": "object",
        "required": ["field", "value"],
        "additionalProperties": False,
        "properties": {
            "field": {"type": "string"},
            "value": {"type": "string"},
            "search": {"type": "string"}}}


class DelHeaderConfig(BaseConfig):
    JSON_SCHEMA = {
        "type": "object",
        "required": ["field"],
        "additionalProperties": False,
        "properties": {
            "field": {"type": "string"},
            "value": {"type": "string"}}}


class AddDisclaimerConfig(BaseConfig):
    JSON_SCHEMA = {
        "type": "object",
        "required": ["action", "html_template", "text_template"],
        "additionalProperties": False,
        "properties": {
            "action": {"type": "string"},
            "html_template": {"type": "string"},
            "text_template": {"type": "string"},
            "error_policy": {"type": "string", "default": "wrap"},
            "add_html_body": {"type": "boolean", "default": False}}}


class RewriteLinksConfig(BaseConfig):
    JSON_SCHEMA = {
        "type": "object",
        "required": ["repl"],
        "additionalProperties": False,
        "properties": {
            "repl": {"type": "string"}}}


class StoreConfig(BaseConfig):
    JSON_SCHEMA = {
        "type": "object",
        "required": ["type"],
        "additionalProperties": True,
        "properties": {
            "type": {"enum": ["file"]}},
        "if": {"properties": {"type": {"const": "file"}}},
        "then": {
            "required": ["directory"],
            "additionalProperties": False,
            "properties": {
                "type": {"type": "string"},
                "directory": {"type": "string"},
                "mode": {"type": "string"},
                "metavar": {"type": "string"},
                "metadata": {"type": "boolean", "default": False},
                "original": {"type": "boolean", "default": False}}}}


class NotifyConfig(BaseConfig):
    JSON_SCHEMA = {
        "type": "object",
        "required": ["type"],
        "additionalProperties": True,
        "properties": {
            "type": {"enum": ["email"]}},
        "if": {"properties": {"type": {"const": "email"}}},
        "then": {
            "required": ["smtp_host", "smtp_port", "envelope_from",
                         "from_header", "subject", "template"],
            "additionalProperties": False,
            "properties": {
                "type": {"type": "string"},
                "smtp_host": {"type": "string"},
                "smtp_port": {"type": "number"},
                "envelope_from": {"type": "string"},
                "from_header": {"type": "string"},
                "subject": {"type": "string"},
                "template": {"type": "string"},
                "repl_img": {"type": "string"},
                "strip_imgs": {"type": "boolean", "default": False},
                "embed_imgs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": []}}}}


class QuarantineConfig(BaseConfig):
    JSON_SCHEMA = {
        "type": "object",
        "required": ["store", "smtp_host", "smtp_port"],
        "additionalProperties": False,
        "properties": {
            "name": {"type": "string"},
            "notify": {"type": "object"},
            "milter_action": {"type": "string"},
            "reject_reason": {"type": "string"},
            "whitelist": {"type": "object"},
            "store": {"type": "object"},
            "smtp_host": {"type": "string"},
            "smtp_port": {"type": "number"}}}

    def __init__(self, config, rec=True):
        super().__init__(config)
        if not rec:
            return
        if "metadata" not in self["store"]:
            self["store"]["metadata"] = True
        self["store"] = StoreConfig(self["store"])
        if "notify" in self:
            self["notify"] = NotifyConfig(self["notify"])
        if "whitelist" in self:
            self["whitelist"] = ConditionsConfig(
                {"whitelist": self["whitelist"]}, rec)


class ActionConfig(BaseConfig):
    ACTION_TYPES = {
        "add_header": AddHeaderConfig,
        "mod_header": ModHeaderConfig,
        "del_header": DelHeaderConfig,
        "add_disclaimer": AddDisclaimerConfig,
        "rewrite_links": RewriteLinksConfig,
        "store": StoreConfig,
        "notify": NotifyConfig,
        "quarantine": QuarantineConfig}

    JSON_SCHEMA = {
        "type": "object",
        "required": ["name", "type", "options"],
        "additionalProperties": False,
        "properties": {
            "name": {"type": "string"},
            "loglevel": {"type": "string", "default": "info"},
            "pretend": {"type": "boolean", "default": False},
            "conditions": {"type": "object"},
            "type": {"enum": list(ACTION_TYPES.keys())},
            "options": {"type": "object"}}}

    def __init__(self, config, rec=True):
        super().__init__(config)
        if not rec:
            return
        if "conditions" in self:
            self["conditions"] = ConditionsConfig(self["conditions"])
        self["action"] = self.ACTION_TYPES[self["type"]](self["options"])


class RuleConfig(BaseConfig):
    JSON_SCHEMA = {
        "type": "object",
        "required": ["name", "actions"],
        "additionalProperties": False,
        "properties": {
            "name": {"type": "string"},
            "loglevel": {"type": "string", "default": "info"},
            "pretend": {"type": "boolean", "default": False},
            "conditions": {"type": "object"},
            "actions": {"type": "array"}}}

    def __init__(self, config, rec=True):
        super().__init__(config)
        if not rec:
            return
        if "conditions" in self:
            self["conditions"] = ConditionsConfig(self["conditions"])

        actions = []
        for idx, action in enumerate(self["actions"]):
            if "loglevel" not in action:
                action["loglevel"] = config["loglevel"]
            if "pretend" not in action:
                action["pretend"] = config["pretend"]
            actions.append(ActionConfig(action, rec))
        self["actions"] = actions


class QuarantineMilterConfig(BaseConfig):
    JSON_SCHEMA = {
        "type": "object",
        "required": ["rules"],
        "additionalProperties": False,
        "properties": {
            "socket": {"type": "string"},
            "local_addrs": {"type": "array",
                            "items": {"type": "string"},
                            "default": [
                                "fe80::/64",
                                "::1/128",
                                "127.0.0.0/8",
                                "10.0.0.0/8",
                                "172.16.0.0/12",
                                "192.168.0.0/16"]},
            "loglevel": {"type": "string", "default": "info"},
            "pretend": {"type": "boolean", "default": False},
            "rules": {"type": "array"}}}

    def __init__(self, config, rec=True):
        super().__init__(config)
        if not rec:
            return
        rules = []
        for idx, rule in enumerate(self["rules"]):
            if "loglevel" not in rule:
                rule["loglevel"] = config["loglevel"]
            if "pretend" not in rule:
                rule["pretend"] = config["pretend"]
            rules.append(RuleConfig(rule, rec))
        self["rules"] = rules


def get_milter_config(cfgfile, raw=False):
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
        raise RuntimeError(f"{e}\n{msg}")
    if raw:
        return cfg
    return QuarantineMilterConfig(cfg)
