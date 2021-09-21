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
    "CustomLogger",
    "BaseConfig",
    "MilterMessage",
    "replace_illegal_chars",
    "config_schema"]

import logging

from email.message import MIMEPart


class CustomLogger(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        if "name" in self.extra:
            msg = f"{self.extra['name']}: {msg}"

        if "qid" in self.extra:
            msg = f"{self.extra['qid']}: {msg}"

        if self.logger.getEffectiveLevel() != logging.DEBUG:
            msg = msg.replace("\n", "").replace("\r", "")

        return msg, kwargs


class BaseConfig:
    def __init__(self, cfg={}, debug=False):
        if "name" in cfg:
            assert isinstance(cfg["name"], str), \
                "name: invalid value, should be string"
            self.name = cfg["name"]
        else:
            self.name = __name__

        self.logger = logging.getLogger(self.name)
        if debug:
            self.loglevel = logging.DEBUG
        elif "loglevel" in cfg:
            if isinstance(cfg["loglevel"], int):
                self.loglevel = cfg["loglevel"]
            else:
                level = getattr(logging, cfg["loglevel"].upper(), None)
                assert isinstance(level, int), \
                    f"{self.name}: loglevel: invalid value"
                self.loglevel = level
        else:
            self.loglevel = logging.INFO

        self.logger.setLevel(self.loglevel)
        self.debug = debug

        # the keys/values in args are used as parameters
        # to initialize action classes
        self.args = {}

    def add_string_arg(self, cfg, args):
        if isinstance(args, str):
            args = [args]

        for arg in args:
            assert arg in cfg, \
                f"{self.name}: mandatory parameter '{arg}' not found"
            assert isinstance(cfg[arg], str), \
                f"{self.name}: {arg}: invalid value, should be string"
            self.args[arg] = cfg[arg]

    def add_bool_arg(self, cfg, args):
        if isinstance(args, str):
            args = [args]

        for arg in args:
            assert arg in cfg, \
                f"{self.name}: mandatory parameter '{arg}' not found"
            assert isinstance(cfg[arg], bool), \
                f"{self.name}: {arg}: invalid value, should be bool"
            self.args[arg] = cfg[arg]

    def add_int_arg(self, cfg, args):
        if isinstance(args, str):
            args = [args]

        for arg in args:
            assert arg in cfg, \
                f"{self.name}: mandatory parameter '{arg}' not found"
            assert isinstance(cfg[arg], int), \
                f"{self.name}: {arg}: invalid value, should be integer"
            self.args[arg] = cfg[arg]


class MilterMessage(MIMEPart):
    def replace_header(self, _name, _value, idx=None):
        _name = _name.lower()
        counter = 0
        for i, (k, v) in zip(range(len(self._headers)), self._headers):
            if k.lower() == _name:
                counter += 1
                if not idx or counter == idx:
                    self._headers[i] = self.policy.header_store_parse(
                        k, _value)
                    break

        else:
            raise KeyError(_name)

    def remove_header(self, name, idx=None):
        name = name.lower()
        newheaders = []
        counter = 0
        for k, v in self._headers:
            if k.lower() == name:
                counter += 1
                if counter != idx:
                    newheaders.append((k, v))
            else:
                newheaders.append((k, v))

        self._headers = newheaders


def replace_illegal_chars(string):
    """Remove illegal characters from header values."""
    return "".join(string.replace("\x00", "").splitlines())


JSON_CONFIG_SCHEMA = """
{
    "$id": "https://example.com/schemas/config",
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Root",
    "type": "object",
    "required": ["rules"],
    "additionalProperties": false,
    "properties": {
        "global": {
            "title": "Section global",
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "local_addrs": { "$ref": "/schemas/config/hosts" },
                "loglevel":    { "$ref": "/schemas/config/loglevel" },
                "socket": {
                    "title": "Socket",
                    "type": "string",
                    "pattern": "^((unix|local):.+|inet6?:[0-9]{1,5}(@.+)?)$"
                }
            }
        },
        "rules": {
            "title": "Section rules",
            "type": "array",
            "items": {
                "title": "Rules",
                "type": "object",
                "required": [
                    "actions"
                ],
                "additionalProperties": false,
                "properties": {
                    "name":       { "$ref": "/schemas/config/name" },
                    "pretend":    { "$ref": "/schemas/config/pretend" },
                    "conditions": { "$ref": "/schemas/config/conditions" },
                    "loglevel":   { "$ref": "/schemas/config/loglevel" },
                    "actions": {
                        "title": "Section actions",
                        "type": "array",
                        "items": {
                            "title": "Actions",
                            "type": "object",
                            "required": ["type"],
                            "properties": {
                                "type": { "$ref": "/schemas/config/actiontype" }
                            },
                            "if": { "properties": { "type": { "const": "add_header" } } },
                            "then": { "$ref": "/schemas/config/add_header" },
                            "else": {
                                "if": { "properties": { "type": { "const": "mod_header" } } },
                                "then": { "$ref": "/schemas/config/mod_header" },
                                "else": {
                                    "if": { "properties": { "type": { "const": "del_header" } } },
                                    "then": { "$ref": "/schemas/config/del_header" },
                                    "else": {
                                        "if": { "properties": { "type": { "const": "add_disclaimer" } } },
                                        "then": { "$ref": "/schemas/config/add_disclaimer" },
                                        "else": {
                                            "if": { "properties": { "type": { "const": "rewrite_links" } } },
                                            "then": { "$ref": "/schemas/config/rewrite_links" },
                                            "else": {
                                                "if": { "properties": { "type": { "const": "store" } } },
                                                "then": { "$ref": "/schemas/config/store" },
                                                "else": {
                                                    "if": { "properties": { "type": { "const": "notify" } } },
                                                    "then": { "$ref": "/schemas/config/notify" },
                                                    "else": {
                                                        "if": { "properties": { "type": { "const": "quarantine" } } },
                                                        "then": { "$ref": "/schemas/config/quarantine" },
                                                        "else": {
                                                            "additionalProperties": false
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    },
    "$defs": {
        "name": {
            "$id": "/schemas/config/name",
            "title": "Name",
            "type": "string",
            "pattern": "^.+$"
        },
        "hosts": {
            "$id": "/schemas/config/hosts",
            "title": "Hosts/networks",
            "type": "array",
            "items": {
                "title": "Hosts/Networks",
                "type": "string",
                "pattern": "^.+$"
            }
        },
        "pretend": {
            "$id": "/schemas/config/pretend",
            "title": "Pretend",
            "type": "boolean"
        },
        "loglevel": {
            "$id": "/schemas/config/loglevel",
            "title": "Loglevel",
            "type": "string",
            "pattern": "^(critical|error|warning|info|debug)$"
        },
        "actiontype": {
            "$id": "/schemas/config/actiontype",
            "title": "Action type",
            "enum": [
                "add_header", "mod_header", "del_header", "add_disclaimer",
                "rewrite_links", "store", "notify", "quarantine"]
        },
        "storagetype": {
            "$id": "/schemas/config/storagetype",
            "title": "Storage type",
            "enum": ["file"]
        },
        "whitelisttype": {
            "$id": "/schemas/config/whitelisttype",
            "title": "Whitelist type",
            "enum": ["db"]
        },
        "field": {
            "$id": "/schemas/config/field",
            "title": "Field",
            "type": "string",
            "pattern": "^.+$"
        },
        "value": {
            "$id": "/schemas/config/value",
            "title": "Value",
            "type": "string",
            "pattern": "^.+$"
        },
        "original": {
            "$id": "/schemas/config/original",
            "title": "Original",
            "type": "boolean"
        },
        "metavar": {
            "$id": "/schemas/config/metavar",
            "title": "Meta variable",
            "type": "string",
            "pattern": "^.+$"
        },
        "conditions": {
            "$id": "/schemas/config/conditions",
            "title": "Conditions",
            "type": "object",
            "properties": {
                "metavar": { "$ref": "/schemas/config/metavar" },
                "local": {
                    "title": "Local",
                    "type": "boolean"
                },
                "hosts": {
                    "title": "Hosts/Networks",
                    "type": "array",
                    "items":{
                        "title": "Host/Network",
                        "type": "string",
                        "pattern": "^.+$"
                    }
                },
                "envfrom": {
                    "title": "Envelope from",
                    "type": "string",
                    "pattern": "^.+$"
                },
                "envto": {
                    "title": "Envelope to",
                    "type": "string",
                    "pattern": "^.+$"
                },
                "header": {
                    "title": "Header",
                    "type": "string",
                    "pattern": "^.+$"
                },
                "var": {
                    "title": "Variable",
                    "type": "string",
                    "pattern": "^.+$"
                }
            },
            "additionalProperties": false,
            "anyOf": [
                {"required": ["local"]},
                {"required": ["hosts"]},
                {"required": ["envfrom"]},
                {"required": ["envto"]},
                {"required": ["header"]},
                {"required": ["var"]}
            ]
        },
        "add_header": {
            "$id": "/schemas/config/add_header",
            "title": "Add header",
            "type": "object",
            "required": ["type", "field", "value"],
            "properties": {
                "type":       { "$ref": "/schemas/config/actiontype" },
                "name":       { "$ref": "/schemas/config/name" },
                "pretend":    { "$ref": "/schemas/config/pretend" },
                "conditions": { "$ref": "/schemas/config/conditions" },
                "loglevel":   { "$ref": "/schemas/config/loglevel" },
                "field":      { "$ref": "/schemas/config/field" },
                "value":      { "$ref": "/schemas/config/value" }
            },
            "additionalProperties": false
        },
        "mod_header": {
            "$id": "/schemas/config/mod_header",
            "title": "Modify header",
            "type": "object",
            "required": ["type", "field", "value"],
            "properties": {
                "type":       { "$ref": "/schemas/config/actiontype" },
                "name":       { "$ref": "/schemas/config/name" },
                "pretend":    { "$ref": "/schemas/config/pretend" },
                "conditions": { "$ref": "/schemas/config/conditions" },
                "loglevel":   { "$ref": "/schemas/config/loglevel" },
                "field":      { "$ref": "/schemas/config/field" },
                "value":      { "$ref": "/schemas/config/value" },
                "search": {
                    "title": "Search",
                    "type": "string",
                    "pattern": "^.+$"
                }
            },
            "additionalProperties": false
        },
        "del_header": {
            "$id": "/schemas/config/del_header",
            "title": "Delete header",
            "type": "object",
            "required": ["type", "field"],
            "properties": {
                "type":       { "$ref": "/schemas/config/actiontype" },
                "name":       { "$ref": "/schemas/config/name" },
                "pretend":    { "$ref": "/schemas/config/pretend" },
                "conditions": { "$ref": "/schemas/config/conditions" },
                "loglevel":   { "$ref": "/schemas/config/loglevel" },
                "field":      { "$ref": "/schemas/config/field" },
                "value":      { "$ref": "/schemas/config/value" }
            },
            "additionalProperties": false
        },
        "add_disclaimer": {
            "$id": "/schemas/config/add_disclaimer",
            "title": "Add disclaimer",
            "type": "object",
            "required": ["type", "action", "html_template", "text_template"],
            "properties": {
                "type":       { "$ref": "/schemas/config/actiontype" },
                "name":       { "$ref": "/schemas/config/name" },
                "pretend":    { "$ref": "/schemas/config/pretend" },
                "conditions": { "$ref": "/schemas/config/conditions" },
                "loglevel":   { "$ref": "/schemas/config/loglevel" },
                "action": {
                    "title": "Action",
                    "enum": ["append", "prepend"]
                },
                "html_template": {
                    "title": "HTML template",
                    "type": "string",
                    "pattern": "^.+$"
                },
                "text_template": {
                    "title": "Text template",
                    "type": "string",
                    "pattern": "^.+$"
                },
                "error_policy": {
                    "title": "Action",
                    "enum": [
                        "wrap", "ignore", "reject",
                        "WRAP", "IGNORE", "REJECT"]
                }
            },
            "additionalProperties": false
        },
        "rewrite_links": {
            "$id": "/schemas/config/rewrite_links",
            "title": "Rewrite links",
            "type": "object",
            "required": ["type", "repl"],
            "properties": {
                "type":       { "$ref": "/schemas/config/actiontype" },
                "name":       { "$ref": "/schemas/config/name" },
                "pretend":    { "$ref": "/schemas/config/pretend" },
                "conditions": { "$ref": "/schemas/config/conditions" },
                "loglevel":   { "$ref": "/schemas/config/loglevel" },
                "repl": {
                    "title": "Replacement",
                    "type": "string",
                    "pattern": "^.+$"
                }
            },
            "additionalProperties": false
        },
        "store": {
            "$id": "/schemas/config/store",
            "title": "Store",
            "type": "object",
            "required": ["storage_type"],
            "properties": {
                "storage_type": { "$ref": "/schemas/config/storagetype" }
            },
            "if": { "properties": { "storage_type": { "const": "file" } } },
            "then": {
                "properties": {
                    "type":       { "$ref": "/schemas/config/actiontype" },
                    "storage_type": { "$ref": "/schemas/config/storagetype" },
                    "name":       { "$ref": "/schemas/config/name" },
                    "pretend":    { "$ref": "/schemas/config/pretend" },
                    "conditions": { "$ref": "/schemas/config/conditions" },
                    "loglevel":   { "$ref": "/schemas/config/loglevel" },
                    "original":   { "$ref": "/schemas/config/original" },
                    "metavar":    { "$ref": "/schemas/config/metavar" },
                    "directory": {
                        "title": "Directory",
                        "type": "string",
                        "pattern": "^.+$"
                    }
                },
                "additionalProperties": false
            },
            "else": {
                "additionalProperties": false
            }
        },
        "notify": {
            "$id": "/schemas/config/notify",
            "title": "Notify",
            "type": "object",
            "required": ["smtp_host", "smtp_port", "envelope_from", "from_header", "subject", "template"],
            "properties": {
                "type":       { "$ref": "/schemas/config/actiontype" },
                "name":       { "$ref": "/schemas/config/name" },
                "pretend":    { "$ref": "/schemas/config/pretend" },
                "conditions": { "$ref": "/schemas/config/conditions" },
                "loglevel":   { "$ref": "/schemas/config/loglevel" },
                "smtp_host": {
                    "title": "SMTP host",
                    "type": "string",
                    "pattern": "^.+$"
                },
                "smtp_port":  {
                    "title": "SMTP port",
                    "type": "number"
                },
                "envelope_from":  {
                    "title": "Envelope from",
                    "type": "string",
                    "pattern": "^.+$"
                },
                "from_header":  {
                    "title": "From-Header",
                    "type": "string",
                    "pattern": "^.+$"
                },
                "subject":  {
                    "title": "Subject",
                    "type": "string",
                    "pattern": "^.+$"
                },
                "template":  {
                    "title": "Template",
                    "type": "string",
                    "pattern": "^.+$"
                },
                "repl_img":  {
                    "title": "Replacement image",
                    "type": "string",
                    "pattern": "^.+$"
                },
                "embed_imgs": {
                    "title": "Embedded images",
                    "type": "array",
                    "items": {
                        "title": "Embedded image",
                        "type": "string",
                        "pattern": "^.+$"
                    }
                }
            },
            "additionalProperties": false
        },
        "quarantine": {
            "$id": "/schemas/config/quarantine",
            "title": "Quarantine",
            "type": "object",
            "required": ["storage"],
            "properties": {
                "type":         { "$ref": "/schemas/config/actiontype" },
                "name":         { "$ref": "/schemas/config/name" },
                "pretend":      { "$ref": "/schemas/config/pretend" },
                "conditions":   { "$ref": "/schemas/config/conditions" },
                "loglevel":     { "$ref": "/schemas/config/loglevel" },
                "storage":      { "$ref": "/schemas/config/store" },
                "notification": { "$ref": "/schemas/config/notify" },
                "milter_action": {
                    "title": "Milter action",
                    "enum": [
                        "reject", "discard", "accept",
                        "REJECT", "DISCARD", "ACCEPT"]
                },
                "reject_reason": {
                    "title": "Reject reason",
                    "type": "string",
                    "pattern": "^.+$"
                },
                "whitelist": {
                    "title": "Whitelist",
                    "type": "object",
                    "required": ["type"],
                    "properties": {
                        "type": { "$ref": "/schemas/config/whitelisttype" }
                    },
                    "if": { "properties": { "type": { "const": "db" } } },
                    "then": {
                        "required": ["connection", "table"],
                        "properties": {
                            "type": { "$ref": "/schemas/config/whitelisttype" },
                            "connection": {
                                "title": "DB connection",
                                "type": "string",
                                "pattern": "^.+$"
                            },
                            "table": {
                                "title": "DB table",
                                "type": "string",
                                "pattern": "^.+$"
                            }
                        },
                        "additionalProperties": false
                    },
                    "else": {
                        "additionalProperties": false
                    }
                }
            }
        }
    }
}
"""
