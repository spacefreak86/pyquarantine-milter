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
    "replace_illegal_chars"]

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
    def __init__(self, cfg={}, debug=False, logger=None):
        self._cfg = {}
        if "name" in cfg:
            assert isinstance(cfg["name"], str), \
                "rule: name: invalid value, should be string"
            self["name"] = cfg["name"]
        else:
            self["name"] = __name__

        if debug:
            self["loglevel"] = logging.DEBUG
        elif "loglevel" in cfg:
            if isinstance(cfg["loglevel"], int):
                self["loglevel"] = cfg["loglevel"]
            else:
                level = getattr(logging, cfg["loglevel"].upper(), None)
                assert isinstance(level, int), \
                    f"{self['name']}: loglevel: invalid value"
                self["loglevel"] = level
        else:
            self["loglevel"] = logging.INFO

        if logger is None:
            logger = logging.getLogger(self["name"])
            logger.setLevel(self["loglevel"])

        self.logger = logger

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
    """Replace illegal characters in header values."""
    return string.replace(
        "\x00", "").replace(
        "\r", "").replace(
        "\n", "")
