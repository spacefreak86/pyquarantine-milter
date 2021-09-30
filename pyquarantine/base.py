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
    "CustomLogger",
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
