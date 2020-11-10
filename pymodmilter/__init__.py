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
    "make_header",
    "actions",
    "conditions",
    "run",
    "version",
    "CustomLogger",
    "Rule",
    "ModifyMilter"]

import Milter
import logging

from Milter.utils import parse_addr
from email.message import Message
from email.parser import BytesFeedParser
from email.policy import default as default_policy

from pymodmilter.conditions import Conditions


class CustomLogger(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        if "name" in self.extra:
            msg = "{}: {}".format(self.extra["name"], msg)

        if "qid" in self.extra:
            msg = "{}: {}".format(self.extra["qid"], msg)

        if self.logger.getEffectiveLevel() != logging.DEBUG:
            msg = msg.replace("\n", "").replace("\r", "")

        return msg, kwargs


class Rule:
    """
    Rule to implement multiple actions on emails.
    """

    def __init__(self, name, local_addrs, conditions, actions, pretend=False,
                 loglevel=logging.INFO):
        logger = logging.getLogger(name)
        self.logger = CustomLogger(logger, {"name": name})
        self.logger.setLevel(loglevel)

        if logger is None:
            logger = logging.getLogger(__name__)

        self.logger = CustomLogger(logger, {"name": name})
        self.conditions = Conditions(
            local_addrs=local_addrs,
            args=conditions,
            logger=self.logger)
        self.actions = actions
        self.pretend = pretend

        self._need_body = False
        for action in actions:
            if action.need_body():
                self._need_body = True
                break

    def need_body(self):
        """Return the if this rule needs the message body."""
        return self._need_body

    def ignores(self, host=None, envfrom=None, envto=None):
        args = {}

        if host is not None:
            args["host"] = host

        if envfrom is not None:
            args["envfrom"] = envfrom

        if envto is not None:
            args["envto"] = envto

        if self.conditions.match(args):
            for action in self.actions:
                if action.conditions.match(args):
                    return False

        return True

    def execute(self, milter, msg, pretend=None):
        """Execute all actions of this rule."""
        if pretend is None:
            pretend = self.pretend

        for action in self.actions:
            milter_action = action.execute(milter, msg, pretend=pretend)
            if milter_action is not None:
                return milter_action


class MilterMessage(Message):
    def replace_header(self, _name, _value, occ=None):
        _name = _name.lower()
        counter = 0
        for i, (k, v) in zip(range(len(self._headers)), self._headers):
            if k.lower() == _name:
                counter += 1
                if not occ or counter == occ:
                    self._headers[i] = self.policy.header_store_parse(
                        k, _value)
                    break

        else:
            raise KeyError(_name)

    def remove_header(self, name, occ=None):
        name = name.lower()
        newheaders = []
        counter = 0
        for k, v in self._headers:
            if k.lower() == name:
                counter += 1
                if counter != occ:
                    newheaders.append((k, v))
            else:
                newheaders.append((k, v))

        self._headers = newheaders


def remove_surrogates(string):
    return string.encode(
        "ascii", errors="surrogateescape").decode(
            "ascii", errors="replace")


class ModifyMilter(Milter.Base):
    """ModifyMilter based on Milter.Base to implement milter communication"""

    _rules = []
    _loglevel = logging.INFO

    @staticmethod
    def set_rules(rules):
        ModifyMilter._rules = rules

    def set_loglevel(level):
        ModifyMilter._loglevel = level

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(ModifyMilter._loglevel)

        # save rules, it must not change during runtime
        self.rules = ModifyMilter._rules.copy()

    def connect(self, IPname, family, hostaddr):
        try:
            if hostaddr is None:
                self.logger.error("unable to proceed, host address is None")
                return Milter.TEMPFAIL

            self.logger.debug(
                f"accepted milter connection from {hostaddr[0]} "
                f"port {hostaddr[1]}")

            # remove rules which ignore this host
            for rule in self.rules.copy():
                if rule.ignores(host=hostaddr[0]):
                    self.rules.remove(rule)

            if not self.rules:
                self.logger.debug(
                    f"host {hostaddr[0]} is ignored by all rules, "
                    f"skip further processing")
                return Milter.ACCEPT
        except Exception as e:
            self.logger.exception(
                f"an exception occured in connect method: {e}")
            return Milter.TEMPFAIL

        return Milter.CONTINUE

    def envfrom(self, mailfrom, *str):
        try:
            mailfrom = "@".join(parse_addr(mailfrom)).lower()
            for rule in self.rules.copy():
                if rule.ignores(envfrom=mailfrom):
                    self.rules.remove(rule)

            if not self.rules:
                self.logger.debug(
                    f"envelope-from address {mailfrom} is ignored by "
                    f"all rules, skip further processing")
                return Milter.ACCEPT

            self.recipients = set()
        except Exception as e:
            self.logger.exception(
                f"an exception occured in envfrom method: {e}")
            return Milter.TEMPFAIL

        return Milter.CONTINUE

    @Milter.noreply
    def envrcpt(self, to, *str):
        try:
            self.recipients.add("@".join(parse_addr(to)).lower())
        except Exception as e:
            self.logger.exception(
                f"an exception occured in envrcpt method: {e}")
            return Milter.TEMPFAIL

        return Milter.CONTINUE

    def data(self):
        try:
            for rule in self.rules.copy():
                if rule.ignores(envto=[*self.recipients]):
                    self.rules.remove(rule)

            if not self.rules:
                self.logger.debug(
                    "envelope-to addresses are ignored by all rules, "
                    "skip further processing")
                return Milter.ACCEPT

            self.qid = self.getsymval('i')
            self.logger = CustomLogger(self.logger, {"qid": self.qid})
            self.logger.debug("received queue-id from MTA")

            self.fields = None
            self.fields_bytes = None
            self.body_data = None

            self._fp = BytesFeedParser(
                _factory=MilterMessage, policy=default_policy)
            self._keep_body = False
            for rule in self.rules:
                if rule.need_body():
                    self._keep_body = True
                    break

        except Exception as e:
            self.logger.exception(
                f"an exception occured in data method: {e}")
            return Milter.TEMPFAIL

        return Milter.CONTINUE

    def header(self, field, value):
        try:
            # feed header line to BytesParser
            self._fp.feed(field + b": " + value + b"\r\n")

            # remove surrogates from field and value
            field = remove_surrogates(field)
            value = remove_surrogates(value)
        except Exception as e:
            self.logger.exception(
                f"an exception occured in header method: {e}")
            return Milter.TEMPFAIL

        return Milter.CONTINUE

    def eoh(self):
        try:
            self._fp.feed(b"\r\n")
        except Exception as e:
            self.logger.exception(
                f"an exception occured in eoh method: {e}")
            return Milter.TEMPFAIL

        return Milter.CONTINUE

    def body(self, chunk):
        try:
            if self._keep_body:
                self._fp.feed(chunk)
        except Exception as e:
            self.logger.exception(
                f"an exception occured in body method: {e}")
            return Milter.TEMPFAIL

        return Milter.CONTINUE

    def eom(self):
        try:
            msg = self._fp.close()

            for rule in self.rules:
                milter_action = rule.execute(self, msg)

                if milter_action is not None:
                    if milter_action["action"] == "reject":
                        self.setreply("554", "5.7.0", milter_action["reason"])
                        return Milter.REJECT

                    if milter_action["action"] == "accept":
                        return Milter.ACCEPT

                    if milter_action["action"] == "discard":
                        return Milter.DISCARD

        except Exception as e:
            self.logger.exception(
                f"an exception occured in eom method: {e}")
            return Milter.TEMPFAIL

        return Milter.ACCEPT
