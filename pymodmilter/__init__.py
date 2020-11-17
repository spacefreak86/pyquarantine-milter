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
    "actions",
    "conditions",
    "run",
    "CustomLogger",
    "Rule",
    "ModifyMilter"]

__version__ = "1.1.3"

import Milter
import logging
import encodings

from Milter.utils import parse_addr
from email.message import MIMEPart
from email.parser import BytesFeedParser
from email.policy import default as default_policy

from pymodmilter.conditions import Conditions

########################################################
#  monkey-patch pythons email library bug 27257,30988  #
########################################################
#
# https://bugs.python.org/issue27257
# https://bugs.python.org/issue30988
#
# fix: https://github.com/python/cpython/pull/15600

import email._header_value_parser
from email._header_value_parser import TokenList, NameAddr
from email._header_value_parser import get_display_name, get_angle_addr
from email._header_value_parser import get_cfws, errors
from email._header_value_parser import CFWS_LEADER, PHRASE_ENDS


class DisplayName(email._header_value_parser.DisplayName):
    @property
    def display_name(self):
        res = TokenList(self)
        if len(res) == 0:
            return res.value
        if res[0].token_type == 'cfws':
            res.pop(0)
        else:
            if isinstance(res[0], TokenList) and \
                    res[0][0].token_type == 'cfws':
                res[0] = TokenList(res[0][1:])
        if res[-1].token_type == 'cfws':
            res.pop()
        else:
            if isinstance(res[-1], TokenList) and \
                    res[-1][-1].token_type == 'cfws':
                res[-1] = TokenList(res[-1][:-1])
        return res.value


def get_name_addr(value):
    """ name-addr = [display-name] angle-addr

    """
    name_addr = NameAddr()
    # Both the optional display name and the angle-addr can start with cfws.
    leader = None
    if value[0] in CFWS_LEADER:
        leader, value = get_cfws(value)
        if not value:
            raise errors.HeaderParseError(
                "expected name-addr but found '{}'".format(leader))
    if value[0] != '<':
        if value[0] in PHRASE_ENDS:
            raise errors.HeaderParseError(
                "expected name-addr but found '{}'".format(value))
        token, value = get_display_name(value)
        if not value:
            raise errors.HeaderParseError(
                "expected name-addr but found '{}'".format(token))
        if leader is not None:
            if isinstance(token[0], TokenList):
                token[0][:0] = [leader]
            else:
                token[:0] = [leader]
            leader = None
        name_addr.append(token)
    token, value = get_angle_addr(value)
    if leader is not None:
        token[:0] = [leader]
    name_addr.append(token)
    return name_addr, value


setattr(email._header_value_parser, "DisplayName", DisplayName)
setattr(email._header_value_parser, "get_name_addr", get_name_addr)

################################################
#  add charset alias for windows-874 encoding  #
################################################

aliases = encodings.aliases.aliases

for alias in ["windows-874", "windows_874"]:
    if alias not in aliases:
        aliases[alias] = "cp874"

setattr(encodings.aliases, "aliases", aliases)

################################################


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

    def execute(self, milter, pretend=None):
        """Execute all actions of this rule."""
        if pretend is None:
            pretend = self.pretend

        for action in self.actions:
            milter_action = action.execute(milter, pretend=pretend)
            if milter_action is not None:
                return milter_action


class MilterMessage(MIMEPart):
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
            # remove surrogates
            field = field.encode("ascii", errors="replace")
            value = value.encode("ascii", errors="replace")

            self._fp.feed(field + b": " + value + b"\r\n")
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
            self.msg = self._fp.close()
            for rule in self.rules:
                milter_action = rule.execute(self)

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
