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
from email.charset import Charset
from email.header import Header, decode_header
from io import BytesIO

from pymodmilter.conditions import Conditions


def make_header(decoded_seq, maxlinelen=None, header_name=None,
                continuation_ws=' ', errors='strict'):
    """Create a Header from a sequence of pairs as returned by decode_header()

    decode_header() takes a header value string and returns a sequence of
    pairs of the format (decoded_string, charset) where charset is the string
    name of the character set.

    This function takes one of those sequence of pairs and returns a Header
    instance.  Optional maxlinelen, header_name, and continuation_ws are as in
    the Header constructor.
    """
    h = Header(maxlinelen=maxlinelen, header_name=header_name,
               continuation_ws=continuation_ws)
    for s, charset in decoded_seq:
        # None means us-ascii but we can simply pass it on to h.append()
        if charset is not None and not isinstance(charset, Charset):
            charset = Charset(charset)
        h.append(s, charset, errors=errors)
    return h


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

        self._needs = []
        for action in actions:
            for need in action.needs():
                if need not in self._needs:
                    self._needs.append(need)

        self.logger.debug("needs: {}".format(", ".join(self._needs)))

    def needs(self):
        """Return the needs of this rule."""
        return self._needs

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
            milter_action = action.execute(milter)
            if milter_action is not None:
                return milter_action


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
                f"an exception occured in connect function: {e}")
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
                f"an exception occured in envfrom function: {e}")
            return Milter.TEMPFAIL

        return Milter.CONTINUE

    @Milter.noreply
    def envrcpt(self, to, *str):
        try:
            self.recipients.add("@".join(parse_addr(to)).lower())
        except Exception as e:
            self.logger.exception(
                f"an exception occured in envrcpt function: {e}")
            return Milter.TEMPFAIL

        return Milter.CONTINUE

    def data(self):
        try:
            for rule in self.rules.copy():
                if rule.ignores(envto=[*self.recipients]):
                    self.rules.remove(rule)

            if not self.rules:
                self.logger.debug(
                    f"envelope-to addresses are ignored by all rules, "
                    f"skip further processing")
                return Milter.ACCEPT

            self.qid = self.getsymval('i')
            self.logger = CustomLogger(self.logger, {"qid": self.qid})
            self.logger.debug("received queue-id from MTA")

            self.fields = None
            self.fields_data = None
            self.body_data = None
            needs = []
            for rule in self.rules:
                needs += rule.needs()

            if "fields" in needs:
                self.fields = []

            if "original_fields" in needs:
                self.fields_data = BytesIO()

            if "body" in needs:
                self.body_data = BytesIO()

        except Exception as e:
            self.logger.exception(
                f"an exception occured in data function: {e}")
            return Milter.TEMPFAIL

        return Milter.CONTINUE

    def header(self, name, value):
        try:
            if self.fields_data != None:
                self.fields_data.write(
                    name.encode("ascii", errors="surrogateescape"))
                self.fields_data.write(b": ")
                self.fields_data.write(
                    value.encode("ascii", errors="surrogateescape"))
                self.fields_data.write(b"\r\n")

            if self.fields is not None:
                # remove surrogates from value
                value = value.encode(
                    errors="surrogateescape").decode(errors="replace")
                self.logger.debug(f"received header: {name}: {value}")
                header = make_header(decode_header(value), errors="replace")
                value = str(header).replace("\x00", "")
                self.logger.debug(f"decoded header: {name}: {value}")
                self.fields.append((name, value))
        except Exception as e:
            self.logger.exception(
                f"an exception occured in header function: {e}")
            return Milter.TEMPFAIL

        return Milter.CONTINUE

    def body(self, chunk):
        try:
            if self.body_data is not None:
                self.body_data.write(chunk)
        except Exception as e:
            self.logger.exception(
                f"an exception occured in body function: {e}")
            return Milter.TEMPFAIL

        return Milter.CONTINUE

    def eom(self):
        try:
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
                f"an exception occured in eom function: {e}")
            return Milter.TEMPFAIL

        return Milter.ACCEPT
