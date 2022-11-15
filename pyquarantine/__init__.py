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
    "action",
    "base",
    "cli",
    "conditions",
    "config",
    "mailer",
    "modify",
    "notify",
    "rule",
    "run",
    "storage",
    "whitelist",
    "QuarantineMilter"]

__version__ = "2.0.6"

from pyquarantine import _runtime_patches

import Milter
import logging

from Milter.utils import parse_addr
from collections import defaultdict
from copy import copy
from email import message_from_binary_file
from email.header import Header, decode_header, make_header
from email.headerregistry import AddressHeader, _default_header_map
from email.policy import SMTP
from io import BytesIO
from netaddr import IPNetwork, AddrFormatError

from pyquarantine.base import CustomLogger, MilterMessage
from pyquarantine.base import replace_illegal_chars
from pyquarantine.rule import Rule


class QuarantineMilter(Milter.Base):
    """QuarantineMilter based on Milter.Base to implement
       milter communication"""

    _rules = []
    _loglevel = logging.INFO
    _addr_fields = [f for f, v in _default_header_map.items()
                    if issubclass(v, AddressHeader)]

    @staticmethod
    def set_config(cfg, debug):
        QuarantineMilter._loglevel = cfg.get_loglevel(debug)

        try:
            local_addrs = []
            for addr in cfg["local_addrs"]:
                local_addrs.append(IPNetwork(addr))
        except AddrFormatError as e:
            raise RuntimeError(e)

        logger = logging.getLogger(__name__)
        logger.setLevel(QuarantineMilter._loglevel)
        for idx, rule_cfg in enumerate(cfg["rules"]):
            rule = Rule(rule_cfg, local_addrs, debug)
            logger.debug(rule)
            QuarantineMilter._rules.append(rule)

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(QuarantineMilter._loglevel)

    def addheader(self, field, value, idx=-1):
        value = replace_illegal_chars(Header(s=value).encode())
        self.logger.debug(f"addheader: {field}: {value}")
        super().addheader(field, value, idx)

    def chgheader(self, field, value, idx=1):
        value = replace_illegal_chars(Header(s=value).encode())
        if value:
            self.logger.debug(f"chgheader: {field}[{idx}]: {value}")
        else:
            self.logger.debug(f"delheader: {field}[{idx}]")
        super().chgheader(field, idx, value)

    def msg_as_bytes(self):
        try:
            data = self.msg.as_bytes()
        except Exception as e:
            self.logger.warning(f"unable to serialize message as bytes: {e}")
            try:
                self.logger.warning("try to serialize as str and encode")
                data = self.msg.as_string().encode(errors="replace")
            except Exception as e:
                self.logger.error(
                    f"unable to serialize message, giving up: {e}")
                raise e

        return data

    def update_headers(self, old_headers):
        if self.msg.is_multipart() and not self.msg["MIME-Version"]:
            self.msg.add_header("MIME-Version", "1.0")

        # serialize the message object so it updates its internal strucure
        self.msg_as_bytes()

        headers = set(self.msg.items())
        to_remove = list(set(old_headers) - headers)
        to_add = list(headers - set(old_headers))

        idx = defaultdict(int)
        for field, value in old_headers:
            field_lower = field.lower()
            if (field, value) in to_remove:
                self.chgheader(field, "", idx=idx[field_lower] + 1)
                continue
            idx[field_lower] += 1

        for field, value in to_add:
            self.addheader(field, value)

    def replacebody(self):
        self._body_changed = True

    def _replacebody(self):
        if not self._body_changed:
            return
        data = self.msg_as_bytes()
        body_pos = data.find(b"\r\n\r\n") + 4
        self.logger.debug("replace body")
        super().replacebody(data[body_pos:])
        del data

    def delrcpt(self, rcpts):
        "Remove recipient. May be called from eom callback only."
        if not isinstance(rcpts, list):
            rcpts = [rcpts]
        for rcpt in rcpts:
            self.logger.debug(f"delrcpt: {rcpt}")
            self.msginfo["rcpts"].remove(rcpt)
            super().delrcpt(rcpt)

    def connect(self, IPname, family, hostaddr):
        try:
            if hostaddr is None:
                self.logger.error(f"received invalid host address {hostaddr}, "
                                  f"unable to proceed")
                return Milter.TEMPFAIL

            self.IP = hostaddr[0]
            self.port = hostaddr[1]
            self.logger.debug(
                f"accepted milter connection from {self.IP} "
                f"port {self.port}")

            # pre-filter rules and actions by the host condition
            # also check if the mail body is needed by any upcoming action.
            self.rules = []
            self._headersonly = True
            for rule in QuarantineMilter._rules:
                if rule.conditions is None or \
                        rule.conditions.match_host(self.IP):
                    actions = []
                    for action in rule.actions:
                        if action.conditions is None or \
                                action.conditions.match_host(self.IP):
                            actions.append(action)
                            if not action.headersonly():
                                self._headersonly = False

                    if actions:
                        # copy needed rules to preserve configured actions
                        rule = copy(rule)
                        rule.actions = actions
                        self.rules.append(rule)

            if not self.rules:
                self.logger.debug(
                    "host is ignored by all rules, skip further processing")
                return Milter.ACCEPT

        except Exception as e:
            self.logger.exception(
                f"an exception occured in connect method: {e}")
            return Milter.TEMPFAIL

        return Milter.CONTINUE

    def hello(self, heloname):
        try:
            self.heloname = heloname
            self.logger.debug(f"received HELO name: {heloname}")
        except Exception as e:
            self.logger.exception(
                f"an exception occured in hello method: {e}")
            return Milter.TEMPFAIL

        return Milter.CONTINUE

    @Milter.decode("replace")
    def envfrom(self, mailfrom, *str):
        try:
            self.mailfrom = "@".join(parse_addr(mailfrom)).lower()
            self.rcpts = set()
        except Exception as e:
            self.logger.exception(
                f"an exception occured in envfrom method: {e}")
            return Milter.TEMPFAIL

        return Milter.CONTINUE

    @Milter.decode("replace")
    def envrcpt(self, to, *str):
        try:
            self.rcpts.add("@".join(parse_addr(to)).lower())
        except Exception as e:
            self.logger.exception(
                f"an exception occured in envrcpt method: {e}")
            return Milter.TEMPFAIL

        return Milter.CONTINUE

    def data(self):
        try:
            self.qid = self.getsymval('i')
            self.logger = CustomLogger(
                self.logger, {"qid": self.qid, "name": "milter"})
            self.logger.debug("received queue-id from MTA")
            self.fp = BytesIO()
        except Exception as e:
            self.logger.exception(
                f"an exception occured in data method: {e}")
            return Milter.TEMPFAIL

        return Milter.CONTINUE

    @Milter.decode("replace")
    def header(self, field, value):
        try:
            # remove CR and LF from address fields, otherwise pythons
            # email library throws an exception
            if field.lower() in QuarantineMilter._addr_fields:
                try:
                    v = str(make_header(decode_header(value)))
                except Exception as e:
                    self.logger.error(
                        f"unable to decode field '{field}': {e}")
                else:
                    if any(c in v for c in ["\r", "\n"]):
                        v = v.replace("\r", "").replace("\n", "")
                        value = Header(s=v).encode()

            # remove surrogates
            field = field.encode("ascii", errors="replace")
            value = value.encode("ascii", errors="replace")

            self.fp.write(field.encode() + b": " + value.encode() + b"\r\n")
        except Exception as e:
            self.logger.exception(
                f"an exception occured in header method: {e}")
            return Milter.TEMPFAIL

        return Milter.CONTINUE

    def eoh(self):
        try:
            self.fp.write(b"\r\n")
        except Exception as e:
            self.logger.exception(
                f"an exception occured in eoh method: {e}")
            return Milter.TEMPFAIL

        return Milter.CONTINUE

    def body(self, chunk):
        try:
            if not self._headersonly:
                self.fp.write(chunk)
        except Exception as e:
            self.logger.exception(
                f"an exception occured in body method: {e}")
            return Milter.TEMPFAIL

        return Milter.CONTINUE

    def eom(self):
        try:
            # msg and msginfo contain the runtime data that
            # is read/modified by actions
            self.fp.seek(0)
            self.msg = message_from_binary_file(
                self.fp, _class=MilterMessage, policy=SMTP.clone(
                    refold_source='none'))
            self.msginfo = {
                "mailfrom": self.mailfrom,
                "rcpts": [*self.rcpts],
                "vars": {}}

            self._body_changed = False
            milter_action = None
            for rule in self.rules:
                milter_action = rule.execute(self)
                self.logger.debug(
                    f"current template variables: {self.msginfo['vars']}")
                if milter_action is not None:
                    break
                elif not self.msginfo["rcpts"]:
                    milter_action = ("DISCARD", None)
                    break

            if milter_action is None:
                self._replacebody()
            else:
                action, reason = milter_action
                if action == "ACCEPT":
                    self._replacebody()
                    return Milter.ACCEPT
                elif action == "REJECT":
                    self.setreply("554", "5.7.0", reason)
                    return Milter.REJECT
                elif action == "DISCARD":
                    return Milter.DISCARD

        except Exception as e:
            self.logger.exception(
                f"an exception occured in eom method: {e}")
            return Milter.TEMPFAIL

        return Milter.ACCEPT
