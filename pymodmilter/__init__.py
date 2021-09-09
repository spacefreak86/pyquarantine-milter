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
    "base",
    "conditions",
    "rules",
    "run",
    "ModifyMilterConfig",
    "ModifyMilter"]

__version__ = "1.1.7"

from pymodmilter import _runtime_patches

import Milter
import logging
import re
import json

from Milter.utils import parse_addr
from collections import defaultdict
from copy import copy
from email import message_from_binary_file
from email.header import Header, decode_header, make_header
from email.headerregistry import AddressHeader, _default_header_map
from email.policy import SMTPUTF8
from io import BytesIO
from netaddr import IPNetwork, AddrFormatError

from pymodmilter.base import CustomLogger, BaseConfig, MilterMessage
from pymodmilter.base import replace_illegal_chars
from pymodmilter.rules import RuleConfig, Rule


class ModifyMilterConfig(BaseConfig):
    def __init__(self, cfgfile, debug=False):
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

        if "global" in cfg:
            assert isinstance(cfg["global"], dict), \
                "global: invalid type, should be dict"

            cfg["global"]["name"] = "global"
            super().__init__(cfg["global"], debug)

            self.logger.debug("initialize config")

            if "pretend" in cfg["global"]:
                pretend = cfg["global"]["pretend"]
                assert isinstance(pretend, bool), \
                    "global: pretend: invalid value, should be bool"
                self["pretend"] = pretend
            else:
                self["pretend"] = False

            if "socket" in cfg["global"]:
                socket = cfg["global"]["socket"]
                assert isinstance(socket, str), \
                    "global: socket: invalid value, should be string"
                self["socket"] = socket
            else:
                self["socket"] = None

            if "local_addrs" in cfg["global"]:
                local_addrs = cfg["global"]["local_addrs"]
                assert isinstance(local_addrs, list) and all(
                    [isinstance(addr, str) for addr in local_addrs]), \
                    "global: local_addrs: invalid value, " \
                    "should be list of strings"
            else:
                local_addrs = [
                    "fe80::/64",
                    "::1/128",
                    "127.0.0.0/8",
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16"]

            self["local_addrs"] = []
            try:
                for addr in local_addrs:
                    self["local_addrs"].append(IPNetwork(addr))
            except AddrFormatError as e:
                raise ValueError(f"{self['name']}: local_addrs: {e}")

            self.logger.debug(f"socket={self['socket']}, "
                              f"local_addrs={self['local_addrs']}, "
                              f"pretend={self['pretend']}, "
                              f"loglevel={self['loglevel']}")

        assert "rules" in cfg, \
            "mandatory parameter 'rules' not found"
        assert isinstance(cfg["rules"], list), \
            "rules: invalid value, should be list"

        self.logger.debug("initialize rules config")
        self["rules"] = []
        for idx, rule_cfg in enumerate(cfg["rules"]):
            self["rules"].append(
                RuleConfig(idx, self, rule_cfg, debug))


class ModifyMilter(Milter.Base):
    """ModifyMilter based on Milter.Base to implement milter communication"""

    _rules = []
    _loglevel = logging.INFO
    _addr_fields = [f for f, v in _default_header_map.items()
                    if issubclass(v, AddressHeader)]

    @staticmethod
    def set_config(cfg):
        ModifyMilter._loglevel = cfg["loglevel"]
        for rule_cfg in cfg["rules"]:
            ModifyMilter._rules.append(
                Rule(cfg, rule_cfg))

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(ModifyMilter._loglevel)

    def addheader(self, field, value, idx=-1):
        value = replace_illegal_chars(Header(s=value).encode())
        self.logger.debug(f"milter: addheader: {field}: {value}")
        super().addheader(field, value, idx)

    def chgheader(self, field, value, idx=1):
        value = replace_illegal_chars(Header(s=value).encode())
        if value:
            self.logger.debug(f"milter: chgheader: {field}[{idx}]: {value}")
        else:
            self.logger.debug(f"milter: delheader: {field}[{idx}]")
        super().chgheader(field, idx, value)

    def update_headers(self, old_headers):
        if self.msg.is_multipart() and not self.msg["MIME-Version"]:
            self.msg.add_header("MIME-Version", "1.0")

        # serialize the message object so it updates its internal strucure
        self.msg.as_bytes()

        old_headers = [(f, f.lower(), v) for f, v in old_headers]
        headers = [(f, f.lower(), v) for f, v in self.msg.items()]

        idx = defaultdict(int)
        for field, field_lower, value in old_headers:
            idx[field_lower] += 1
            if (field, field_lower, value) not in headers:
                self.chgheader(field, "", idx=idx[field_lower])
                idx[field] -= 1

        for field, value in self.msg.items():
            field_lower = field.lower()
            if (field, field_lower, value) not in old_headers:
                self.addheader(field, value)

    def replacebody(self):
        self._replacebody = True

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

    def envfrom(self, mailfrom, *str):
        try:
            self.mailfrom = "@".join(parse_addr(mailfrom)).lower()
            self.rcpts = set()
        except Exception as e:
            self.logger.exception(
                f"an exception occured in envfrom method: {e}")
            return Milter.TEMPFAIL

        return Milter.CONTINUE

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
            self.logger = CustomLogger(self.logger, {"qid": self.qid})
            self.logger.debug("received queue-id from MTA")

            # pre-filter rules and actions by the host condition, other
            # conditions (headers, envelope-from, envelope-to) may get
            # changed by executed actions later on.
            # also check if the mail body is needed by any upcoming action.

            self.rules = []
            self._headersonly = True
            for rule in ModifyMilter._rules:
                if rule.conditions is None or \
                        rule.conditions.match(host=self.IP):
                    actions = []
                    for action in rule.actions:
                        if action.conditions is None or \
                                action.conditions.match(host=self.IP):
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
                    "message is ignored by all rules, skip further processing")
                return Milter.ACCEPT

            self.fp = BytesIO()
        except Exception as e:
            self.logger.exception(
                f"an exception occured in data method: {e}")
            return Milter.TEMPFAIL

        return Milter.CONTINUE

    def header(self, field, value):
        try:
            # remove CR and LF from address fields, otherwise pythons
            # email library throws an exception
            if field.lower() in ModifyMilter._addr_fields:
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

            self.fp.write(field + b": " + value + b"\r\n")
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
            # setup msg and msg_info to be read/modified by rules and actions
            self.fp.seek(0)
            self.msg = message_from_binary_file(
                self.fp, _class=MilterMessage, policy=SMTPUTF8.clone(
                    refold_source='none'))
            self.msg_info = defaultdict(str)
            self.msg_info["ip"] = self.IP
            self.msg_info["port"] = self.port
            self.msg_info["heloname"] = self.heloname
            self.msg_info["envfrom"] = self.mailfrom
            self.msg_info["rcpts"] = self.rcpts
            self.msg_info["qid"] = self.qid

            self._replacebody = False
            milter_action = None
            for rule in self.rules:
                milter_action = rule.execute(self)
                if milter_action is not None:
                    break

            if self._replacebody:
                data = self.msg.as_bytes()
                body_pos = data.find(b"\r\n\r\n") + 4
                self.logger.debug("milter: replacebody")
                super().replacebody(data[body_pos:])
                del data

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
