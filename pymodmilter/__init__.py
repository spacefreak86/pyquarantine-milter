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
    "replace_illegal_chars",
    "run",
    "version",
    "Modification",
    "Rule",
    "ModifyMilter"]

import Milter
import logging
import logging.handlers
import re

from Milter.utils import parse_addr
from email.charset import Charset
from email.header import Header, decode_header
from netaddr import IPAddress, IPNetwork, AddrFormatError


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


def replace_illegal_chars(string):
    return string.replace(
        "\x00", "").replace(
        "\r", "").replace(
        "\n", "")


class Modification:
    """Modification to implement a modification to apply on e-mail headers."""

    types = {
        "add_header": ["header", "value"],
        "del_header": ["header"],
        "mod_header": ["header", "search", "value"]
    }

    def __init__(self, name, mod_type, log, **params):
        self.logger = logging.getLogger(__name__)
        self.logger.debug(f"initializing modification '{name}'")
        self.name = name
        self.log = log
        # check mod_type
        if mod_type not in Modification.types:
            raise RuntimeError(
                f"{self.name}: invalid modification type '{mod_type}'")
        self.mod_type = mod_type
        # check if mandatory modification options are present in config
        for option in Modification.types[self.mod_type]:
            if option not in params:
                raise RuntimeError(
                    f"{self.name}: mandatory config "
                    f"option '{option}' not found")
            if option == "value" and not params["value"]:
                raise RuntimeError(
                    f"{self.name}: empty value specified")

        if mod_type == "add_header":
            self.header = params["header"]
            self.value = params["value"]
        elif mod_type in ["del_header", "mod_header"]:
            # compile header regex
            try:
                self.header = re.compile(
                    params["header"], re.MULTILINE + re.DOTALL + re.IGNORECASE)
            except re.error as e:
                raise RuntimeError(
                    f"{self.name}: unable to parse regular expression of "
                    f"option 'header': {e}")

            if mod_type == "mod_header":
                # compile search regex
                try:
                    self.search = re.compile(
                        params["search"],
                        re.MULTILINE + re.DOTALL + re.IGNORECASE)
                except re.error as e:
                    raise RuntimeError(
                        f"{self.name}: unable to parse regular expression of "
                        f"option 'search': {e}")
                self.value = params["value"]

    def execute(self, qid, headers):
        """
        Execute rule on given headers and return list
        with modified headers.
        """
        if self.mod_type == "add_header":
            header = f"{self.header}: {self.value}"
            if self.log:
                self.logger.info(
                    f"{qid}: {self.name}: add_header: {header[0:70]}")
            else:
                self.logger.debug(
                    f"{qid}: {self.name}: add_header: {header}")
            return [(self.mod_type, self.header, self.value, 0, 1)]

        modified = []
        index = 0
        occurrences = {}

        # iterate headers
        for name, value in headers:
            # keep track of the occurrence of each header, needed by
            # Milter.Base.chgheader
            if name not in occurrences.keys():
                occurrences[name] = 1
            else:
                occurrences[name] += 1

            # check if header line matches regex
            header = f"{name}: {value}"
            if self.header.search(header):
                if self.mod_type == "del_header":
                    # set an empty value to delete the header
                    new_value = ""
                    if self.log:
                        self.logger.info(
                            f"{qid}: {self.name}: del_header: "
                            f"{header[0:70]}")
                    else:
                        self.logger.debug(
                            f"{qid}: {self.name}: del_header: "
                            f"(occ. {occurrences[name]}): {header}")
                else:
                    old_header = header
                    new_value = self.search.sub(self.value, value)
                    if value == new_value:
                        continue
                    header = f"{name}: {new_value}"
                    if self.log:
                        self.logger.info(
                            f"{qid}: {self.name}: mod_header: "
                            f"{old_header[0:70]}: {header[0:70]}")
                    else:
                        self.logger.debug(
                            f"{qid}: {self.name}: mod_header: "
                            f"(occ. {occurrences[name]}): {old_header}: "
                            f"{header}")
                modified.append(
                    (self.mod_type, name, new_value, index, occurrences[name]))
            index += 1
        return modified


class Rule:
    def __init__(self, name, modifications, local_addrs, log, conditions={}):
        self.logger = logging.getLogger(__name__)
        self.name = name
        self.log = log

        self.logger.debug(f"initializing rule '{self.name}'")

        self._local_addrs = []
        # replace strings in local_addrs list with IPNetwork instances
        try:
            for addr in local_addrs:
                self._local_addrs.append(IPNetwork(addr))
        except AddrFormatError as e:
            raise RuntimeError(
                f"{self.name}: unable to parse entry of "
                f"option local_addrs: {e}")

        self.conditions = {}
        for option, value in conditions.items():
            if option == "local":
                self.conditions[option] = value
                self.logger.debug(
                    f"{self.name}: added condition: {option} = {value}")
            elif option == "hosts":
                self.conditions[option] = []
                try:
                    for host in value:
                        self.conditions[option].append(IPNetwork(host))
                except AddrFormatError as e:
                    raise RuntimeError(
                        f"{self.name}: unable to parse entry of "
                        f"condition '{option}': {e}")
                self.logger.debug(
                    f"{self.name}: added condition: {option} = {value}")
            elif option == "envfrom":
                try:
                    self.conditions[option] = re.compile(value, re.IGNORECASE)
                except re.error as e:
                    raise RuntimeError(
                        f"{self.name}: unable to parse regular expression of "
                        f"condition '{option}': {e}")
                self.logger.debug(
                    f"{self.name}: added condition: {option} = {value}")

        self.modifications = []
        for mod_idx, mod in enumerate(modifications):
            params = {}
            # set default values if not specified in config
            if "name" not in mod:
                mod["name"] = f"Modification #{mod_idx}"

            if self.name:
                params["name"] = f"{self.name}/{mod['name']}"
            else:
                params["name"] = mod["name"]

            if "log" in mod:
                params["log"] = mod["log"]
            else:
                params["log"] = self.log

            if "type" in mod:
                params["mod_type"] = mod["type"]
            else:
                raise RuntimeError(
                    f"{params['name']}: mandatory config "
                    f"option 'type' not found")

            if "header" in mod:
                params["header"] = mod["header"]

            if "search" in mod:
                params["search"] = mod["search"]

            if "value" in mod:
                params["value"] = mod["value"]

            self.modifications.append(Modification(**params))
            self.logger.debug(
                f"{self.name}: added modification: {mod['name']}")

    def ignore_host(self, host):
        ip = IPAddress(host)

        if "local" in self.conditions:
            is_local = False
            for addr in self._local_addrs:
                if ip in addr:
                    is_local = True
                    break
            if is_local != self.conditions["local"]:
                return True

        if "hosts" in self.conditions:
            # check if host is in list
            for accepted in self.conditions["hosts"]:
                if ip in accepted:
                    return False
            return True

        return False

    def ignore_envfrom(self, envfrom):
        if "envfrom" in self.conditions:
            if not self.conditions["envfrom"].search(envfrom):
                return True
        return False

    def execute(self, qid, headers):
        changes = []
        if self.log:
            self.logger.info(f"{qid}: executing rule '{self.name}'")
        else:
            self.logger.debug(f"{qid}: executing rule '{self.name}'")

        for mod in self.modifications:
            self.logger.debug(f"{qid}: executing modification '{mod.name}'")
            result = mod.execute(qid, headers)
            changes += result
            for mod_type, name, value, index, occurrence in result:
                if mod_type == "add_header":
                    headers.append((name, value))
                else:
                    if mod_type == "mod_header":
                        headers[index] = (name, value)
                    elif mod_type == "del_header":
                        del headers[index]
        return changes


class ModifyMilter(Milter.Base):
    """ModifyMilter based on Milter.Base to implement milter communication"""

    _rules = []

    @staticmethod
    def set_rules(rules):
        ModifyMilter._rules = rules

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # save rules, it must not change during runtime
        self.rules = ModifyMilter._rules.copy()

    def connect(self, IPname, family, hostaddr):
        self.logger.debug(
            f"accepted milter connection from {hostaddr[0]} "
            f"port {hostaddr[1]}")
        ip = IPAddress(hostaddr[0])

        # remove rules which ignore this host
        for rule in self.rules.copy():
            if rule.ignore_host(ip):
                self.logger.debug(
                    f"host {hostaddr[0]} is ignored by rule '{rule.name}'")
                self.rules.remove(rule)

        if not self.rules:
            self.logger.debug(
                f"host {hostaddr[0]} is ignored by all rules, "
                f"skip further processing")
            return Milter.ACCEPT
        return Milter.CONTINUE

    def envfrom(self, mailfrom, *str):
        mailfrom = "@".join(parse_addr(mailfrom)).lower()
        for rule in self.rules.copy():
            if rule.ignore_envfrom(mailfrom):
                self.logger.debug(
                    f"envelope-from {mailfrom} is ignored by "
                    f"rule '{rule.name}'")
                self.rules.remove(rule)

        if not self.rules:
            self.logger.debug(
                f"mail from {mailfrom} is ignored by all rules, "
                f"skip further processing")
            return Milter.ACCEPT
        return Milter.CONTINUE

    @Milter.noreply
    def data(self):
        self.qid = self.getsymval('i')
        self.logger.debug(f"{self.qid}: received queue-id from MTA")
        self.headers = []
        return Milter.CONTINUE

    def header(self, name, value):
        try:
            # remove surrogates from value
            value = value.encode(
                errors="surrogateescape").decode(errors="replace")
            self.logger.debug(f"{self.qid}: received header: {name}: {value}")
            header = make_header(decode_header(value), errors="replace")
            value = str(header).replace("\x00", "")
            self.logger.debug(
                f"{self.qid}: decoded header: {name}: {value}")
            self.headers.append((name, value))
            return Milter.CONTINUE
        except Exception as e:
            self.logger.exception(
                f"an exception occured in header function: {e}")
            return Milter.TEMPFAIL

    def eom(self):
        try:
            for rule in self.rules:
                changes = rule.execute(self.qid, self.headers)
                for mod_type, name, value, index, occurrence in changes:
                    enc_value = replace_illegal_chars(
                        Header(s=value).encode())
                    if mod_type == "add_header":
                        self.logger.debug(f"{self.qid}: milter: adding "
                                          f"header: {name}: {enc_value}")
                        self.addheader(name, enc_value, -1)
                    else:
                        self.logger.debug(f"{self.qid}: milter: modify "
                                          f"header (occ. {occurrence}): "
                                          f"{name}: {enc_value}")
                        self.chgheader(name, occurrence, enc_value)
            return Milter.ACCEPT
        except Exception as e:
            self.logger.exception(
                f"an exception occured in eom function: {e}")
            return Milter.TEMPFAIL
