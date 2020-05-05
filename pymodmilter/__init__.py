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
from bs4 import BeautifulSoup
from email.charset import Charset
from email.header import Header, decode_header
from email import message_from_binary_file
from email.message import MIMEPart
from email.policy import default as default_policy, SMTP
from io import BytesIO
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
    """Replace illegal characters in header values."""
    return string.replace(
        "\x00", "").replace(
        "\r", "").replace(
        "\n", "")


class Modification:
    """
    Modification to implement certain modifications on e-mails.

    Each modification function returns the necessary changes for ModifyMilter
    so they can be applied to the email passing the MTA.
    """

    def __init__(self, name, mod_type, log, **params):
        self.logger = logging.getLogger(__name__)
        self.logger.debug(f"initializing modification '{name}'")
        self.name = name
        self.log = log
        # needs for each modification type
        self.types = {
            "add_header": {
                "needs": ["headers"]},
            "del_header": {
                "needs": ["headers"]},
            "mod_header": {
                "needs": ["headers"]},
            "add_disclaimer": {
                "needs": ["headers", "data"]}}

        if mod_type not in self.types:
            raise RuntimeError(
                f"{self.name}: invalid modification type '{mod_type}'")

        self.mod_type = mod_type

        try:
            if mod_type == "add_header":
                self.header = params["header"]
                self.value = params["value"]
            elif mod_type in ["del_header", "mod_header"]:
                try:
                    self.header = re.compile(
                        params["header"],
                        re.MULTILINE + re.DOTALL + re.IGNORECASE)
                except re.error as e:
                    raise RuntimeError(
                        f"{self.name}: unable to parse regex of "
                        f"option 'header': {e}")

                if mod_type == "mod_header":
                    try:
                        self.search = re.compile(
                            params["search"],
                            re.MULTILINE + re.DOTALL + re.IGNORECASE)
                    except re.error as e:
                        raise RuntimeError(
                            f"{self.name}: unable to parse regex of "
                            f"option 'search': {e}")

                    self.value = params["value"]
            elif mod_type == "add_disclaimer":
                if params["action"] not in ["append", "prepend"]:
                    raise RuntimeError(
                        f"{self.name}: unknown action specified")

                self.action = params["action"]

                if params["error_policy"] not in ["wrap", "ignore", "reject"]:
                    raise RuntimeError(
                        f"{self.name}: unknown error_policy specified")

                self.error_policy = params["error_policy"]

                try:
                    with open(params["html_template"], "r") as f:
                        self.html = BeautifulSoup(f.read(), "html.parser")
                        body = self.html.find('body')
                        if body:
                            # just use content within the body tag if present
                            self.html = body
                    with open(params["text_template"], "r") as f:
                        self.text = f.read()
                except IOError as e:
                    raise RuntimeError(f"unable to read template: {e}")
        except KeyError as e:
            raise RuntimeError(
                f"{self.name}: mandatory configuration option not found: {e}")

    def needs(self):
        """Return the needs of this modification to work."""
        return self.types[self.mod_type]["needs"]

    def add_header(self, qid, headers, header, value, pos=-1):
        """Add header to email."""
        hdr = f"{header}: {value}"
        if self.log:
            self.logger.info(
                f"{qid}: {self.name}: add_header: {hdr[0:70]}")
        else:
            self.logger.debug(
                f"{qid}: {self.name}: add_header: {hdr}")

        headers.append((header, value))
        params = [header, value, pos]
        return [("add_header", *params)]

    def mod_header(self, qid, headers, header, search, replace):
        """Modify an email header."""
        if isinstance(header, str):
            header = re.compile(
                header, re.MULTILINE + re.DOTALL + re.IGNORECASE)

        if isinstance(search, str):
            search = re.compile(
                search, re.MULTILINE + re.DOTALL + re.IGNORECASE)

        changes = []
        index = 0
        occurrences = {}
        # iterate a copy of headers because headers may be modified
        for name, value in headers.copy():
            # keep track of the occurrence of each header
            # needed by Milter.Base.chgheader
            if name not in occurrences.keys():
                occurrences[name] = 1
            else:
                occurrences[name] += 1

            hdr = f"{name}: {value}"
            if header.search(hdr):
                new_value = search.sub(replace, value).strip()
                if new_value == "":
                    self.logger.warning(
                        f"{qid}: {self.name}: mod_header: resulting value is "
                        f"empty, skip modification")
                elif value != new_value:
                    old_hdr = hdr
                    hdr = f"{name}: {new_value}"
                    if self.log:
                        self.logger.info(
                            f"{qid}: {self.name}: mod_header: "
                            f"{old_hdr[0:70]}: {hdr[0:70]}")
                    else:
                        self.logger.debug(
                            f"{qid}: {self.name}: mod_header: "
                            f"(occ. {occurrences[name]}): {old_hdr}: "
                            f"{hdr}")

                    headers[index] = (name, new_value)
                    params = [name, new_value, occurrences[name]]
                    changes.append(("mod_header", *params))

            index += 1

        return changes

    def del_header(self, qid, headers, header):
        """Delete an email header."""
        if isinstance(header, str):
            header = re.compile(
                header, re.MULTILINE + re.DOTALL + re.IGNORECASE)

        changes = []
        index = 0
        occurrences = {}
        # iterate a copy of headers because headers may be modified
        for name, value in headers.copy():
            # keep track of the occurrence of each header,
            # needed by Milter.Base.chgheader
            if name not in occurrences.keys():
                occurrences[name] = 1
            else:
                occurrences[name] += 1

            hdr = f"{name}: {value}"
            if header.search(hdr):
                if self.log:
                    self.logger.info(
                        f"{qid}: {self.name}: del_header: "
                        f"{hdr[0:70]}")
                else:
                    self.logger.debug(
                        f"{qid}: {self.name}: del_header: "
                        f"(occ. {occurrences[name]}): {hdr}")

                del headers[index]
                params = [name, "", occurrences[name]]
                changes.append(("mod_header", *params))
                index -= 1
                occurrences[name] -= 1

            index += 1

        return changes

    def add_disclaimer(self, qid, headers, fp, text_template, html_template,
                       error_policy):
        """Append or prepend a disclaimer to the email body."""
        changes = []

        fp.seek(0)
        msg = message_from_binary_file(fp, policy=default_policy)

        html_body = None
        text_body = None
        update_headers = False

        try:
            html_body = msg.get_body(preferencelist=("html"))
            text_body = msg.get_body(preferencelist=("plain"))
        except Exception as e:
            self.logger.error(
                f"{qid}: {self.name}: an error occured in "
                f"email.message.EmailMessage.get_body: {e}")

        if html_body is None and text_body is None:
            if self.error_policy == "ignore":
                self.logger.info(
                    f"{qid}: {self.name}: unable to find email body, "
                    f"ignore according to policy")
                return changes
            elif self.error_policy == "reject":
                self.logger.info(
                    f"{qid}: {self.name}: unable to find email body, "
                    f"reject message according to policy")
                return [
                    ("reject", "Message rejected due to missing email body")]

            self.logger.info(
                f"{qid}: {self.name}: unable to find email body, "
                f"wrapping original email in a new message envelope")
            msg = MIMEPart()
            msg.add_header("MIME-Version", "1.0")
            msg.set_content(
                "Please see the original email attached to this email.")
            msg.add_alternative(
                "Please see the original email attached to this email.",
                subtype="html")
            fp.seek(0)
            msg.add_attachment(
                fp.read(), maintype="plain", subtype="text",
                filename="original_email.eml")
            html_body = msg.get_body(preferencelist=("html"))
            text_body = msg.get_body(preferencelist=("plain"))
            # content and mime headers may have to be updated because
            # a new message has been created
            update_headers = True
        elif not msg.is_multipart():
            # content and mime headers may have to be updated because
            # we operate on a non-multipart email
            update_headers = True

        if text_body is not None:
            if self.log:
                self.logger.info(
                    f"{qid}: {self.name}: {self.action} text disclaimer")
            else:
                self.logger.debug(
                    f"{qid}: {self.name}: {self.action} text disclaimer")

            text = text_body.get_content()
            if self.action == "prepend":
                text = f"{text_template}{text}"
            else:
                text = f"{text}{text_template}"

            text_body.set_content(
                text.encode(), maintype="text", subtype="plain")
            text_body.set_param("charset", "UTF-8", header="Content-Type")

        if html_body is not None:
            if self.log:
                self.logger.info(
                    f"{qid}: {self.name}: {self.action} html disclaimer")
            else:
                self.logger.debug(
                    f"{qid}: {self.name}: {self.action} html disclaimer")

            soup = BeautifulSoup(html_body.get_content(), "html.parser")
            body = soup.find('body')
            if body:
                # work within the body tag if it is present
                soup = body

            if self.action == "prepend":
                soup.insert(0, html_template)
            else:
                soup.append(html_template)

            html_body.set_content(
                str(soup).encode(), maintype="text", subtype="html")
            html_body.set_param("charset", "UTF-8", header="Content-Type")

        if update_headers:
            for name, value in msg.items():
                name_lower = name.lower()
                if not name_lower.startswith("content-") and \
                        name_lower != "mime-version":
                    continue

                defined = False
                for n, v in headers:
                    if n.lower() == name_lower:
                        changes += self.mod_header(
                            qid, headers, f"^{n}:", ".*", value)
                        defined = True
                        break

                if not defined:
                    changes += self.add_header(
                        qid, headers, name, value)

        msg = msg.as_string(policy=SMTP).encode("ascii", errors="replace")
        fp.seek(0)
        fp.write(msg)
        fp.truncate()
        body_pos = msg.find(b"\r\n\r\n") + 2
        changes.append(("mod_body", body_pos))
        return changes

    def execute(self, qid, headers, fp):
        """
        Execute configured modification.
        """
        changes = []

        if self.mod_type == "add_header":
            changes = self.add_header(
                qid, headers, self.header, self.value)
        elif self.mod_type == "mod_header":
            changes = self.mod_header(
                qid, headers, self.header, self.search, self.value)
        elif self.mod_type == "del_header":
            changes = self.del_header(
                qid, headers, self.header)
        elif self.mod_type == "add_disclaimer":
            changes = self.add_disclaimer(
                qid, headers, fp, self.text,
                self.html, self.error_policy)

        return changes


class Rule:
    """
    Rule to implement multiple modifications on emails based on conditions.
    """

    def __init__(self, name, modifications, local_addrs, log, conditions={},
                 pretend=False):
        self.logger = logging.getLogger(__name__)
        if pretend:
            self.name = f"{name} (pretend)"
        else:
            self.name = name

        self.logger.debug(f"initializing rule '{self.name}'")
        self.log = log
        self.pretend = pretend
        self._needs = []
        self._local_addrs = []

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
            elif option in ["envfrom", "envto"]:
                try:
                    self.conditions[option] = re.compile(value, re.IGNORECASE)
                except re.error as e:
                    raise RuntimeError(
                        f"{self.name}: unable to parse regex of "
                        f"condition '{option}': {e}")

                self.logger.debug(
                    f"{self.name}: added condition: {option} = {value}")

        self.modifications = []
        for mod_idx, mod in enumerate(modifications):
            params = {}
            if "name" not in mod:
                mod["name"] = f"Modification #{mod_idx}"

            if self.name:
                params["name"] = f"{self.name}: {mod['name']}"
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

            for param in [
                    "header", "search", "value", "action", "html_template",
                    "text_template", "error_policy"]:
                if param in mod:
                    params[param] = mod[param]

            modification = Modification(**params)
            for need in modification.needs():
                if need not in self._needs:
                    self._needs.append(need)

            self.modifications.append(modification)
            self.logger.debug(
                f"{self.name}: added modification: {mod['name']}")

        self.logger.debug(
            f"{self.name}: rule needs: {self._needs}")

    def needs(self):
        """Return the needs of this rule."""
        return self._needs

    def ignore_host(self, host):
        """Check if host is ignored by this rule."""
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
        """Check if envelope-from address is ignored by this rule."""
        if "envfrom" in self.conditions:
            if not self.conditions["envfrom"].search(envfrom):
                return True

        return False

    def ignore_envto(self, envto):
        """Check if envelope-to address is ignored by this rule."""
        if "envto" in self.conditions:
            if not isinstance(envto, set):
                envto = set(envto)
            for to in envto:
                if not self.conditions["envto"].search(to):
                    return True

        return False

    def execute(self, qid, headers, data):
        """Execute all modifications of this rule."""
        changes = []
        if self.log:
            self.logger.info(f"{qid}: executing rule '{self.name}'")
        else:
            self.logger.debug(f"{qid}: executing rule '{self.name}'")

        for mod in self.modifications:
            self.logger.debug(f"{qid}: executing modification '{mod.name}'")
            changes += mod.execute(qid, headers, data)

        if self.pretend:
            changes = []
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
                f"envelope-from address {mailfrom} is ignored by all rules, "
                f"skip further processing")
            return Milter.ACCEPT

        self.recipients = set()
        return Milter.CONTINUE

    @Milter.noreply
    def envrcpt(self, to, *str):
        self.recipients.add("@".join(parse_addr(to)).lower())
        return Milter.CONTINUE

    def data(self):
        try:
            for rule in self.rules.copy():
                if rule.ignore_envto(self.recipients):
                    self.logger.debug(
                        f"envelope-to addresses are ignored by "
                        f"rule '{rule.name}'")
                    self.rules.remove(rule)

            if not self.rules:
                self.logger.debug(
                    f"envelope-to addresses are ignored by all rules, "
                    f"skip further processing")
                return Milter.ACCEPT

            self.qid = self.getsymval('i')
            self.logger.debug(f"{self.qid}: received queue-id from MTA")
            self.headers = None
            self.fp = None
            for rule in self.rules:
                if "headers" in rule.needs() and self.headers is None:
                    self.headers = []

                if "data" in rule.needs() and self.fp is None:
                    self.fp = BytesIO()

                if None not in [self.headers, self.fp]:
                    break

        except Exception as e:
            self.logger.exception(
                f"an exception occured in data function: {e}")
            return Milter.TEMPFAIL

        return Milter.CONTINUE

    def header(self, name, value):
        try:
            # remove surrogates from value
            value = value.encode(
                errors="surrogateescape").decode(errors="replace")
            if self.fp is not None:
                self.fp.write(f"{name}: {value}\r\n".encode(
                    encoding="ascii", errors="replace"))

            if self.headers is not None:
                self.logger.debug(f"{self.qid}: received header: "
                                  f"{name}: {value}")
                header = make_header(decode_header(value), errors="replace")
                value = str(header).replace("\x00", "")
                self.logger.debug(
                    f"{self.qid}: decoded header: {name}: {value}")
                self.headers.append((name, value))
        except Exception as e:
            self.logger.exception(
                f"an exception occured in header function: {e}")
            return Milter.TEMPFAIL

        return Milter.CONTINUE

    def eoh(self):
        try:
            if self.fp is not None:
                self.fp.write(b"\r\n")
        except Exception as e:
            self.logger.exception(
                f"an exception occured in eoh function: {e}")
            return Milter.TEMPFAIL

        return Milter.CONTINUE

    def body(self, chunk):
        try:
            if self.fp is not None:
                self.fp.write(chunk)
        except Exception as e:
            self.logger.exception(
                f"an exception occured in body function: {e}")
            return Milter.TEMPFAIL

        return Milter.CONTINUE

    def eom(self):
        try:
            changes = []
            for rule in self.rules:
                changes += rule.execute(self.qid, self.headers, self.fp)

            mod_body_pos = None
            for mod_type, *params in changes:
                if mod_type in ["add_header", "mod_header", "del_header"]:
                    header, value, occurrence = params
                    enc_value = replace_illegal_chars(
                        Header(s=value).encode())
                    if mod_type == "add_header":
                        self.logger.debug(f"{self.qid}: milter: add "
                                          f"header: {header}: {enc_value}")
                        self.addheader(header, enc_value, occurrence)
                    else:
                        if enc_value == "":
                            self.logger.debug(
                                f"{self.qid}: milter: delete "
                                f"header (occ. {occurrence}): "
                                f"{header}")
                        else:
                            self.logger.debug(
                                f"{self.qid}: milter: modify "
                                f"header (occ. {occurrence}): "
                                f"{header}: {enc_value}")

                        self.chgheader(header, occurrence, enc_value)
                elif mod_type == "mod_body":
                    mod_body_pos = params[0]
                elif mod_type == "reject":
                    self.setreply("554", "5.7.0", params[0])
                    return Milter.REJECT

            if mod_body_pos is not None:
                self.fp.seek(mod_body_pos)
                self.logger.debug(f"{self.qid}: milter: replace body")
                self.replacebody(self.fp.read())
        except Exception as e:
            self.logger.exception(
                f"an exception occured in eom function: {e}")
            return Milter.TEMPFAIL

        return Milter.ACCEPT
