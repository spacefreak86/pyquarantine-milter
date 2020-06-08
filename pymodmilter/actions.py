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

import logging
import re

from bs4 import BeautifulSoup
from collections import defaultdict
from copy import copy
from email.header import Header
from email.parser import BytesFeedParser
from email.message import MIMEPart
from email.policy import default as default_policy, SMTP

from pymodmilter import CustomLogger, Conditions


def _replace_illegal_chars(string):
    """Replace illegal characters in header values."""
    return string.replace(
        "\x00", "").replace(
        "\r", "").replace(
        "\n", "")


def add_header(field, value, milter, idx=-1, pretend=False,
               logger=logging.getLogger(__name__)):
    """Add a mail header field."""
    header = f"{field}: {value}"
    if logger.getEffectiveLevel() == logging.DEBUG:
        logger.debug(f"add_header: {header}")
    else:
        logger.info(f"add_header: {header[0:70]}")

    if idx == -1:
        milter.fields.append((field, value))
    else:
        milter.fields.insert(idx, (field, value))

    if pretend:
        return

    encoded_value = _replace_illegal_chars(
        Header(s=value).encode())
    milter.logger.debug(f"milter: addheader: {field}[{idx}]: {encoded_value}")
    milter.addheader(field, encoded_value, idx)


def mod_header(field, value, milter, search=None, pretend=False,
               logger=logging.getLogger(__name__)):
    """Change the value of a mail header field."""
    if not isinstance(field, re.Pattern):
        field = re.compile(field, re.IGNORECASE)

    if search is not None and not isinstance(search, re.Pattern):
        search = re.compile(search, re.MULTILINE + re.DOTALL + re.IGNORECASE)

    occ = defaultdict(int)

    for idx, (f, v) in enumerate(milter.fields):
        occ[f] += 1

        if not field.match(f):
            continue

        if search is not None:
            new_v = search.sub(value, v).strip()
        else:
            new_v = value.strip()

        if new_v == v:
            continue

        if not new_v:
            logger.warning(
                f"mod_header: resulting value is empty, "
                f"skip modification")
            continue

        header = f"{f}: {v}"
        new_header = f"{f}: {new_v}"
        if logger.getEffectiveLevel() == logging.DEBUG:
            logger.debug(f"mod_header: {header}: {new_header}")
        else:
            logger.info(f"mod_header: {header[0:70]}: {new_header[0:70]}")

        milter.fields[idx] = (f, new_v)

        if pretend:
            continue

        encoded_value = _replace_illegal_chars(
            Header(s=new_v).encode())
        milter.logger.debug(
            f"milter: chgheader: {f}[{occ[f]}]: {encoded_value}")
        milter.chgheader(f, occ[f], encoded_value)


def del_header(field, milter, value=None, pretend=False,
               logger=logging.getLogger(__name__)):
    """Delete a mail header field."""
    if not isinstance(field, re.Pattern):
        field = re.compile(field, re.IGNORECASE)

    if value is not None and not isinstance(value, re.Pattern):
        value = re.compile(value, re.MULTILINE + re.DOTALL + re.IGNORECASE)

    idx = -1
    occ = defaultdict(int)

    # iterate a copy of milter.fields because elements may get removed
    # during iteration
    for f, v in milter.fields.copy():
        idx += 1
        occ[f] += 1

        if not field.match(f):
            continue

        if value is not None and not value.search(v):
            continue

        header = f"{f}: {v}"
        if logger.getEffectiveLevel() == logging.DEBUG:
            logger.debug(f"del_header: {header}")
        else:
            logger.info(f"del_header: {header[0:70]}")

        del milter.fields[idx]

        if not pretend:
            encoded_value = ""
            milter.logger.debug(
                f"milter: chgheader: {f}[{occ[f]}]: {encoded_value}")
            milter.chgheader(f, occ[f], encoded_value)

        idx -= 1
        occ[f] -= 1


def _get_body_content(msg, body_type):
    content = None
    body_part = msg.get_body(preferencelist=(body_type))
    if body_part is not None:
        content = body_part.get_content()

    return (body_part, content)


def _wrap_message(milter):
    msg = MIMEPart()
    msg.add_header("MIME-Version", "1.0")

    msg.set_content(
        "Please see the original email attached.")
    msg.add_alternative(
        "Please see the original email attached.",
        subtype="html")

    data = b""
    for field, value in milter.fields:
        encoded_value = _replace_illegal_chars(
            Header(s=value).encode())
        data += field.encode("ascii", errors="replace")
        data += b": "
        data += encoded_value.encode("ascii", errors="replace")
        data += b"\r\n"

    milter.fp.seek(0)
    data += b"\r\n" + milter.fp.read()

    msg.add_attachment(
        data, maintype="plain", subtype="text",
        filename=f"{milter.qid}.eml")

    return msg


def _inject_body(milter, msg):
    if not msg.is_multipart():
        msg.make_mixed()

    new_msg = MIMEPart()
    new_msg.add_header("MIME-Version", "1.0")
    new_msg.set_content("")
    new_msg.add_alternative("", subtype="html")
    new_msg.make_mixed()
    for attachment in msg.iter_attachments():
        new_msg.attach(attachment)

    return new_msg


def add_disclaimer(text, html, action, policy, milter, pretend=False,
                   logger=logging.getLogger(__name__)):
    """Append or prepend a disclaimer to the mail body."""
    milter.fp.seek(0)
    fp = BytesFeedParser(policy=default_policy)

    for field, value in milter.fields:
        field_lower = field.lower()
        if not field_lower.startswith("content-") and \
                field_lower != "mime-version":
            continue
        logger.debug(
            f"feed content header to message object: {field}: {value}")
        encoded_value = _replace_illegal_chars(
            Header(s=value).encode())
        fp.feed(field.encode("ascii", errors="replace"))
        fp.feed(b": ")
        fp.feed(encoded_value.encode("ascii", errors="replace"))
        fp.feed(b"\r\n")

    fp.feed(b"\r\n")
    logger.debug(f"feed body to message object: {field}: {value}")
    fp.feed(milter.fp.read())

    logger.debug("parse message")
    msg = fp.close()

    text_content = None
    html_content = None

    try:
        try:
            logger.debug("try to find a plain and/or html body part")
            text_body, text_content = _get_body_content(msg, "plain")
            html_body, html_content = _get_body_content(msg, "html")
            if text_content is None and html_content is None:
                raise RuntimeError()
        except RuntimeError:
            logger.info(
                "message does not contain any body part, "
                "inject empty plain and html body parts")
            msg = _inject_body(milter, msg)
            text_body, text_content = _get_body_content(msg, "plain")
            html_body, html_content = _get_body_content(msg, "html")
            if text_content is None and html_content is None:
                raise RuntimeError("no message body present after injecting")
    except Exception as e:
        logger.warning(e)
        if policy == "ignore":
            logger.info(
                f"unable to add disclaimer to message body, "
                f"ignore error according to policy")
            return
        elif policy == "reject":
            logger.info(
                f"unable to add disclaimer to message body, "
                f"reject message according to policy")
            return [
                ("reject", "Message rejected due to error")]

        logger.info("wrap original message in a new message envelope")
        msg = _wrap_message(milter)
        text_body, text_content = _get_body_content(msg, "plain")
        html_body, html_content = _get_body_content(msg, "html")
        if text_content is None and html_content is None:
            raise Exception("no message body present after wrapping, "
                            "give up ...")

    if text_content is not None:
        logger.info(f"{action} text disclaimer")

        if action == "prepend":
            content = f"{text}{text_content}"
        else:
            content = f"{text_content}{text}"

        text_body.set_content(
            content.encode(), maintype="text", subtype="plain")
        text_body.set_param("charset", "UTF-8", header="Content-Type")

    if html_content is not None:
        logger.info(f"{action} html disclaimer")

        soup = BeautifulSoup(html_content, "html.parser")

        body = soup.find('body')
        if body:
            soup = body

        if action == "prepend":
            soup.insert(0, copy(html))
        else:
            soup.append(html)

        html_body.set_content(
            str(soup).encode(), maintype="text", subtype="html")
        html_body.set_param("charset", "UTF-8", header="Content-Type")

    try:
        logger.debug("serialize message as bytes")
        data = msg.as_bytes(policy=SMTP)
    except Exception as e:
        logger.waring(
            f"unable to serialize message as bytes: {e}")
        try:
            logger.warning("try to serialize message as string")
            data = msg.as_string(policy=SMTP)
            data = data.encode("ascii", errors="replace")
        except Exception as e:
            raise e

    body_pos = data.find(b"\r\n\r\n") + 4
    milter.fp.seek(0)
    milter.fp.write(data[body_pos:])
    milter.fp.truncate()

    if pretend:
        return

    logger.debug("milter: replacebody")
    milter.replacebody(data[body_pos:])
    del data

    fields = {
        "mime-version": {
            "field": "MIME-Version",
            "value": msg.get("MIME-Version"),
            "modified": False},
        "content-type": {
            "field": "Content-Type",
            "value": msg.get("Content-Type"),
            "modified": False},
        "content-transfer-encoding": {
            "field": "Content-Transfer-Encoding",
            "value": msg.get("Content-Transfer-Encoding"),
            "modified": False}}

    for field, value in milter.fields.copy():
        field_lower = field.lower()
        if field_lower in fields and fields[field_lower]["value"] is not None:
            mod_header(field=f"^{field}$", value=fields[field_lower]["value"],
                       milter=milter, pretend=pretend, logger=logger)
            fields[field_lower]["modified"] = True

        elif field_lower.startswith("content-"):
            del_header(field=f"^{field}$", milter=milter,
                       pretend=pretend, logger=logger)

    for field in fields.values():
        if not field["modified"] and field["value"] is not None:
            add_header(field=field["field"], value=field["value"],
                       milter=milter, pretend=pretend, logger=logger)


class Action:
    """Action to implement a pre-configured action to perform on e-mails."""
    _types = {
        "add_header": ["fields"],
        "del_header": ["fields"],
        "mod_header": ["fields"],
        "add_disclaimer": ["fields", "body"]}

    def __init__(self, name, local_addrs, conditions, action_type, args,
                 loglevel=logging.INFO, pretend=False):
        logger = logging.getLogger(name)
        self.logger = CustomLogger(logger, {"name": name})
        self.logger.setLevel(loglevel)

        self.conditions = Conditions(
            local_addrs=local_addrs,
            args=conditions,
            logger=self.logger)
        self.pretend = pretend
        self._args = {}

        if action_type not in self._types:
            raise RuntimeError(f"invalid action_type '{action_type}'")
        self._needs = self._types[action_type]

        try:
            if action_type == "add_header":
                self._func = add_header
                self._args["field"] = args["header"]
                self._args["value"] = args["value"]
                if "idx" in args:
                    self._args["idx"] = args["idx"]

            elif action_type in ["mod_header", "del_header"]:
                args["field"] = args["header"]
                del args["header"]
                regex_args = ["field"]

                if action_type == "mod_header":
                    self._func = mod_header
                    self._args["value"] = args["value"]
                    regex_args.append("search")
                elif action_type == "del_header" and "value" in args:
                    self._func = del_header
                    regex_args.append("value")

                for arg in regex_args:
                    try:
                        self._args[arg] = re.compile(
                            args[arg],
                            re.MULTILINE + re.DOTALL + re.IGNORECASE)
                    except re.error as e:
                        raise RuntimeError(
                            f"unable to parse {arg} regex: {e}")

            elif action_type == "add_disclaimer":
                self._func = add_disclaimer
                if args["action"] not in ["append", "prepend"]:
                    raise RuntimeError(f"invalid action '{args['action']}'")

                self._args["action"] = args["action"]

                if args["error_policy"] not in ["wrap", "ignore", "reject"]:
                    raise RuntimeError(f"invalid policy '{args['policy']}'")

                self._args["policy"] = args["error_policy"]

                try:
                    with open(args["html_file"], "r") as f:
                        html = BeautifulSoup(
                            f.read(), "html.parser")
                        body = html.find('body')
                        if body:
                            # just use content within the body tag if present
                            html = body
                        self._args["html"] = html
                    with open(args["text_file"], "r") as f:
                        self._args["text"] = f.read()
                except IOError as e:
                    raise RuntimeError(f"unable to read template: {e}")

        except KeyError as e:
            raise RuntimeError(
                f"mandatory argument not found: {e}")

    def needs(self):
        """Return the needs of this action."""
        return self._needs

    def execute(self, milter, pretend=None):
        """Execute configured action."""
        if pretend is None:
            pretend = self.pretend

        logger = CustomLogger(self.logger, {"qid": milter.qid})

        return self._func(
            milter=milter, pretend=pretend, logger=logger, **self._args)
