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
import os
import re

from bs4 import BeautifulSoup
from collections import defaultdict
from copy import copy
from datetime import datetime
from email.header import Header
from email.message import MIMEPart
from email.policy import SMTP

from pymodmilter import CustomLogger, Conditions


def _replace_illegal_chars(string):
    """Replace illegal characters in header values."""
    return string.replace(
        "\x00", "").replace(
        "\r", "").replace(
        "\n", "")


def add_header(milter, msg, field, value, pretend=False,
               logger=logging.getLogger(__name__)):
    """Add a mail header field."""
    header = f"{field}: {value}"
    if logger.getEffectiveLevel() == logging.DEBUG:
        logger.debug(f"add_header: {header}")
    else:
        logger.info(f"add_header: {header[0:70]}")

    msg.add_header(field, value)

    if pretend:
        return

    encoded_value = _replace_illegal_chars(
        Header(s=value).encode())
    milter.logger.debug(f"milter: addheader: {field}: {encoded_value}")
    milter.addheader(field, encoded_value, -1)


def mod_header(milter, msg, field, value, search=None, pretend=False,
               logger=logging.getLogger(__name__)):
    """Change the value of a mail header field."""
    if isinstance(field, str):
        field = re.compile(field, re.IGNORECASE)

    if isinstance(search, str):
        search = re.compile(search, re.MULTILINE + re.DOTALL + re.IGNORECASE)

    occ = defaultdict(int)

    for i, (f, v) in enumerate(msg.items()):
        f_lower = f.lower()
        occ[f_lower] += 1

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
                "mod_header: resulting value is empty, "
                "skip modification")
            continue

        header = f"{f}: {v}"
        new_header = f"{f}: {new_v}"

        if logger.getEffectiveLevel() == logging.DEBUG:
            logger.debug(f"mod_header: {header}: {new_header}")
        else:
            logger.info(f"mod_header: {header[0:70]}: {new_header[0:70]}")

        msg.replace_header(f, new_v, occ=occ[f_lower])

        if pretend:
            continue

        encoded_value = _replace_illegal_chars(
            Header(s=new_v).encode())
        milter.logger.debug(
            f"milter: chgheader: {f}[{occ[f_lower]}]: {encoded_value}")
        milter.chgheader(f, occ[f_lower], encoded_value)


def del_header(milter, msg, field, value=None, pretend=False,
               logger=logging.getLogger(__name__)):
    """Delete a mail header field."""
    if isinstance(field, str):
        field = re.compile(field, re.IGNORECASE)

    if isinstance(value, str):
        value = re.compile(value, re.MULTILINE + re.DOTALL + re.IGNORECASE)

    occ = defaultdict(int)

    # iterate a copy of milter.fields because elements may get removed
    # during iteration
    for f, v in msg.items():
        f_lower = f.lower()
        occ[f_lower] += 1

        if not field.match(f):
            continue

        if value is not None and not value.search(v):
            continue

        header = f"{f}: {v}"
        if logger.getEffectiveLevel() == logging.DEBUG:
            logger.debug(f"del_header: {header}")
        else:
            logger.info(f"del_header: {header[0:70]}")

        msg.remove_header(f, occ=occ[f_lower])

        occ[f_lower] -= 1

        if not pretend:
            milter.logger.debug(
                f"milter: chgheader: {f}[{occ[f_lower]}]:")
            milter.chgheader(f, occ[f_lower], "")


def _get_body_content(msg, body_type):
    content = None
    body_part = msg.get_body(preferencelist=(body_type))
    if body_part is not None:
        content = body_part.get_content()

    return (body_part, content)


def _has_content_before_body_tag(soup):
    s = copy(soup)
    for element in s.find_all("head") + s.find_all("body"):
        element.extract()

    if len(s.text.strip()) > 0:
        return True

    return False


def _patch_message_body(msg, action, text, html, logger):
    text_body, text_content = _get_body_content(msg, "plain")
    html_body, html_content = _get_body_content(msg, "html")

    if text_content is None and html_content is None:
        raise RuntimeError("message does not contain any body part")

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
        if not body:
            body = soup
        elif _has_content_before_body_tag(soup):
            body = soup

        if action == "prepend":
            body.insert(0, copy(html))
        else:
            body.append(html)

        html_body.set_content(
            str(soup).encode(), maintype="text", subtype="html")
        html_body.set_param("charset", "UTF-8", header="Content-Type")


def _serialize_msg(msg, logger):
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

    return data


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

    milter.body_data.seek(0)
    data += b"\r\n" + milter.body_data.read()

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


def add_disclaimer(milter, msg, text, html, action, policy, pretend=False,
                   logger=logging.getLogger(__name__)):
    """Append or prepend a disclaimer to the mail body."""
    update_headers = False

    try:
        try:
            _patch_message_body(msg, action, text, html, logger)
            data = _serialize_msg(msg, logger)
            if not msg.is_multipart():
                update_headers = True
        except RuntimeError as e:
            logger.info(f"{e}, inject empty plain and html body")
            msg = _inject_body(milter, msg)
            _patch_message_body(msg, action, text, html, logger)
            data = _serialize_msg(msg, logger)
            update_headers = True
    except Exception as e:
        logger.warning(e)
        if policy == "ignore":
            logger.info(
                "unable to add disclaimer to message body, "
                "ignore error according to policy")
            return
        elif policy == "reject":
            logger.info(
                "unable to add disclaimer to message body, "
                "reject message according to policy")
            return [
                ("reject", "Message rejected due to error")]

        logger.info("wrap original message in a new message envelope")
        try:
            msg = _wrap_message(milter)
            _patch_message_body(msg, action, text, html, logger)
            data = _serialize_msg(msg, logger)
            update_headers = True
        except Exception as e:
            logger.error(e)
            raise Exception(
                "unable to wrap message in a new message envelope, "
                "give up ...")

    body_pos = data.find(b"\r\n\r\n") + 4
    milter.body_data.seek(0)
    milter.body_data.write(data[body_pos:])
    milter.body_data.truncate()

    if pretend:
        return

    logger.debug("milter: replacebody")
    milter.replacebody(data[body_pos:])
    del data

    if not update_headers:
        return

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

    for field, value in msg.items():
        field_lower = field.lower()
        if field_lower in fields and fields[field_lower]["value"] is not None:
            mod_header(milter, msg, field=f"^{field}$",
                       value=fields[field_lower]["value"],
                       pretend=pretend, logger=logger)
            fields[field_lower]["modified"] = True

        elif field_lower.startswith("content-"):
            del_header(milter, msg, field=f"^{field}$",
                       pretend=pretend, logger=logger)

    for field in fields.values():
        if not field["modified"] and field["value"] is not None:
            add_header(milter, msg, field=field["field"], value=field["value"],
                       pretend=pretend, logger=logger)


def store(milter, msg, directory, pretend=False,
          logger=logging.getLogger(__name__)):
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    store_id = f"{timestamp}_{milter.qid}"
    datafile = os.path.join(directory, store_id)

    milter.body_data.seek(0)
    logger.info(f"store message in file {datafile}")
    try:
        with open(datafile, "wb") as fp:
            fp.write(msg.as_bytes())
    except IOError as e:
        raise RuntimeError(f"unable to store message: {e}")


class Action:
    """Action to implement a pre-configured action to perform on e-mails."""
    _need_body_map = {
        "add_header": False,
        "del_header": False,
        "mod_header": False,
        "add_disclaimer": True,
        "store": True}

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

        if action_type not in self._need_body_map:
            raise RuntimeError(f"invalid action type '{action_type}'")
        self._need_body = self._need_body_map[action_type]

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
                elif action_type == "del_header":
                    self._func = del_header
                    if "value" in args:
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
            elif action_type == "store":
                self._func = store
                if args["storage_type"] not in ["file"]:
                    raise RuntimeError(
                        "invalid storage_type 'args['storage_type']'")

                if args["storage_type"] == "file":
                    self._args["directory"] = args["directory"]
            else:
                raise RuntimeError(f"invalid action type: {action_type}")

        except KeyError as e:
            raise RuntimeError(
                f"mandatory argument not found: {e}")

    def need_body(self):
        """Return the needs of this action."""
        return self._need_body

    def execute(self, milter, msg, pretend=None):
        """Execute configured action."""
        if pretend is None:
            pretend = self.pretend

        logger = CustomLogger(self.logger, {"qid": milter.qid})

        return self._func(milter=milter, msg=msg, pretend=pretend,
                          logger=logger, **self._args)
