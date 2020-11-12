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


def add_header(milter, field, value, pretend=False, update_msg=True,
               logger=logging.getLogger(__name__)):
    """Add a mail header field."""
    if update_msg:
        header = f"{field}: {value}"
        if logger.getEffectiveLevel() == logging.DEBUG:
            logger.debug(f"add_header: {header}")
        else:
            logger.info(f"add_header: {header[0:70]}")

        milter.msg.add_header(field, value)

    if pretend:
        return

    encoded_value = _replace_illegal_chars(
        Header(s=value).encode())
    milter.logger.debug(f"milter: addheader: {field}: {encoded_value}")
    milter.addheader(field, encoded_value, -1)


def mod_header(milter, field, value, search=None, pretend=False,
               update_msg=True, logger=logging.getLogger(__name__)):
    """Change the value of a mail header field."""
    if isinstance(field, str):
        field = re.compile(field, re.IGNORECASE)

    if isinstance(search, str):
        search = re.compile(search, re.MULTILINE + re.DOTALL + re.IGNORECASE)

    occ = defaultdict(int)

    for i, (f, v) in enumerate(milter.msg.items()):
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

        if update_msg:
            header = f"{f}: {v}"
            new_header = f"{f}: {new_v}"

            if logger.getEffectiveLevel() == logging.DEBUG:
                logger.debug(f"mod_header: {header}: {new_header}")
            else:
                logger.info(f"mod_header: {header[0:70]}: {new_header[0:70]}")

            milter.msg.replace_header(f, new_v, occ=occ[f_lower])

        if pretend:
            continue

        encoded_value = _replace_illegal_chars(
            Header(s=new_v).encode())
        milter.logger.debug(
            f"milter: chgheader: {f}[{occ[f_lower]}]: {encoded_value}")
        milter.chgheader(f, occ[f_lower], encoded_value)


def del_header(milter, field, value=None, pretend=False, update_msg=True,
               logger=logging.getLogger(__name__)):
    """Delete a mail header field."""
    if isinstance(field, str):
        field = re.compile(field, re.IGNORECASE)

    if isinstance(value, str):
        value = re.compile(value, re.MULTILINE + re.DOTALL + re.IGNORECASE)

    occ = defaultdict(int)

    for f, v in milter.msg.items():
        f_lower = f.lower()
        occ[f_lower] += 1

        if not field.match(f):
            continue

        if value is not None and not value.search(v):
            continue

        if update_msg:
            header = f"{f}: {v}"
            if logger.getEffectiveLevel() == logging.DEBUG:
                logger.debug(f"del_header: {header}")
            else:
                logger.info(f"del_header: {header[0:70]}")
                milter.msg.remove_header(f, occ=occ[f_lower])

        occ[f_lower] -= 1

        if not pretend:
            milter.logger.debug(
                f"milter: chgheader: {f}[{occ[f_lower]}]:")
            milter.chgheader(f, occ[f_lower], "")


def _serialize_msg(msg, logger):
    if not msg["MIME-Version"]:
        msg.add_header("MIME-Version", "1.0")

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


def _get_body_content(msg, pref):
    part = None
    content = None
    if not msg.is_multipart() and msg.get_content_type() == f"text/{pref}":
        part = msg
    else:
        part = msg.get_body(preferencelist=(pref))

    if part is not None:
        content = part.get_content()

    return (part, content)


def _has_content_before_body_tag(soup):
    s = copy(soup)
    for element in s.find_all("head") + s.find_all("body"):
        element.extract()

    if len(s.text.strip()) > 0:
        return True

    return False


def _patch_message_body(milter, action, text, html, logger):
    text_body, text_content = _get_body_content(milter.msg, "plain")
    html_body, html_content = _get_body_content(milter.msg, "html")

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
        del text_body["MIME-Version"]

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
        del html_body["MIME-Version"]


def _update_body(milter, logger):
    data = _serialize_msg(milter.msg, logger)
    body_pos = data.find(b"\r\n\r\n") + 4
    logger.debug("milter: replacebody")
    milter.replacebody(data[body_pos:])
    del data


def _update_headers(milter, original_headers, logger):
    # serialize the message object so it updates its headers internally
    milter.msg.as_bytes()
    for field, value in original_headers:
        if field not in milter.msg:
            del_header(milter, field=f"^{field}$", update_msg=False,
                       logger=logger)

    for field, value in milter.msg.items():
        field_lower = field.lower()
        if not [f for f in original_headers if f[0].lower() == field_lower]:
            add_header(milter, field=field, value=value, update_msg=False,
                       logger=logger)
        else:
            mod_header(milter, field=f"^{field}$", value=value,
                       update_msg=False, logger=logger)


def _wrap_message(milter, logger):
    attachment = MIMEPart()
    attachment.set_content(milter.msg.as_bytes(),
                           maintype="plain", subtype="text",
                           disposition="attachment",
                           filename=f"{milter.qid}.eml",
                           params={"name": f"{milter.qid}.eml"})

    milter.msg.clear_content()
    milter.msg.set_content(
        "Please see the original email attached.")
    milter.msg.add_alternative(
        "<html><body>Please see the original email attached.</body></html>",
        subtype="html")
    milter.msg.make_mixed()
    milter.msg.attach(attachment)


def _inject_body(milter):
    if not milter.msg.is_multipart():
        milter.msg.make_mixed()

    attachments = []
    for attachment in milter.msg.iter_attachments():
        if "content-disposition" not in attachment:
            attachment["Content-Disposition"] = "attachment"
        attachments.append(attachment)

    milter.msg.clear_content()
    milter.msg.set_content("")
    milter.msg.add_alternative("", subtype="html")
    milter.msg.make_mixed()

    for attachment in attachments:
        milter.msg.attach(attachment)


def add_disclaimer(milter, text, html, action, policy, pretend=False,
                   logger=logging.getLogger(__name__)):
    """Append or prepend a disclaimer to the mail body."""
    original_headers = milter.msg.items()

    try:
        try:
            _patch_message_body(milter, action, text, html, logger)
        except RuntimeError as e:
            logger.info(f"{e}, inject empty plain and html body")
            _inject_body(milter)
            _patch_message_body(milter, action, text, html, logger)
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
            _wrap_message(milter, logger)
            _patch_message_body(milter, action, text, html, logger)
        except Exception as e:
            logger.error(e)
            raise Exception(
                "unable to wrap message in a new message envelope, "
                "give up ...")

    if pretend:
        return

    _update_headers(milter, original_headers, logger)
    _update_body(milter, logger)


def store(milter, directory, pretend=False,
          logger=logging.getLogger(__name__)):
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    store_id = f"{timestamp}_{milter.qid}"
    datafile = os.path.join(directory, store_id)

    logger.info(f"store message in file {datafile}")
    try:
        with open(datafile, "wb") as fp:
            fp.write(milter.msg.as_bytes())
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

    def execute(self, milter, pretend=None):
        """Execute configured action."""
        if pretend is None:
            pretend = self.pretend

        logger = CustomLogger(self.logger, {"qid": milter.qid})

        return self._func(milter=milter, pretend=pretend,
                          logger=logger, **self._args)
