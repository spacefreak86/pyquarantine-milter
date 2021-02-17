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
from email.message import MIMEPart

from pymodmilter import CustomLogger, Conditions, replace_illegal_chars


def add_header(milter, field, value, pretend=False,
               logger=logging.getLogger(__name__)):
    """Add a mail header field."""
    header = f"{field}: {value}"
    if logger.getEffectiveLevel() == logging.DEBUG:
        logger.debug(f"add_header: {header}")
    else:
        logger.info(f"add_header: {header[0:70]}")

    milter.msg.add_header(field, replace_illegal_chars(value))

    if not pretend:
        milter.addheader(field, value)


def mod_header(milter, field, value, search=None, pretend=False,
               logger=logging.getLogger(__name__)):
    """Change the value of a mail header field."""
    if isinstance(field, str):
        field = re.compile(field, re.IGNORECASE)

    if isinstance(search, str):
        search = re.compile(search, re.MULTILINE + re.DOTALL + re.IGNORECASE)

    idx = defaultdict(int)

    for i, (f, v) in enumerate(milter.msg.items()):
        f_lower = f.lower()
        idx[f_lower] += 1

        if not field.match(f):
            continue

        new_value = v
        if search is not None:
            new_value = search.sub(value, v).strip()
        else:
            new_value = value

        if not new_value:
            logger.warning(
                "mod_header: resulting value is empty, "
                "skip modification")
            continue

        if new_value == v:
            continue

        header = f"{f}: {v}"
        new_header = f"{f}: {new_value}"

        if logger.getEffectiveLevel() == logging.DEBUG:
            logger.debug(f"mod_header: {header}: {new_header}")
        else:
            logger.info(f"mod_header: {header[0:70]}: {new_header[0:70]}")

        milter.msg.replace_header(
            f, replace_illegal_chars(new_value), idx=idx[f_lower])

        if not pretend:
            milter.chgheader(f, new_value, idx=idx[f_lower])


def del_header(milter, field, value=None, pretend=False,
               logger=logging.getLogger(__name__)):
    """Delete a mail header field."""
    if isinstance(field, str):
        field = re.compile(field, re.IGNORECASE)

    if isinstance(value, str):
        value = re.compile(value, re.MULTILINE + re.DOTALL + re.IGNORECASE)

    idx = defaultdict(int)

    for f, v in milter.msg.items():
        f_lower = f.lower()
        idx[f_lower] += 1

        if not field.match(f):
            continue

        if value is not None and not value.search(v):
            continue

        header = f"{f}: {v}"
        if logger.getEffectiveLevel() == logging.DEBUG:
            logger.debug(f"del_header: {header}")
        else:
            logger.info(f"del_header: {header[0:70]}")
        milter.msg.remove_header(f, idx=idx[f_lower])

        if not pretend:
            milter.chgheader(f, "", idx=idx[f_lower])

        idx[f_lower] -= 1


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
    old_headers = milter.msg.items()

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

    if not pretend:
        milter.update_headers(old_headers)
        milter.replacebody()


def replace_links(milter, repl, pretend=False,
                  logger=logging.getLogger(__name__)):
    """Replace links in the mail body."""

    text_body, text_content = _get_body_content(milter.msg, "plain")
    html_body, html_content = _get_body_content(milter.msg, "html")

    if text_content is not None:
        logger.info("replace links in text body")

        content = text_content

        text_body.set_content(
            content.encode(), maintype="text", subtype="plain")
        text_body.set_param("charset", "UTF-8", header="Content-Type")
        del text_body["MIME-Version"]

    if html_content is not None:
        logger.info("replace links in html body")

        soup = BeautifulSoup(html_content, "html.parser")

        for link in soup.find_all("a", href=True):
            link["href"] = repl

        html_body.set_content(
            str(soup).encode(), maintype="text", subtype="html")
        html_body.set_param("charset", "UTF-8", header="Content-Type")
        del html_body["MIME-Version"]

    if not pretend:
        milter.replacebody()


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
        "replace_links": True,
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

            elif action_type == "replace_links":
                self._func = replace_links
                self._args["repl"] = args["repl"]

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
