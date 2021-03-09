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
    "add_header",
    "mod_header",
    "del_header",
    "add_disclaimer",
    "rewrite_links",
    "store",
    "ActionConfig",
    "Action"]

import logging
import os
import re

from base64 import b64encode
from bs4 import BeautifulSoup
from collections import defaultdict
from copy import copy
from datetime import datetime
from email.message import MIMEPart

from pymodmilter import CustomLogger, BaseConfig
from pymodmilter.conditions import ConditionsConfig, Conditions
from pymodmilter import replace_illegal_chars


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


def _patch_message_body(milter, action, text_template, html_template, logger):
    text_body, text_content = _get_body_content(milter.msg, "plain")
    html_body, html_content = _get_body_content(milter.msg, "html")

    if text_content is None and html_content is None:
        raise RuntimeError("message does not contain any body part")

    if text_content is not None:
        logger.info(f"{action} text disclaimer")

        if action == "prepend":
            content = f"{text_template}{text_content}"
        else:
            content = f"{text_content}{text_template}"

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
            body.insert(0, copy(html_template))
        else:
            body.append(html_template)

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


def add_disclaimer(milter, text_template, html_template, action, error_policy,
                   pretend=False, logger=logging.getLogger(__name__)):
    """Append or prepend a disclaimer to the mail body."""
    old_headers = milter.msg.items()

    try:
        try:
            _patch_message_body(
                milter, action, text_template, html_template, logger)
        except RuntimeError as e:
            logger.info(f"{e}, inject empty plain and html body")
            _inject_body(milter)
            _patch_message_body(
                milter, action, text_template, html_template, logger)
    except Exception as e:
        logger.warning(e)
        if error_policy == "ignore":
            logger.info(
                "unable to add disclaimer to message body, "
                "ignore error according to policy")
            return
        elif error_policy == "reject":
            logger.info(
                "unable to add disclaimer to message body, "
                "reject message according to policy")
            return [
                ("reject", "Message rejected due to error")]

        logger.info("wrap original message in a new message envelope")
        try:
            _wrap_message(milter, logger)
            _patch_message_body(
                milter, action, text_template, html_template, logger)
        except Exception as e:
            logger.error(e)
            raise Exception(
                "unable to wrap message in a new message envelope, "
                "give up ...")

    if not pretend:
        milter.update_headers(old_headers)
        milter.replacebody()


def rewrite_links(milter, repl, pretend=False,
                  logger=logging.getLogger(__name__)):
    """Rewrite link targets in the mail html body."""

    html_body, html_content = _get_body_content(milter.msg, "html")
    if html_content is not None:
        soup = BeautifulSoup(html_content, "html.parser")

        rewritten = 0
        for link in soup.find_all("a", href=True):
            if not link["href"]:
                continue

            if "{URL_B64}" in repl:
                url_b64 = b64encode(link["href"].encode()).decode()
                target = repl.replace("{URL_B64}", url_b64)
            else:
                target = repl

            link["href"] = target
            rewritten += 1

        if rewritten:
            logger.info(f"rewrote {rewritten} link(s) in html body")

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


class ActionConfig(BaseConfig):
    def __init__(self, idx, rule_cfg, cfg, debug):
        if "name" in cfg:
            assert isinstance(cfg["name"], str), \
                f"{rule_cfg['name']}: Action #{idx}: name: invalid value, " \
                f"should be string"
            cfg["name"] = f"{rule_cfg['name']}: {cfg['name']}"
        else:
            cfg["name"] = f"{rule_cfg['name']}: Action #{idx}"

        if "loglevel" not in cfg:
            cfg["loglevel"] = rule_cfg["loglevel"]

        super().__init__(cfg, debug)

        self["pretend"] = rule_cfg["pretend"]
        self["conditions"] = None
        self["type"] = ""

        if "pretend" in cfg:
            pretend = cfg["pretend"]
            assert isinstance(pretend, bool), \
                f"{self['name']}: pretend: invalid value, should be bool"
            self["pretend"] = pretend

        assert "type" in cfg, \
            f"{self['name']}: mandatory parameter 'type' not found"
        assert isinstance(cfg["type"], str), \
            f"{self['name']}: type: invalid value, should be string"
        self["type"] = cfg["type"]

        if self["type"] == "add_header":
            self["func"] = add_header
            self["need_body"] = False
            self.add_string_arg(cfg, ("field", "value"))

        elif self["type"] == "mod_header":
            self["func"] = mod_header
            self["need_body"] = False
            args = ["field", "value"]
            if "search" in cfg:
                args.append("search")

            for arg in args:
                self.add_string_arg(cfg, arg)
                if arg in ("field", "search"):
                    try:
                        self["args"][arg] = re.compile(
                            self["args"][arg],
                            re.MULTILINE + re.DOTALL + re.IGNORECASE)
                    except re.error as e:
                        raise ValueError(f"{self['name']}: {arg}: {e}")

        elif self["type"] == "del_header":
            self["func"] = del_header
            self["need_body"] = False
            args = ["field"]
            if "value" in cfg:
                args.append("value")

            for arg in args:
                self.add_string_arg(cfg, arg)
                try:
                    self["args"][arg] = re.compile(
                        self["args"][arg],
                        re.MULTILINE + re.DOTALL + re.IGNORECASE)
                except re.error as e:
                    raise ValueError(f"{self['name']}: {arg}: {e}")

        elif self["type"] == "add_disclaimer":
            self["func"] = add_disclaimer
            self["need_body"] = True

            if "error_policy" not in cfg:
                cfg["error_policy"] = "wrap"

            self.add_string_arg(
                cfg, ("action", "html_template", "text_template",
                      "error_policy"))
            assert self["args"]["action"] in ("append", "prepend"), \
                f"{self['name']}: action: invalid value, " \
                f"should be 'append' or 'prepend'"
            assert self["args"]["error_policy"] in ("wrap",
                                                    "ignore",
                                                    "reject"), \
                f"{self['name']}: error_policy: invalid value, " \
                f"should be 'wrap', 'ignore' or 'reject'"

            try:
                with open(self["args"]["html_template"], "r") as f:
                    html = BeautifulSoup(f.read(), "html.parser")
                    body = html.find('body')
                    if body:
                        # just use content within the body tag if present
                        html = body
                    self["args"]["html_template"] = html

                with open(self["args"]["text_template"], "r") as f:
                    self["args"]["text_template"] = f.read()

            except IOError as e:
                raise RuntimeError(
                    f"{self['name']}: unable to open/read template file: {e}")

        elif self["type"] == "rewrite_links":
            self["func"] = rewrite_links
            self["need_body"] = True
            self.add_string_arg(cfg, "repl")

        elif self["type"] == "store":
            self["func"] = store
            self["need_body"] = True

            assert "storage_type" in cfg, \
                f"{self['name']}: mandatory parameter 'storage_type' not found"
            assert isinstance(cfg["type"], str), \
                f"{self['name']}: storage_type: invalid value, " \
                f"should be string"
            self["storage_type"] = cfg["storage_type"]
            if self["storage_type"] == "file":
                self.add_string_arg(cfg, "directory")
            else:
                raise RuntimeError(
                    f"{self['name']}: storage_type: invalid storage type")

        else:
            raise RuntimeError(f"{self['name']}: type: invalid action type")

        if "conditions" in cfg:
            conditions = cfg["conditions"]
            assert isinstance(conditions, dict), \
                f"{self['name']}: conditions: invalid value, should be dict"
            self["conditions"] = ConditionsConfig(self, conditions, debug)

        self.logger.debug(f"pretend={self['pretend']}, "
                          f"loglevel={self['loglevel']}, "
                          f"type={self['type']}, "
                          f"args={self['args']}")


class Action:
    """Action to implement a pre-configured action to perform on e-mails."""

    def __init__(self, milter_cfg, cfg):
        self.logger = cfg.logger

        if cfg["conditions"] is None:
            self.conditions = None
        else:
            self.conditions = Conditions(milter_cfg, cfg["conditions"])

        self.pretend = cfg["pretend"]
        self._name = cfg["name"]
        self._func = cfg["func"]
        self._args = cfg["args"]
        self._need_body = cfg["need_body"]

    def need_body(self):
        """Return the needs of this action."""
        return self._need_body

    def execute(self, milter, pretend=None):
        """Execute configured action."""
        if pretend is None:
            pretend = self.pretend

        logger = CustomLogger(
            self.logger, {"name": self._name, "qid": milter.qid})

        return self._func(milter=milter, pretend=pretend,
                          logger=logger, **self._args)
