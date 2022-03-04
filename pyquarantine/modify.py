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
    "AddHeader",
    "ModHeader",
    "DelHeader",
    "AddDisclaimer",
    "RewriteLinks",
    "Modify"]

import logging
import re

from base64 import b64encode
from bs4 import BeautifulSoup
from collections import defaultdict
from copy import copy
from email.message import MIMEPart
from email.policy import SMTP
from html import escape
from urllib.parse import quote

from pyquarantine import replace_illegal_chars
from pyquarantine.base import CustomLogger


class AddHeader:
    """Add a mail header field."""
    _headersonly = True

    def __init__(self, field, value, pretend=False):
        self.field = field
        self.value = value
        self.pretend = pretend

    def execute(self, milter, logger):
        header = f"{self.field}: {self.value}"
        if logger.getEffectiveLevel() == logging.DEBUG:
            logger.debug(f"add_header: {header}")
        else:
            logger.info(f"add_header: {header[0:70]}")

        milter.msg.add_header(self.field, self.value)
        if not self.pretend:
            milter.addheader(self.field, self.value)


class ModHeader:
    """Change the value of a mail header field."""
    _headersonly = True

    def __init__(self, field, value, search=None, pretend=False):
        try:
            self.field = re.compile(field, re.IGNORECASE)
            self.search = search
            if self.search is not None:
                self.search = re.compile(
                    self.search, re.MULTILINE + re.DOTALL + re.IGNORECASE)

        except re.error as e:
            raise RuntimeError(e)

        self.value = value
        self.pretend = pretend

    def execute(self, milter, logger):
        idx = defaultdict(int)

        for i, (field, value) in enumerate(milter.msg.items()):
            field_lower = field.lower()
            idx[field_lower] += 1

            if not self.field.match(field):
                continue

            new_value = value
            if self.search is not None:
                new_value = self.search.sub(self.value, value).strip()
            else:
                new_value = self.value

            if not new_value:
                logger.warning(
                    "mod_header: resulting value is empty, "
                    "skip modification")
                continue

            if new_value == value:
                continue

            header = f"{field}: {value}"
            new_header = f"{field}: {new_value}"

            if logger.getEffectiveLevel() == logging.DEBUG:
                logger.debug(f"mod_header: {header}: {new_header}")
            else:
                logger.info(
                    f"mod_header: {header[0:70]}: {new_header[0:70]}")

            milter.msg.replace_header(
                field, replace_illegal_chars(new_value), idx=idx[field_lower])

            if not self.pretend:
                milter.chgheader(field, new_value, idx=idx[field_lower])


class DelHeader:
    """Delete a mail header field."""
    _headersonly = True

    def __init__(self, field, value=None, pretend=False):
        try:
            self.field = re.compile(field, re.IGNORECASE)
            self.value = value
            if self.value is not None:
                self.value = re.compile(
                    value, re.MULTILINE + re.DOTALL + re.IGNORECASE)
        except re.error as e:
            raise RuntimeError(e)

        self.pretend = pretend

    def execute(self, milter, logger):
        idx = defaultdict(int)

        for field, value in milter.msg.items():
            field_lower = field.lower()
            idx[field_lower] += 1

            if not self.field.match(field):
                continue

            if self.value is not None and not self.value.search(value):
                continue

            header = f"{field}: {value}"
            if logger.getEffectiveLevel() == logging.DEBUG:
                logger.debug(f"del_header: {header}")
            else:
                logger.info(f"del_header: {header[0:70]}")
            milter.msg.remove_header(field, idx=idx[field_lower])

            if not self.pretend:
                milter.chgheader(field, "", idx=idx[field_lower])

            idx[field_lower] -= 1


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


def _wrap_message(milter):
    attachment = MIMEPart(policy=SMTP)
    attachment.set_content(milter.msg_as_bytes(),
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


class AddDisclaimer:
    """Append or prepend a disclaimer to the mail body."""
    _headersonly = False

    def __init__(self, text_template, html_template, action, error_policy,
                 add_html_body, pretend=False):
        self.text_template_path = text_template
        self.html_template_path = html_template
        try:
            with open(text_template, "r") as f:
                self.text_template = f.read()

            with open(html_template, "r") as f:
                self.html_template = f.read()

        except IOError as e:
            raise RuntimeError(e)
        self.action = action.lower()
        assert self.action in ["prepend", "append"], \
            f"invalid action '{action}'"
        self.error_policy = error_policy.lower()
        assert self.error_policy in ["ignore", "reject", "wrap"], \
            f"invalid error_policy '{error_policy}'"
        self.add_html_body = add_html_body
        self.pretend = pretend

    def patch_message_body(self, milter, logger):
        text_body, text_content = milter.msg.get_body_content("plain")
        html_body, html_content = milter.msg.get_body_content("html")

        if text_content is None and html_content is None:
            logger.info("message contains no body, inject it")
            if self.add_html_body:
                milter.msg.set_body("", "")
                html_body, html_content = milter.msg.get_body_content("html")
            else:
                milter.msg.set_body("")
            text_body, text_content = milter.msg.get_body_content("plain")

        if html_content is None and self.add_html_body:
            logger.info("inject html body based on plain body")
            header = '<meta http-equiv="Content-Type" content="text/html; ' \
                     'charset=utf-8">'
            html_text = re.sub(r"^(.*)$", r"\1<br/>",
                               escape(text_content, quote=False),
                               flags=re.MULTILINE)
            milter.msg.set_body(None, f"{header}{html_text}")
            text_body, text_content = milter.msg.get_body_content("plain")
            html_body, html_content = milter.msg.get_body_content("html")

        variables = defaultdict(str, milter.msginfo["vars"])
        variables["ENVELOPE_FROM"] = escape(
            milter.msginfo["mailfrom"], quote=False)
        variables["ENVELOPE_FROM_URL"] = escape(
            quote(milter.msginfo["mailfrom"]), quote=False)

        if text_content is not None:
            logger.info(f"{self.action} text disclaimer")
            text_template = self.text_template.format_map(variables)

            if self.action == "prepend":
                content = f"{text_template}{text_content}"
            else:
                content = f"{text_content}{text_template}"

            text_body.set_content(
                content.encode(errors="replace"),
                maintype="text",
                subtype="plain")
            text_body.set_param("charset", "UTF-8", header="Content-Type")
            del text_body["MIME-Version"]

        if html_content is not None:
            logger.info(f"{self.action} html disclaimer")

            soup = BeautifulSoup(html_content, "html.parser")
            body = soup.find('body')
            if not body:
                body = soup
            elif _has_content_before_body_tag(soup):
                body = soup

            html_template = self.html_template.format_map(variables)
            html_template = BeautifulSoup(html_template, "html.parser")
            html_template = html_template.find("body") or html_template
            if self.action == "prepend":
                body.insert(0, html_template)
            else:
                body.append(html_template)

            html_body.set_content(
                str(soup).encode(errors="replace"),
                maintype="text",
                subtype="html")
            html_body.set_param("charset", "UTF-8", header="Content-Type")
            del html_body["MIME-Version"]

    def execute(self, milter, logger):
        old_headers = milter.msg.items()

        try:
            self.patch_message_body(milter, logger)
        except Exception as e:
            logger.warning(e)
            if self.error_policy == "ignore":
                logger.info(
                    "unable to add disclaimer to message body, "
                    "ignore error according to policy")
                return
            elif self.error_policy == "reject":
                logger.info(
                    "unable to add disclaimer to message body, "
                    "reject message according to policy")
                return [
                    ("reject", "Message rejected due to error")]

            logger.info("wrap original message in a new message envelope")
            try:
                _wrap_message(milter)
                self.patch_message_body(milter, logger)
            except Exception as e:
                logger.error(e)
                raise Exception(
                    "unable to wrap message in a new message envelope, "
                    "give up ...")

        if not self.pretend:
            milter.update_headers(old_headers)
            milter.replacebody()


class RewriteLinks:
    """Rewrite link targets in the mail html body."""
    _headersonly = False

    def __init__(self, repl, pretend=False):
        self.repl = repl
        self.pretend = pretend

    def execute(self, milter, logger):
        html_body, html_content = _get_body_content(milter.msg, "html")
        if html_content is not None:
            soup = BeautifulSoup(html_content, "html.parser")

            rewritten = 0
            for link in soup.find_all("a", href=True):
                if not link["href"]:
                    continue

                if "{URL_B64}" in self.repl:
                    url_b64 = b64encode(link["href"].encode()).decode()
                    target = self.repl.replace("{URL_B64}", url_b64)
                else:
                    target = self.repl

                link["href"] = target
                rewritten += 1

            if rewritten:
                logger.info(f"rewrote {rewritten} link(s) in html body")

                html_body.set_content(
                    str(soup).encode(), maintype="text", subtype="html")
                html_body.set_param("charset", "UTF-8", header="Content-Type")
                del html_body["MIME-Version"]

                if not self.pretend:
                    milter.replacebody()


class Modify:
    MODIFICATION_TYPES = {
        "add_header": AddHeader,
        "mod_header": ModHeader,
        "del_header": DelHeader,
        "add_disclaimer": AddDisclaimer,
        "rewrite_links": RewriteLinks}

    def __init__(self, cfg, local_addrs, debug):
        self.cfg = cfg
        self.logger = logging.getLogger(cfg["name"])
        self.logger.setLevel(cfg.get_loglevel(debug))
        cfg["options"]["pretend"] = cfg["pretend"]
        self._modification = self.MODIFICATION_TYPES[cfg["type"]](
            **cfg["options"])
        self._headersonly = self._modification._headersonly

    def __str__(self):
        cfg = []
        for key, value in self.cfg["options"].items():
            cfg.append(f"{key}={value}")
        class_name = type(self._modification).__name__
        return f"{class_name}(" + ", ".join(cfg) + ")"

    def execute(self, milter):
        logger = CustomLogger(
            self.logger, {"name": self.cfg["name"], "qid": milter.qid})
        self._modification.execute(milter, logger)
