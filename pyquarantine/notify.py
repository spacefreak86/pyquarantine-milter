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
    "BaseNotification",
    "EMailNotification",
    "Notify"]

import email
import logging
import re

from bs4 import BeautifulSoup
from collections import defaultdict
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from html import escape
from os.path import basename
from urllib.parse import quote

from pyquarantine.base import CustomLogger
from pyquarantine import mailer


class BaseNotification:
    "Notification base class"
    _headersonly = True

    def __init__(self, pretend=False):
        self.pretend = pretend

    def execute(self, milter, logger):
        return


class EMailNotification(BaseNotification):
    "Notification class to send notifications via mail."
    _headersonly = False
    _bad_tags = [
        "applet",
        "embed",
        "frame",
        "frameset",
        "head",
        "iframe",
        "script",
        "style"
    ]
    _good_tags = [
        "a",
        "b",
        "br",
        "center",
        "div",
        "font",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "i",
        "img",
        "li",
        "p",
        "pre",
        "span",
        "table",
        "td",
        "th",
        "tr",
        "tt",
        "u",
        "ul"
    ]
    _good_attributes = [
        "align",
        "alt",
        "bgcolor",
        "border",
        "cellpadding",
        "cellspacing",
        "class",
        "color",
        "colspan",
        "dir",
        "face",
        "headers",
        "height",
        "id",
        "name",
        "rowspan",
        "size",
        "src",
        "style",
        "title",
        "type",
        "valign",
        "value",
        "width"
    ]

    def __init__(self, smtp_host, smtp_port, envelope_from, from_header,
                 subject, template, embed_imgs=[], repl_img=None,
                 strip_imgs=False, parser_lib="lxml", pretend=False):
        super().__init__(pretend)
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.mailfrom = envelope_from
        self.from_header = from_header
        self.subject = subject
        try:
            with open(template, "r") as fh:
                self.template = fh.read()
            self.embed_imgs = []
            for img_path in embed_imgs:
                with open(img_path, "rb") as fh:
                    img = MIMEImage(fh.read())
                filename = basename(img_path)
                img.add_header("Content-ID", f"<{filename}>")
                self.embed_imgs.append(img)
            self.replacement_img = repl_img
            self.strip_images = strip_imgs

            if not strip_imgs and repl_img:
                with open(repl_img, "rb") as fh:
                    self.replacement_img = MIMEImage(fh.read())
                self.replacement_img.add_header(
                    "Content-ID", "<removed_for_security_reasons>")

        except IOError as e:
            raise RuntimeError(e)

        self.parser_lib = parser_lib

    def get_msg_body_soup(self, msg, logger):
        "Extract and decode message body, return it as BeautifulSoup object."
        # try to find the body part
        logger.debug("trying to find message body")
        try:
            body = msg.get_body(preferencelist=("html", "plain"))
        except Exception as e:
            logger.error(
                f"an error occured in email.message.EmailMessage.get_body: "
                f"{e}")
            body = None

        if body:
            charset = body.get_content_charset() or "utf-8"
            content = body.get_payload(decode=True)
            try:
                content = content.decode(encoding=charset, errors="replace")
            except LookupError:
                logger.info(
                    f"unknown encoding '{charset}', falling back to UTF-8")
                content = content.decode("utf-8", errors="replace")
            content_type = body.get_content_type()
            if content_type == "text/plain":
                # convert text/plain to text/html
                logger.debug(
                    f"content type is {content_type}, "
                    f"converting to text/html")
                content = re.sub(r"^(.*)$", r"\1<br/>",
                                 escape(content, quote=False),
                                 flags=re.MULTILINE)
            else:
                logger.debug(f"content type is {content_type}")
        else:
            logger.error("unable to find message body")
            content = "ERROR: unable to find message body"

        # create BeautifulSoup object
        length = len(content)
        logger.debug(
            f"trying to create BeatufilSoup object with "
            f"parser lib {self.parser_lib}, "
            f"text length is {length} bytes")
        soup = BeautifulSoup(content, self.parser_lib)
        logger.debug("sucessfully created BeautifulSoup object")

        return soup

    def sanitize(self, soup, logger):
        "Sanitize mail html text."
        logger.debug("sanitize message text")

        # completly remove bad elements
        for element in soup(EMailNotification._bad_tags):
            logger.debug(
                f"removing dangerous tag '{element.name}' "
                f"and its content")
            element.extract()

        # remove not whitelisted elements, but keep their content
        for element in soup.find_all(True):
            if element.name not in EMailNotification._good_tags:
                logger.debug(
                    f"removing tag '{element.name}', keep its content")
                element.replaceWithChildren()

        # remove not whitelisted attributes
        for element in soup.find_all(True):
            for attribute in list(element.attrs.keys()):
                if attribute not in EMailNotification._good_attributes:
                    if element.name == "a" and attribute == "href":
                        logger.debug(
                            f"setting attribute href to '#' "
                            f"on tag '{element.name}'")
                        element["href"] = "#"
                    else:
                        logger.debug(
                            f"removing attribute '{attribute}' "
                            f"from tag '{element.name}'")
                        del(element.attrs[attribute])
        return soup

    def notify(self, msg, qid, mailfrom, recipients, logger,
               template_vars={}, synchronous=False):
        "Notify recipients via email."
        # extract body from email
        soup = self.get_msg_body_soup(msg, logger)

        # replace picture sources
        image_replaced = False
        if self.strip_images:
            logger.debug("looking for images to strip")
            for element in soup("img"):
                if "src" in element.attrs.keys():
                    logger.debug(f"strip image: {element['src']}")
                element.extract()
        elif self.replacement_img:
            logger.debug("looking for images to replace")
            for element in soup("img"):
                if "src" in element.attrs.keys():
                    logger.debug(f"replacing image: {element['src']}")
                element["src"] = "cid:removed_for_security_reasons"
                image_replaced = True

        # sanitize message text
        sanitized_text = self.sanitize(soup, logger)
        del soup

        # send email notifications
        for recipient in recipients:
            logger.debug(
                f"generating email notification for '{recipient}'")
            logger.debug("parsing message template")

            variables = defaultdict(str, template_vars)
            variables["HTML_TEXT"] = sanitized_text
            variables["ENVELOPE_FROM"] = escape(mailfrom, quote=False)
            variables["ENVELOPE_FROM_URL"] = escape(
                quote(mailfrom), quote=False)
            variables["ENVELOPE_TO"] = escape(recipient, quote=False)
            variables["ENVELOPE_TO_URL"] = escape(quote(recipient))

            newmsg = MIMEMultipart('related')
            if msg["from"] is not None:
                newmsg["From"] = self.from_header.format_map(
                    defaultdict(str, FROM=msg["from"]))
                variables["FROM"] = escape(msg["from"], quote=False)
            else:
                newmsg["From"] = self.from_header.format_map(defaultdict(str))

            if msg["to"] is not None:
                newmsg["To"] = msg["to"]
                variables["TO"] = escape(msg["to"], quote=False)
            else:
                newmsg["To"] = recipient

            if msg["subject"] is not None:
                newmsg["Subject"] = self.subject.format_map(
                    defaultdict(str, SUBJECT=msg["subject"]))
                variables["SUBJECT"] = escape(msg["subject"], quote=False)

            newmsg["Date"] = email.utils.formatdate()

            # parse template
            htmltext = self.template.format_map(variables)
            newmsg.attach(MIMEText(htmltext, "html", 'UTF-8'))

            if image_replaced:
                logger.debug("attaching notification_replacement_img")
                newmsg.attach(self.replacement_img)

            for img in self.embed_imgs:
                logger.debug("attaching imgage")
                newmsg.attach(img)

            logger.debug(f"sending email notification to: {recipient}")
            if synchronous:
                try:
                    mailer.smtp_send(self.smtp_host, self.smtp_port,
                                     self.mailfrom, recipient,
                                     newmsg.as_string())
                except Exception as e:
                    raise RuntimeError(
                        f"error while sending email notification "
                        f"to '{recipient}': {e}")
            else:
                mailer.sendmail(self.smtp_host, self.smtp_port, qid,
                                self.mailfrom, recipient, newmsg.as_string(),
                                "email notification")

    def execute(self, milter, logger):
        super().execute(milter, logger)

        self.notify(msg=milter.msg, qid=milter.qid,
                    mailfrom=milter.msginfo["mailfrom"],
                    recipients=milter.msginfo["rcpts"],
                    template_vars=milter.msginfo["vars"],
                    logger=logger)


class Notify:
    NOTIFICATION_TYPES = {
        "email": EMailNotification}

    def __init__(self, cfg, local_addrs, debug):
        self.cfg = cfg
        self.logger = logging.getLogger(cfg["name"])
        self.logger.setLevel(cfg.get_loglevel(debug))

        nodification_type = cfg["options"]["type"]
        del cfg["options"]["type"]
        cfg["options"]["pretend"] = cfg["pretend"]
        self._notification = self.NOTIFICATION_TYPES[nodification_type](
            **cfg["options"])
        self._headersonly = self._notification._headersonly

    def __str__(self):
        cfg = []
        for key, value in self.cfg["options"].items():
            cfg.append(f"{key}={value}")
        class_name = type(self._notification).__name__
        return f"{class_name}(" + ", ".join(cfg) + ")"

    def get_notification(self):
        return self._notification

    def execute(self, milter):
        logger = CustomLogger(
            self.logger, {"name": self.cfg["name"], "qid": milter.qid})
        self._notification.execute(milter, logger)
