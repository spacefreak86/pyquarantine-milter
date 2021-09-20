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
    "BaseNotification",
    "EMailNotification"]

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

from pymodmilter import mailer


class BaseNotification:
    "Notification base class"
    _headersonly = True

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        return

    def execute(self, milter, pretend=False, logger=None):
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
        "script"
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
                 strip_imgs=False, parser_lib="lxml"):
        super().__init__()

        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.mailfrom = envelope_from
        self.from_header = from_header
        self.subject = subject
        try:
            self.template = open(template, "r").read()
            self.embed_imgs = []
            for img_path in embed_imgs:
                img = MIMEImage(open(img_path, "rb").read())
                filename = basename(img_path)
                img.add_header("Content-ID", f"<{filename}>")
                self.embed_imgs.append(img)

            self.replacement_img = repl_img
            self.strip_images = strip_imgs

            if not strip_imgs and repl_img:
                self.replacement_img = MIMEImage(
                    open(repl_img, "rb").read())
                self.replacement_img.add_header(
                    "Content-ID", "<removed_for_security_reasons>")

        except IOError as e:
            raise RuntimeError(e)

        self.parser_lib = parser_lib

    def get_email_body_soup(self, msg, logger=None):
        "Extract and decode email body and return it as BeautifulSoup object."
        if logger is None:
            logger = self.logger

        # try to find the body part
        logger.debug("trying to find email body")
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
            logger.error("unable to find email body")
            content = "ERROR: unable to find email body"

        # create BeautifulSoup object
        length = len(content)
        logger.debug(
            f"trying to create BeatufilSoup object with "
            f"parser lib {self.parser_lib}, "
            f"text length is {length} bytes")
        soup = BeautifulSoup(content, self.parser_lib)
        logger.debug("sucessfully created BeautifulSoup object")

        return soup

    def sanitize(self, soup, logger=None):
        "Sanitize mail html text."
        if logger is None:
            logger = self.logger

        logger.debug("sanitizing email text")

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

    def notify(self, msg, qid, mailfrom, recipients,
               template_vars=defaultdict(str), synchronous=False,
               logger=None):
        "Notify recipients via email."
        if logger is None:
            logger = self.logger

        # extract body from email
        soup = self.get_email_body_soup(msg, logger)

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

        # sanitizing email text of original email
        sanitized_text = self.sanitize(soup, logger)
        del soup

        # sending email notifications
        for recipient in recipients:
            logger.debug(f"generating notification email for '{recipient}'")
            logger.debug("parsing email template")

            # generate dict containing all template variables

            variables = defaultdict(str, template_vars)
            variables.update({
                "HTML_TEXT": sanitized_text,
                "FROM": escape(msg["from"], quote=False),
                "ENVELOPE_FROM": escape(mailfrom, quote=False),
                "ENVELOPE_FROM_URL": escape(quote(mailfrom),
                                            quote=False),
                "TO": escape(msg["to"], quote=False),
                "ENVELOPE_TO": escape(recipient, quote=False),
                "ENVELOPE_TO_URL": escape(quote(recipient)),
                "SUBJECT": escape(msg["subject"], quote=False)})

            # parse template
            htmltext = self.template.format_map(variables)

            newmsg = MIMEMultipart('related')
            newmsg["From"] = self.from_header.format_map(
                defaultdict(str, FROM=msg["from"]))
            newmsg["To"] = msg["to"]
            newmsg["Subject"] = self.subject.format_map(
                defaultdict(str, SUBJECT=msg["subject"]))
            newmsg["Date"] = email.utils.formatdate()
            newmsg.attach(MIMEText(htmltext, "html", 'UTF-8'))

            if image_replaced:
                logger.debug("attaching notification_replacement_img")
                newmsg.attach(self.replacement_img)

            for img in self.embed_imgs:
                logger.debug("attaching imgage")
                newmsg.attach(img)

            logger.debug(f"sending notification email to: {recipient}")
            if synchronous:
                try:
                    mailer.smtp_send(self.smtp_host, self.smtp_port,
                                     self.mailfrom, recipient,
                                     newmsg.as_string())
                except Exception as e:
                    raise RuntimeError(
                        f"error while sending email to '{recipient}': {e}")
            else:
                mailer.sendmail(self.smtp_host, self.smtp_port, qid,
                                self.mailfrom, recipient, newmsg.as_string(),
                                "notification email")

    def execute(self, milter, pretend=False,
                logger=None):
        super().execute(milter, pretend, logger)

        if logger is None:
            logger = self.logger

        self.notify(msg=milter.msg, qid=milter.qid,
                    mailfrom=milter.msginfo["mailfrom"],
                    recipients=milter.msginfo["rcpts"],
                    template_vars=milter.msginfo["vars"],
                    logger=logger)
