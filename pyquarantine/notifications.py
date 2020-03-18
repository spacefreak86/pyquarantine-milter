# PyQuarantine-Milter is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# PyQuarantine-Milter is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with PyQuarantineMilter.  If not, see <http://www.gnu.org/licenses/>.
#

import email
import logging
import re

from bs4 import BeautifulSoup
from cgi import escape
from collections import defaultdict
from email.policy import default as default_policy
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from os.path import basename
from urllib.parse import quote

from pyquarantine import mailer


class BaseNotification(object):
    "Notification base class"
    notification_type = "base"

    def __init__(self, name, global_cfg, cfg, test=False):
        self.name = name
        self.logger = logging.getLogger(__name__)

    def notify(self, qid, storage_id, mailfrom, recipients, headers,
               fp, subgroups=None, named_subgroups=None, synchronous=False):
        fp.seek(0)
        pass


class EMailNotification(BaseNotification):
    "Notification class to send notifications via mail."
    notification_type = "email"
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

    def __init__(self, name, global_cfg, cfg, test=False):
        super(EMailNotification, self).__init__(
            name, global_cfg, cfg, test)

        defaults = {
            "notification_email_replacement_img": "",
            "notification_email_strip_images": "false",
            "notification_email_parser_lib": "lxml"
        }
        # check config
        for opt in [
            "notification_email_smtp_host",
            "notification_email_smtp_port",
            "notification_email_envelope_from",
            "notification_email_from",
            "notification_email_subject",
            "notification_email_template",
                "notification_email_embedded_imgs"] + list(defaults.keys()):
            if opt in cfg:
                continue
            if opt in global_cfg:
                cfg[opt] = global_cfg[opt]
            elif opt in defaults:
                cfg[opt] = defaults[opt]
            else:
                raise RuntimeError(
                    f"mandatory option '{opt}' not present in config "
                    f"section '{self.name}' or 'global'")

        self.smtp_host = cfg["notification_email_smtp_host"]
        self.smtp_port = cfg["notification_email_smtp_port"]
        self.mailfrom = cfg["notification_email_envelope_from"]
        self.from_header = cfg["notification_email_from"]
        self.subject = cfg["notification_email_subject"]

        testvars = defaultdict(str, test="TEST")

        # test-parse from header
        try:
            self.from_header.format_map(testvars)
        except ValueError as e:
            raise RuntimeError(
                f"error parsing notification_email_from: {e}")

        # test-parse subject
        try:
            self.subject.format_map(testvars)
        except ValueError as e:
            raise RuntimeError(
                f"error parsing notification_email_subject: {e}")

        # read and parse email notification template
        try:
            self.template = open(
                cfg["notification_email_template"], "r").read()
            self.template.format_map(testvars)
        except IOError as e:
            raise RuntimeError(f"error reading template: {e}")
        except ValueError as e:
            raise RuntimeError(f"error parsing template: {e}")

        strip_images = cfg["notification_email_strip_images"].strip().upper()
        if strip_images in ["TRUE", "ON", "YES"]:
            self.strip_images = True
        elif strip_images in ["FALSE", "OFF", "NO"]:
            self.strip_images = False
        else:
            raise RuntimeError(
                "error parsing notification_email_strip_images: unknown value")

        self.parser_lib = cfg["notification_email_parser_lib"].strip()
        if self.parser_lib not in ["lxml", "html.parser"]:
            raise RuntimeError(
                "error parsing notification_email_parser_lib: unknown value")

        # read email replacement image if specified
        replacement_img = cfg["notification_email_replacement_img"].strip()
        if not self.strip_images and replacement_img:
            try:
                self.replacement_img = MIMEImage(
                    open(replacement_img, "rb").read())
            except IOError as e:
                raise RuntimeError(
                    f"error reading replacement image: {e}")
            else:
                self.replacement_img.add_header(
                    "Content-ID", "<removed_for_security_reasons>")
        else:
            self.replacement_img = None

        # read images to embed if specified
        embedded_img_paths = [
            p.strip() for p in cfg["notification_email_embedded_imgs"].split(
                ",") if p]
        self.embedded_imgs = []
        for img_path in embedded_img_paths:
            # read image
            try:
                img = MIMEImage(open(img_path, "rb").read())
            except IOError as e:
                raise RuntimeError(f"error reading image: {e}")
            else:
                filename = basename(img_path)
                img.add_header(f"Content-ID", f"<{filename}>")
                self.embedded_imgs.append(img)

    def get_email_body_soup(self, qid, msg):
        "Extract and decode email body and return it as BeautifulSoup object."
        # try to find the body part
        self.logger.debug(f"{qid}: trying to find email body")
        try:
            body = msg.get_body(preferencelist=("html", "plain"))
        except Exception as e:
            self.logger.error(
                f"{qid}: an error occured in "
                f"email.message.EmailMessage.get_body: {e}")
            body = None

        if body:
            charset = body.get_content_charset() or "utf-8"
            content = body.get_payload(decode=True)
            try:
                content = content.decode(encoding=charset, errors="replace")
            except LookupError:
                self.logger.info(
                    f"{qid}: unknown encoding '{charset}', "
                    f"falling back to UTF-8")
                content = content.decode("utf-8", errors="replace")
            content_type = body.get_content_type()
            if content_type == "text/plain":
                # convert text/plain to text/html
                self.logger.debug(
                    f"{qid}: content type is {content_type}, "
                    f"converting to text/html")
                content = re.sub(r"^(.*)$", r"\1<br/>",
                                 escape(content), flags=re.MULTILINE)
            else:
                self.logger.debug(
                    f"{qid}: content type is {content_type}")
        else:
            self.logger.error(
                f"{qid}: unable to find email body")
            content = "ERROR: unable to find email body"

        # create BeautifulSoup object
        length = len(content)
        self.logger.debug(
            f"{qid}: trying to create BeatufilSoup object with "
            f"parser lib {self.parser_lib}, "
            f"text length is {length} bytes")
        soup = BeautifulSoup(content, self.parser_lib)
        self.logger.debug(
            f"{qid}: sucessfully created BeautifulSoup object")

        return soup

    def sanitize(self, qid, soup):
        "Sanitize mail html text."
        self.logger.debug(f"{qid}: sanitizing email text")

        # completly remove bad elements
        for element in soup(EMailNotification._bad_tags):
            self.logger.debug(
                f"{qid}: removing dangerous tag '{element.name}' "
                f"and its content")
            element.extract()

        # remove not whitelisted elements, but keep their content
        for element in soup.find_all(True):
            if element.name not in EMailNotification._good_tags:
                self.logger.debug(
                    f"{qid}: removing tag '{element.name}', keep its content")
                element.replaceWithChildren()

        # remove not whitelisted attributes
        for element in soup.find_all(True):
            for attribute in list(element.attrs.keys()):
                if attribute not in EMailNotification._good_attributes:
                    if element.name == "a" and attribute == "href":
                        self.logger.debug(
                            f"{qid}: setting attribute href to '#' "
                            f"on tag '{element.name}'")
                        element["href"] = "#"
                    else:
                        self.logger.debug(
                            f"{qid}: removing attribute '{attribute}' "
                            f"from tag '{element.name}'")
                        del(element.attrs[attribute])
        return soup

    def notify(self, qid, storage_id, mailfrom, recipients, headers, fp,
               subgroups=None, named_subgroups=None, synchronous=False):
        "Notify recipients via email."
        super(
            EMailNotification,
            self).notify(
            qid,
            storage_id,
            mailfrom,
            recipients,
            headers,
            fp,
            subgroups,
            named_subgroups,
            synchronous)

        # extract body from email
        soup = self.get_email_body_soup(
            qid, email.message_from_binary_file(fp, policy=default_policy))

        # replace picture sources
        image_replaced = False
        if self.strip_images:
            self.logger.debug(
                f"{qid}: looking for images to strip")
            for element in soup("img"):
                if "src" in element.attrs.keys():
                    self.logger.debug(
                        f"{qid}: strip image: {element['src']}")
                element.extract()
        elif self.replacement_img:
            self.logger.debug(
                f"{qid}: looking for images to replace")
            for element in soup("img"):
                if "src" in element.attrs.keys():
                    self.logger.debug(
                        f"{qid}: replacing image: {element['src']}")
                element["src"] = "cid:removed_for_security_reasons"
                image_replaced = True

        # sanitizing email text of original email
        sanitized_text = self.sanitize(qid, soup)
        del soup

        # sending email notifications
        for recipient in recipients:
            self.logger.debug(
                f"{qid}: generating notification email for '{recipient}'")
            self.logger.debug(f"{qid}: parsing email template")

            # generate dict containing all template variables
            variables = defaultdict(
                    str,
                    EMAIL_HTML_TEXT=sanitized_text,
                    EMAIL_FROM=escape(headers["from"]),
                    EMAIL_ENVELOPE_FROM=escape(mailfrom),
                    EMAIL_ENVELOPE_FROM_URL=escape(quote(mailfrom)),
                    EMAIL_TO=escape(headers["to"]),
                    EMAIL_ENVELOPE_TO=escape(recipient),
                    EMAIL_ENVELOPE_TO_URL=escape(quote(recipient)),
                    EMAIL_SUBJECT=escape(headers["subject"]),
                    EMAIL_QUARANTINE_ID=storage_id)

            if subgroups:
                number = 0
                for subgroup in subgroups:
                    variables[f"SUBGROUP_{number}"] = escape(subgroup)
            if named_subgroups:
                for key, value in named_subgroups.items():
                    named_subgroups[key] = escape(value)
                variables.update(named_subgroups)

            # parse template
            htmltext = self.template.format_map(variables)

            msg = MIMEMultipart('related')
            msg["From"] = self.from_header.format_map(
                defaultdict(str, EMAIL_FROM=headers["from"]))
            msg["To"] = headers["to"]
            msg["Subject"] = self.subject.format_map(
                defaultdict(str, EMAIL_SUBJECT=headers["subject"]))
            msg["Date"] = email.utils.formatdate()
            msg.attach(MIMEText(htmltext, "html", 'UTF-8'))

            if image_replaced:
                self.logger.debug(
                    f"{qid}: attaching notification_replacement_img")
                msg.attach(self.replacement_img)

            for img in self.embedded_imgs:
                self.logger.debug(f"{qid}: attaching imgage")
                msg.attach(img)

            self.logger.debug(
                f"{qid}: sending notification email to: {recipient}")
            if synchronous:
                try:
                    mailer.smtp_send(self.smtp_host, self.smtp_port,
                                     self.mailfrom, recipient, msg.as_string())
                except Exception as e:
                    raise RuntimeError(
                        f"error while sending email to '{recipient}': {e}")
            else:
                mailer.sendmail(self.smtp_host, self.smtp_port, qid,
                                self.mailfrom, recipient, msg.as_string(),
                                "notification email")


# list of notification types and their related notification classes
TYPES = {"email": EMailNotification}
