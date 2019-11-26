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
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from os.path import basename

from pyquarantine import mailer


class BaseNotification(object):
    "Notification base class"

    def __init__(self, global_config, config, configtest=False):
        self.quarantine_name = config["name"]
        self.global_config = global_config
        self.config = config
        self.logger = logging.getLogger(__name__)

    def notify(self, queueid, quarantine_id, mailfrom, recipients, headers,
               fp, subgroups=None, named_subgroups=None, synchronous=False):
        fp.seek(0)
        pass


class EMailNotification(BaseNotification):
    "Notification class to send notifications via mail."
    _html_text = "text/html"
    _plain_text = "text/plain"
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

    def __init__(self, global_config, config, configtest=False):
        super(EMailNotification, self).__init__(
            global_config, config, configtest)

        # check if mandatory options are present in config
        for option in [
            "notification_email_smtp_host",
            "notification_email_smtp_port",
            "notification_email_envelope_from",
            "notification_email_from",
            "notification_email_subject",
            "notification_email_template",
                "notification_email_embedded_imgs"]:
            if option not in self.config.keys() and option in self.global_config.keys():
                self.config[option] = self.global_config[option]
            if option not in self.config.keys():
                raise RuntimeError(
                    "mandatory option '{}' not present in config section '{}' or 'global'".format(
                        option, self.quarantine_name))

        # check if optional config options are present in config
        defaults = {
            "notification_email_replacement_img": "",
            "notification_email_strip_images": "false",
            "notification_email_parser_lib": "lxml"
        }
        for option in defaults.keys():
            if option not in config.keys() and \
                    option in global_config.keys():
                config[option] = global_config[option]
            if option not in config.keys():
                config[option] = defaults[option]

        self.smtp_host = self.config["notification_email_smtp_host"]
        self.smtp_port = self.config["notification_email_smtp_port"]
        self.mailfrom = self.config["notification_email_envelope_from"]
        self.from_header = self.config["notification_email_from"]
        self.subject = self.config["notification_email_subject"]

        testvars = defaultdict(str, test="TEST")

        # test-parse from header
        try:
            self.from_header.format_map(testvars)
        except ValueError as e:
            raise RuntimeError(
                "error parsing notification_email_from: {}".format(e))

        # test-parse subject
        try:
            self.subject.format_map(testvars)
        except ValueError as e:
            raise RuntimeError(
                "error parsing notification_email_subject: {}".format(e))

        # read and parse email notification template
        try:
            self.template = open(
                self.config["notification_email_template"], "r").read()
            self.template.format_map(testvars)
        except IOError as e:
            raise RuntimeError("error reading template: {}".format(e))
        except ValueError as e:
            raise RuntimeError("error parsing template: {}".format(e))

        strip_images = self.config["notification_email_strip_images"].strip().upper()
        if strip_images in ["TRUE", "ON", "YES"]:
            self.strip_images = True
        elif strip_images in ["FALSE", "OFF", "NO"]:
            self.strip_images = False
        else:
            raise RuntimeError("error parsing notification_email_strip_images: unknown value")

        self.parser_lib = self.config["notification_email_parser_lib"].strip()
        if self.parser_lib not in ["lxml", "html.parser"]:
            raise RuntimeError("error parsing notification_email_parser_lib: unknown value")

        # read email replacement image if specified
        replacement_img = self.config["notification_email_replacement_img"].strip()
        if not self.strip_images and replacement_img:
            try:
                self.replacement_img = MIMEImage(
                    open(replacement_img, "rb").read())
            except IOError as e:
                raise RuntimeError(
                    "error reading replacement image: {}".format(e))
            else:
                self.replacement_img.add_header(
                    "Content-ID", "<removed_for_security_reasons>")
        else:
            self.replacement_img = None

        # read images to embed if specified
        embedded_img_paths = [
            p.strip() for p in self.config["notification_email_embedded_imgs"].split(",") if p]
        self.embedded_imgs = []
        for img_path in embedded_img_paths:
            # read image
            try:
                img = MIMEImage(open(img_path, "rb").read())
            except IOError as e:
                raise RuntimeError("error reading image: {}".format(e))
            else:
                img.add_header("Content-ID", "<{}>".format(basename(img_path)))
                self.embedded_imgs.append(img)

    def get_decoded_email_body(self, queueid, msg, preferred=_html_text):
        "Find and decode email body."
        # try to find the body part
        self.logger.debug("{}: trying to find email body".format(queueid))
        body = None
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in [EMailNotification._plain_text,
                                EMailNotification._html_text]:
                body = part
                if content_type == preferred:
                    break

        if body is not None:
            # get the character set, fallback to utf-8 if not defined in header
            charset = body.get_content_charset()
            if charset is None:
                charset = "utf-8"

            # decode content
            content = body.get_payload(decode=True).decode(
                encoding=charset, errors="replace")

            content_type = body.get_content_type()
            if content_type == EMailNotification._plain_text:
                # convert text/plain to text/html
                self.logger.debug(
                    "{}: content type is {}, converting to {}".format(
                        queueid, content_type, EMailNotification._html_text))
                content = re.sub(r"^(.*)$", r"\1<br/>",
                                 escape(content), flags=re.MULTILINE)
            else:
                self.logger.debug(
                    "{}: content type is {}".format(
                        queueid, content_type))
        else:
            self.logger.error(
                "{}: unable to find email body".format(queueid))
            content = "ERROR: unable to find email body"

        return content

    def sanitize(self, queueid, soup):
        "Sanitize mail html text."
        self.logger.debug("{}: sanitizing email text".format(queueid))

        # completly remove bad elements
        for element in soup(EMailNotification._bad_tags):
            self.logger.debug(
                "{}: removing dangerous tag '{}' and its content".format(
                    queueid, element.name))
            element.extract()

        # remove not whitelisted elements, but keep their content
        for element in soup.find_all(True):
            if element.name not in EMailNotification._good_tags:
                self.logger.debug(
                    "{}: removing tag '{}', keep its content".format(
                        queueid, element.name))
                element.replaceWithChildren()

        # remove not whitelisted attributes
        for element in soup.find_all(True):
            for attribute in list(element.attrs.keys()):
                if attribute not in EMailNotification._good_attributes:
                    if element.name == "a" and attribute == "href":
                        self.logger.debug(
                            "{}: setting attribute href to '#' on tag '{}'".format(
                                queueid, element.name))
                        element["href"] = "#"
                    else:
                        self.logger.debug(
                            "{}: removing attribute '{}' from tag '{}'".format(
                                queueid, attribute, element.name))
                        del(element.attrs[attribute])
        return soup

    def notify(self, queueid, quarantine_id, mailfrom, recipients, headers, fp,
               subgroups=None, named_subgroups=None, synchronous=False):
        "Notify recipients via email."
        super(
            EMailNotification,
            self).notify(
            queueid,
            quarantine_id,
            mailfrom,
            recipients,
            headers,
            fp,
            subgroups,
            named_subgroups,
            synchronous)

        # extract body from email
        content = self.get_decoded_email_body(
            queueid, email.message_from_binary_file(fp))

        # create BeautifulSoup object
        self.logger.debug(
            "{}: trying to create BeatufilSoup object with parser lib {}, "
            "text length is {} bytes".format(
                queueid, self.parser_lib, len(content)))
        soup = BeautifulSoup(content, self.parser_lib)
        self.logger.debug(
            "{}: sucessfully created BeautifulSoup object".format(queueid))

        # replace picture sources
        image_replaced = False
        if self.strip_images:
            self.logger.debug(
                "{}: looking for images to strip".format(queueid))
            for element in soup("img"):
                if "src" in element.attrs.keys():
                    self.logger.debug(
                        "{}: strip image: {}".format(
                            queueid, element["src"]))
                element.extract()
        elif self.replacement_img:
            self.logger.debug(
                "{}: looking for images to replace".format(queueid))
            for element in soup("img"):
                if "src" in element.attrs.keys():
                    self.logger.debug(
                        "{}: replacing image: {}".format(
                            queueid, element["src"]))
                element["src"] = "cid:removed_for_security_reasons"
                image_replaced = True

        # sanitizing email text of original email
        sanitized_text = self.sanitize(queueid, soup)
        del soup

        # sending email notifications
        for recipient in recipients:
            self.logger.debug(
                "{}: generating notification email for '{}'".format(
                    queueid, recipient))
            self.logger.debug("{}: parsing email template".format(queueid))

            # generate dict containing all template variables
            variables = defaultdict(str,
                                    EMAIL_HTML_TEXT=sanitized_text,
                                    EMAIL_FROM=escape(headers["from"]),
                                    EMAIL_ENVELOPE_FROM=escape(mailfrom),
                                    EMAIL_TO=escape(recipient),
                                    EMAIL_SUBJECT=escape(headers["subject"]),
                                    EMAIL_QUARANTINE_ID=quarantine_id)

            if subgroups:
                number = 0
                for subgroup in subgroups:
                    variables["SUBGROUP_{}".format(number)] = escape(subgroup)
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
                    "{}: attaching notification_replacement_img".format(queueid))
                msg.attach(self.replacement_img)

            for img in self.embedded_imgs:
                self.logger.debug("{}: attaching imgage".format(queueid))
                msg.attach(img)

            self.logger.debug(
                "{}: sending notification email to: {}".format(
                    queueid, recipient))
            if synchronous:
                try:
                    mailer.smtp_send(self.smtp_host, self.smtp_port,
                                     self.mailfrom, recipient, msg.as_string())
                except Exception as e:
                    raise RuntimeError(
                        "error while sending email to '{}': {}".format(
                            recipient, e))
            else:
                mailer.sendmail(self.smtp_host, self.smtp_port, queueid,
                                self.mailfrom, recipient, msg.as_string(),
                                "notification email")


# list of notification types and their related notification classes
TYPES = {"email": EMailNotification}
