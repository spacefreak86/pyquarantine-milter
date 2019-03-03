#!/usr/bin/env python2
#
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
import mailer
import re

from bs4 import BeautifulSoup
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage



class BaseNotification(object):
    "Notification base class"
    def __init__(self, quarantine_name, config, configtest=False):
        self.quarantine_name = quarantine_name
        self.config = config[quarantine_name]
        self.global_config = config["global"]
        self.logger = logging.getLogger(__name__)

    def notify(self, queueid, quarantine_id, subject, mailfrom, recipients, fp):
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
            "span",
            "table",
            "td",
            "th",
            "tr",
            "tt",
            "u",
            "ul"
    ]
    good_attributes = [
            "align",
            "alt",
            "bgcolor",
            "border",
            "cellpadding",
            "cellspacing",
            "colspan",
            "dir",
            "headers",
            "height",
            "name",
            "rowspan",
            "size",
            "src",
            "style",
            "title",
            "type",
            "value",
            "width"
    ]

    def __init__(self, quarantine_name, config, configtest=False):
        super(EMailNotification, self).__init__(quarantine_name, config, configtest)
        # check if mandatory options are present in config
        for option in ["smtp_host", "smtp_port", "notification_email_from", "notification_email_subject", "notification_email_template", "notification_email_replacement_img"]:
            if option not in self.config.keys() and option in self.global_config.keys():
                self.config[option] = self.global_config[option]
            if option not in self.config.keys():
                raise RuntimeError("mandatory option '{}' not present in config section '{}' or 'global'".format(option, self.quarantine_name))
        self.smtp_host = self.config["smtp_host"]
        self.smtp_port = self.config["smtp_port"]
        self.mailfrom = self.config["notification_email_from"]
        self.subject = self.config["notification_email_subject"]
        try:
            self.template = open(self.config["notification_email_template"], "rb").read()
        except Exception as e:
            raise RuntimeError("error reading email template: {}".format(e))
        try:
            self.replacement_img = MIMEImage(open(self.config["notification_email_replacement_img"], "rb").read())
        except Exception as e:
            raise RuntimeError("error reading email replacement image: {}".format(e))
        else:
            self.replacement_img.add_header("Content-ID", "<removed_for_security_reasons>")

    def get_text(self, part):
        "Get the mail text in html form from email part."
        mimetype = part.get_content_type()
        text = part.get_payload(decode=True)
        if mimetype == EMailNotification._plain_text:
            text = re.sub(r"^(.*)$", r"\1<br/>\n", text, flags=re.MULTILINE)
        soup = BeautifulSoup(text, "lxml", from_encoding=part.get_content_charset())
        return soup

    def get_text_multipart(self, msg, preferred=_html_text):
        "Get the mail text of a multipart email in html form."
        soup = None
        for part in msg.get_payload():
            mimetype = part.get_content_type()
            if mimetype in [EMailNotification._plain_text, EMailNotification._html_text]:
                soup = self.get_text(part)
            elif mimetype.startswith("multipart"):
                soup = self.get_text_multipart(part, preferred)
            if soup != None and mimetype == preferred:
                break
        return soup

    def sanitize(self, soup):
        "Sanitize mail html text."
        # completly remove bad elements
        for element in soup(EMailNotification._bad_tags):
            element.extract()
        # remove not whitelisted elements, but keep their content
        for element in soup.find_all(True):
            if element.name not in EMailNotification._good_tags:
                element.replaceWithChildren()
        # remove not whitelisted attributes
        for element in soup.find_all(True):
            for attribute in element.attrs.keys():
                if attribute not in EMailNotification.good_attributes:
                    del(element.attrs[attribute])
        # set href attribute for all a-tags to #
        for element in soup("a"):
            element["href"] = "#"
        return soup

    def get_html_text_part(self, msg):
        "Get the mail text of an email in html form."
        soup = None
        mimetype = msg.get_content_type()
        if mimetype in [EMailNotification._plain_text, EMailNotification._html_text]:
            soup = self.get_text(msg)
        elif mimetype.startswith("multipart"):
            soup = self.get_text_multipart(msg)
        if soup == None:
            text = "ERROR: unable to extract text from email body"
            soup = BeautifulSoup(text, "lxml", "UTF-8")
        return soup

    def notify(self, queueid, quarantine_id, subject, mailfrom, recipients, fp):
        "Notify recipients via email."
        super(EMailNotification, self).notify(queueid, quarantine_id, subject, mailfrom, recipients, fp)
        self.logger.debug("{}: generating notification email".format(queueid))
        # extract html text from email
        self.logger.debug("{}: extraction email text from original email".format(queueid))
        soup = self.get_html_text_part(email.message_from_file(fp))
        # replace picture sources
        picture_replaced = False
        for element in soup("img"):
            if "src" in element:
                self.logger.debug("{}: replacing image: {}".format(queueid, element["src"]))
            element["src"] = "cid:removed_for_security_reasons"
            picture_replaced = True
        for recipient in recipients:
            self.logger.debug("{}: sending notification to <{}>".format(queueid, recipient))
            self.logger.debug("{}: parsing email template".format(queueid))
            htmltext = self.template.format( \
                EMAIL_HTML_TEXT=self.sanitize(soup), \
                EMAIL_FROM=mailfrom, \
                EMAIL_TO=recipient, \
                EMAIL_SUBJECT=subject, \
                EMAIL_QUARANTINE_ID=quarantine_id
            )
            msg = MIMEMultipart('alternative')
            msg["Subject"] = self.subject
            msg["From"] = "<{}>".format(self.mailfrom)
            msg["To"] = "<{}>".format(recipient)
            msg["Date"] = email.utils.formatdate()
            msg.attach(MIMEText(htmltext, "html", 'UTF-8'))
            if picture_replaced:
                msg.attach(self.replacement_img)
            mailer.sendmail(self.smtp_host, self.smtp_port, queueid, self.mailfrom, recipient, msg.as_string())



# list of notification types and their related notification classes
notification_types = {"email": EMailNotification}
