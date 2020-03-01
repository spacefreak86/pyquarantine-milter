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

import logging
import smtplib

from multiprocessing import Process, Queue


logger = logging.getLogger(__name__)
queue = Queue(maxsize=50)
process = None


def smtp_send(smtp_host, smtp_port, mailfrom, recipient, mail):
    s = smtplib.SMTP(host=smtp_host, port=smtp_port)
    s.ehlo()
    if s.has_extn("STARTTLS"):
        s.starttls()
        s.ehlo()
    s.sendmail(mailfrom, [recipient], mail)
    s.quit()


def mailprocess():
    "Mailer process to send emails asynchronously."
    global logger
    global queue

    try:
        while True:
            m = queue.get()
            if not m:
                break

            smtp_host, smtp_port, qid, mailfrom, recipient, mail, emailtype = m
            try:
                smtp_send(smtp_host, smtp_port, mailfrom, recipient, mail)
            except Exception as e:
                logger.error(
                    f"{qid}: error while sending {emailtype} "
                    f"to '{recipient}': {e}")
            else:
                logger.info(
                    f"{qid}: successfully sent {emailtype} to: {recipient}")
    except KeyboardInterrupt:
        pass
    logger.debug("mailer process terminated")


def sendmail(smtp_host, smtp_port, qid, mailfrom, recipients, mail,
             emailtype="email"):
    "Send an email."
    global logger
    global process
    global queue

    if isinstance(recipients, str):
        recipients = [recipients]

    # start mailprocess if it is not started yet
    if process is None:
        process = Process(target=mailprocess)
        process.daemon = True
        logger.debug("starting mailer process")
        process.start()

    for recipient in recipients:
        try:
            queue.put(
                (smtp_host, smtp_port, qid, mailfrom, recipient, mail,
                 emailtype),
                timeout=30)
        except Queue.Full:
            raise RuntimeError("email queue is full")
