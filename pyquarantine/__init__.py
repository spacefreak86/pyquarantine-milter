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

import Milter
import configparser
import logging
import os
import re

from Milter.utils import parse_addr
from collections import defaultdict
from email.charset import Charset
from email.header import Header, decode_header
from io import BytesIO
from itertools import groupby
from netaddr import IPAddress, IPNetwork, AddrFormatError
from pyquarantine import mailer
from pyquarantine import notifications
from pyquarantine import storages
from pyquarantine import whitelists

__all__ = [
    "make_header",
    "Quarantine",
    "QuarantineMilter",
    "setup_milter",
    "reload_config",
    "cli",
    "mailer",
    "notifications",
    "storages",
    "run",
    "version",
    "whitelists"]


def make_header(decoded_seq, maxlinelen=None, header_name=None,
                continuation_ws=' ', errors='strict'):
    """Create a Header from a sequence of pairs as returned by decode_header()

    decode_header() takes a header value string and returns a sequence of
    pairs of the format (decoded_string, charset) where charset is the string
    name of the character set.

    This function takes one of those sequence of pairs and returns a Header
    instance.  Optional maxlinelen, header_name, and continuation_ws are as in
    the Header constructor.
    """
    h = Header(maxlinelen=maxlinelen, header_name=header_name,
               continuation_ws=continuation_ws)
    for s, charset in decoded_seq:
        # None means us-ascii but we can simply pass it on to h.append()
        if charset is not None and not isinstance(charset, Charset):
            charset = Charset(charset)
        h.append(s, charset, errors=errors)
    return h


class Quarantine(object):
    """Quarantine class suitable for QuarantineMilter

    The class holds all the objects and functions needed
    for QuarantineMilter quarantine.

    """

    # list of possible actions
    _actions = {
        "ACCEPT": Milter.ACCEPT,
        "REJECT": Milter.REJECT,
        "DISCARD": Milter.DISCARD}

    def __init__(self, name, index=0, regex=None, storage=None, whitelist=None,
                 host_whitelist=[], notification=None, action="ACCEPT",
                 reject_reason=None):
        self.logger = logging.getLogger(__name__)
        self.name = name
        self.index = index
        self.regex = regex
        if regex:
            self.re = re.compile(
                regex, re.MULTILINE + re.DOTALL + re.IGNORECASE)
        self.storage = storage
        self.whitelist = whitelist
        self.host_whitelist = host_whitelist
        self.notification = notification
        action = action.upper()
        assert action in self._actions
        self.action = action
        self.milter_action = self._actions[action]
        self.reject_reason = reject_reason

    def setup_from_cfg(self, global_cfg, cfg, test=False):
        defaults = {
            "action": "accept",
            "reject_reason": "Message rejected",
            "storage_type": "none",
            "notification_type": "none",
            "whitelist_type": "none",
            "host_whitelist": ""
        }
        # check config
        for opt in ["regex", "smtp_host", "smtp_port"] + list(defaults.keys()):
            if opt in cfg:
                continue
            if opt in global_cfg:
                cfg[opt] = global_cfg[opt]
            elif opt in defaults:
                cfg[opt] = defaults[opt]
            else:
                raise RuntimeError(
                    f"mandatory option '{opt}' not present in "
                    f"config section '{self.name}' or 'global'")

        # pre-compile regex
        self.logger.debug(
            f"{self.name}: compiling regex '{cfg['regex']}'")
        self.re = re.compile(
            cfg["regex"], re.MULTILINE + re.DOTALL + re.IGNORECASE)

        self.smtp_host = cfg["smtp_host"]
        self.smtp_port = cfg["smtp_port"]

        # create storage instance
        storage_type = cfg["storage_type"].lower()
        if storage_type in storages.TYPES:
            self.logger.debug(
                f"{self.name}: initializing storage "
                f"type '{storage_type.upper()}'")
            self.storage = storages.TYPES[storage_type](
                self.name, global_cfg, cfg, test)
        elif storage_type == "none":
            self.logger.debug(f"{self.name}: storage is NONE")
            self.storage = None
        else:
            raise RuntimeError(
                f"{self.name}: unknown storage type '{storage_type}'")

        # create whitelist instance
        whitelist_type = cfg["whitelist_type"].lower()
        if whitelist_type in whitelists.TYPES:
            self.logger.debug(
                f"{self.name}: initializing whitelist "
                f"type '{whitelist_type.upper()}'")
            self.whitelist = whitelists.TYPES[whitelist_type](
               self.name, global_cfg, cfg, test)
        elif whitelist_type == "none":
            self.logger.debug(f"{self.name}: whitelist is NONE")
            self.whitelist = None
        else:
            raise RuntimeError(
                f"{self.name}: unknown whitelist type '{whitelist_type}'")

        # create notification instance
        notification_type = cfg["notification_type"].lower()
        if notification_type in notifications.TYPES:
            self.logger.debug(
                f"{self.name}: initializing notification "
                f"type '{notification_type.upper()}'")
            self.notification = notifications.TYPES[notification_type](
                self.name, global_cfg, cfg, test)
        elif notification_type == "none":
            self.logger.debug(f"{self.name}: notification is NONE")
            self.notification = None
        else:
            raise RuntimeError(
                f"{self.name}: unknown notification "
                f"type '{notification_type}'")

        # determining milter action for this quarantine
        action = cfg["action"].upper()
        if action in self._actions:
            self.logger.debug(f"{self.name}: action is {action}")
            self.action = action
            self.milter_action = self._actions[action]
        else:
            raise RuntimeError(
                f"{self.name}: unknown action '{action}'")

        self.reject_reason = cfg["reject_reason"]

        # create host/network whitelist
        self.host_whitelist = []
        host_whitelist = set([p.strip()
                             for p in cfg["host_whitelist"].split(",") if p])
        for host in host_whitelist:
            if not host:
                continue
            # parse network notation
            try:
                net = IPNetwork(host)
            except AddrFormatError as e:
                raise RuntimeError(
                    f"{self.name}: error parsing host_whitelist: {e}")
            else:
                self.host_whitelist.append(net)
        if self.host_whitelist:
            whitelist = ", ".join([str(ip) for ip in host_whitelist])
            self.logger.debug(
                f"{self.name}: host whitelist: {whitelist}")

    def notify(self, storage_id, recipient=None, synchronous=True):
        "Notify recipient about email in storage."
        if not self.storage:
            raise RuntimeError(
                "storage type is set to None, unable to send notification")

        if not self.notification:
            raise RuntimeError(
                "notification type is set to None, "
                "unable to send notification")

        fp, metadata = self.storage.get_mail(storage_id)

        if recipient is not None:
            if recipient not in metadata["recipients"]:
                raise RuntimeError(f"invalid recipient '{recipient}'")
            recipients = [recipient]
        else:
            recipients = metadata["recipients"]

        self.notification.notify(
            metadata["queue_id"], storage_id, metadata["mailfrom"],
            recipients, metadata["headers"], fp,
            metadata["subgroups"], metadata["named_subgroups"],
            synchronous)
        fp.close()

    def release(self, storage_id, recipients=None):
        "Release email from storage."
        if not self.storage:
            raise RuntimeError(
                "storage type is set to None, unable to release email")

        fp, metadata = self.storage.get_mail(storage_id)
        try:
            mail = fp.read()
            fp.close()
        except IOError as e:
            raise RuntimeError(f"unable to read data file: {e}")

        if recipients and type(recipients) == str:
            recipients = [recipients]
        else:
            recipients = metadata["recipients"]

        for recipient in recipients:
            if recipient not in metadata["recipients"]:
                raise RuntimeError(f"invalid recipient '{recipient}'")

            try:
                mailer.smtp_send(
                    self.smtp_host,
                    self.smtp_port,
                    metadata["mailfrom"],
                    recipient,
                    mail)
            except Exception as e:
                raise RuntimeError(
                    f"error while sending email to '{recipient}': {e}")
            self.storage.delete(storage_id, recipient)

    def get_storage(self):
        return self.storage

    def get_notification(self):
        return self.notification

    def get_whitelist(self):
        return self.whitelist

    def host_in_whitelist(self, hostaddr):
        ip = IPAddress(hostaddr[0])
        for entry in self.host_whitelist:
            if ip in entry:
                return True
        return False

    def match(self, header):
        return self.re.search(header)


class QuarantineMilter(Milter.Base):
    """QuarantineMilter based on Milter.Base to implement milter communication

    The class variable quarantines needs to be filled by
    runng the setup_milter function.

    """
    quarantines = []
    preferred_action = "first"

    # list of default config files
    _cfg_files = [
        "/etc/pyquarantine/pyquarantine.conf",
        os.path.expanduser('~/pyquarantine.conf'),
        "pyquarantine.conf"]

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # save runtime config, it must not change during runtime
        self.quarantines = QuarantineMilter.quarantines

    def _get_preferred_quarantine(self):
        matching_quarantines = [
            q for q in self.rcpts_quarantines.values() if q]
        if self.preferred_action == "first":
            quarantine = sorted(
                matching_quarantines,
                key=lambda q: q.index)[0]
        else:
            quarantine = sorted(
                matching_quarantines,
                key=lambda q: q.index,
                reverse=True)[0]
        return quarantine

    @staticmethod
    def get_cfg_files():
        return QuarantineMilter._cfg_files

    @staticmethod
    def set_cfg_files(cfg_files):
        QuarantineMilter._cfg_files = cfg_files

    def connect(self, hostname, family, hostaddr):
        self.hostaddr = hostaddr
        self.logger.debug(
            f"accepted milter connection from {hostaddr[0]} "
            f"port {hostaddr[1]}")
        for quarantine in self.quarantines.copy():
            if quarantine.host_in_whitelist(hostaddr):
                self.logger.debug(
                    f"host {hostaddr[0]} is in whitelist of "
                    f"quarantine {quarantine['name']}")
                self.quarantines.remove(quarantine)
                if not self.quarantines:
                    self.logger.debug(
                        f"host {hostaddr[0]} is in whitelist of all "
                        f"quarantines, skip further processing")
                    return Milter.ACCEPT
        return Milter.CONTINUE

    @Milter.noreply
    def envfrom(self, mailfrom, *str):
        self.mailfrom = "@".join(parse_addr(mailfrom)).lower()
        self.recipients = set()
        return Milter.CONTINUE

    @Milter.noreply
    def envrcpt(self, to, *str):
        self.recipients.add("@".join(parse_addr(to)).lower())
        return Milter.CONTINUE

    @Milter.noreply
    def data(self):
        self.qid = self.getsymval('i')
        self.logger.debug(
            f"{self.qid}: received queue-id from MTA")
        self.recipients = list(self.recipients)
        self.logger.debug(
            f"{self.qid}: initializing memory buffer to save email data")
        # initialize memory buffer to save email data
        self.fp = BytesIO()
        self.headers = []
        return Milter.CONTINUE

    def header(self, name, value):
        try:
            # remove surrogates from value
            value = value.encode(
                errors="surrogateescape").decode(errors="replace")
            self.logger.debug(f"{self.qid}: received header: {name}: {value}")
            # write email header to memory buffer
            self.fp.write(f"{name}: {value}\r\n".encode(
                encoding="ascii", errors="replace"))
            header = make_header(decode_header(value), errors="replace")
            value = str(header).replace("\x00", "")
            self.logger.debug(
                f"{self.qid}: decoded header: {name}: {value}")
            self.headers.append((name, value))
            return Milter.CONTINUE
        except Exception as e:
            self.logger.exception(
                f"an exception occured in header function: {e}")
            return Milter.TEMPFAIL

    def eoh(self):
        try:
            self.fp.write("\r\n".encode(encoding="ascii"))
            self.wl_cache = whitelists.WhitelistCache()

            # initialize dicts to set quaranines per recipient and keep matches
            self.rcpts_quarantines = {}
            self.matches = {}

            # iterate email headers
            rcpts_to_check = self.recipients.copy()
            for name, value in self.headers:
                header = f"{name}: {value}"
                self.logger.debug(
                    f"{self.qid}: checking header against configured "
                    f"quarantines: {header}")
                # iterate quarantines
                for quarantine in self.quarantines:
                    if len(self.rcpts_quarantines) == len(
                            self.recipients):
                        # every recipient matched a quarantine already
                        if quarantine.index >= max(
                                [q.index for q in
                                    self.rcpts_quarantines.values()]):
                            # all recipients matched a quarantine with at least
                            # the same precedence already, skip checks against
                            # quarantines with lower precedence
                            self.logger.debug(
                                f"{self.qid}: {quarantine.name}: skip further "
                                f"checks of this header")
                            break

                    # check email header against quarantine regex
                    self.logger.debug(
                        f"{self.qid}: {quarantine.name}: checking header "
                        f"against regex '{str(quarantine.regex)}'")
                    match = quarantine.match(header)
                    if match:
                        self.logger.debug(
                            f"{self.qid}: {quarantine.name}: "
                            f"header matched regex")
                        # check for whitelisted recipients
                        whitelist = quarantine.get_whitelist()
                        if whitelist:
                            try:
                                wl_recipients = self.wl_cache.get_recipients(
                                        whitelist,
                                        self.mailfrom,
                                        rcpts_to_check)
                            except RuntimeError as e:
                                self.logger.error(
                                    f"{self.qid}: {quarantine.name}: unable "
                                    f"to query whitelist: {e}")
                                return Milter.TEMPFAIL
                        else:
                            wl_recipients = {}

                        # iterate recipients
                        for rcpt in rcpts_to_check.copy():
                            if rcpt in wl_recipients:
                                # recipient is whitelisted in this quarantine
                                self.logger.debug(
                                    f"{self.qid}: {quarantine.name}: "
                                    f"recipient '{rcpt}' is whitelisted")
                                continue

                            if rcpt not in self.rcpts_quarantines or \
                                    self.rcpts_quarantines[rcpt].index > \
                                    quarantine.index:
                                self.logger.debug(
                                    f"{self.qid}: {quarantine.name}: set "
                                    f"quarantine for recipient '{rcpt}'")
                                # save match for later use as template
                                # variables
                                self.matches[quarantine.name] = match
                                self.rcpts_quarantines[rcpt] = quarantine
                                if quarantine.index == 0:
                                    # we do not need to check recipients which
                                    # matched the quarantine with the highest
                                    # precedence already
                                    rcpts_to_check.remove(rcpt)
                            else:
                                self.logger.debug(
                                    f"{self.qid}: {quarantine.name}: a "
                                    f"quarantine with same or higher "
                                    f"precedence matched already for "
                                    f"recipient '{rcpt}'")

                if not rcpts_to_check:
                    self.logger.debug(
                        f"{self.qid}: all recipients matched the first "
                        f"quarantine, skipping all remaining header checks")
                    break

            # check if no quarantine has matched for all recipients
            if not self.rcpts_quarantines:
                # accept email
                self.logger.info(
                    f"{self.qid}: passed clean for all recipients")
                return Milter.ACCEPT

            # check if the mail body is needed
            for recipient, quarantine in self.rcpts_quarantines.items():
                if quarantine.get_storage() or quarantine.get_notification():
                    # mail body is needed, continue processing
                    return Milter.CONTINUE

            # quarantine and notification are disabled on all matching
            # quarantines, just return configured action
            quarantine = self._get_preferred_quarantine()
            self.logger.info(
                f"{self.qid}: {self.preferred_action} "
                f"matching quarantine is '{quarantine.name}', performing "
                f"milter action {quarantine.action}")
            if quarantine.action == "REJECT":
                self.setreply("554", "5.7.0", quarantine.reject_reason)
            return quarantine.milter_action

        except Exception as e:
            self.logger.exception(
                f"an exception occured in eoh function: {e}")
            return Milter.TEMPFAIL

    def body(self, chunk):
        try:
            # save received body chunk
            self.fp.write(chunk)
        except Exception as e:
            self.logger.exception(
                f"an exception occured in body function: {e}")
            return Milter.TEMPFAIL
        return Milter.CONTINUE

    def eom(self):
        try:
            # processing recipients grouped by quarantines
            quarantines = []
            for quarantine, recipients in groupby(
                    sorted(self.rcpts_quarantines,
                           key=lambda x: self.rcpts_quarantines[x].index),
                    lambda x: self.rcpts_quarantines[x]):
                quarantines.append((quarantine, list(recipients)))

            # iterate quarantines sorted by index
            for quarantine, recipients in sorted(
                    quarantines, key=lambda x: x[0].index):
                headers = defaultdict(str)
                for name, value in self.headers:
                    headers[name.lower()] = value
                subgroups = self.matches[quarantine.name].groups(
                    default="")
                named_subgroups = self.matches[quarantine.name].groupdict(
                    default="")

                rcpts = ", ".join(recipients)

                # check if a storage is configured
                storage_id = ""
                storage = quarantine.get_storage()
                if storage:
                    # add email to quarantine
                    self.logger.info(
                        f"{self.qid}: adding to quarantine "
                        f"'{quarantine.name}' for: {rcpts}")
                    try:
                        storage_id = storage.add(
                            self.qid, self.mailfrom, recipients, headers,
                            self.fp, subgroups, named_subgroups)
                    except RuntimeError as e:
                        self.logger.error(
                            f"{self.qid}: unable to add to quarantine "
                            f"'{quarantine.name}': {e}")
                        return Milter.TEMPFAIL

                # check if a notification is configured
                notification = quarantine.get_notification()
                if notification:
                    # notify
                    self.logger.info(
                        f"{self.qid}: sending notification to: {rcpts}")
                    try:
                        notification.notify(
                            self.qid, storage_id,
                            self.mailfrom, recipients, headers, self.fp,
                            subgroups, named_subgroups)
                    except RuntimeError as e:
                        self.logger.error(
                            f"{self.qid}: unable to send notification: {e}")
                        return Milter.TEMPFAIL

                # remove processed recipient
                for recipient in recipients:
                    self.delrcpt(recipient)
                    self.recipients.remove(recipient)

            self.fp.close()

            # email passed clean for at least one recipient, accepting email
            if self.recipients:
                rcpts = ", ".join(recipients)
                self.logger.info(
                    f"{self.qid}: passed clean for: {rcpts}")
                return Milter.ACCEPT

            # return configured action
            quarantine = self._get_preferred_quarantine()
            self.logger.info(
                f"{self.qid}: {self.preferred_action} matching "
                f"quarantine is '{quarantine.name}', performing milter "
                f"action {quarantine.action}")
            if quarantine.action == "REJECT":
                self.setreply("554", "5.7.0", quarantine.reject_reason)
            return quarantine.milter_action

        except Exception as e:
            self.logger.exception(
                f"an exception occured in eom function: {e}")
            return Milter.TEMPFAIL

    def close(self):
        self.logger.debug(
            f"disconnect from {self.hostaddr[0]} port {self.hostaddr[1]}")
        return Milter.CONTINUE


def setup_milter(test=False, cfg_files=[]):
    "Generate the configuration for QuarantineMilter class."
    logger = logging.getLogger(__name__)

    # read config file
    parser = configparser.ConfigParser()
    if not cfg_files:
        cfg_files = parser.read(QuarantineMilter.get_cfg_files())
    else:
        cfg_files = parser.read(cfg_files)
    if not cfg_files:
        raise RuntimeError("config file not found")

    QuarantineMilter.set_cfg_files(cfg_files)
    os.chdir(os.path.dirname(cfg_files[0]))

    # check if mandatory config options in global section are present
    if "global" not in parser.sections():
        raise RuntimeError(
            "mandatory section 'global' not present in config file")
    for option in ["quarantines", "preferred_quarantine_action"]:
        if not parser.has_option("global", option):
            raise RuntimeError(
                f"mandatory option '{option}' not present in config "
                f"section 'global'")

    # read global config section
    global_cfg = dict(parser.items("global"))
    preferred_action = global_cfg["preferred_quarantine_action"].lower()
    if preferred_action not in ["first", "last"]:
        raise RuntimeError(
            "option preferred_quarantine_action has illegal value")

    # read active quarantine names
    quarantines = [
        q.strip() for q in global_cfg["quarantines"].split(",")]
    if len(quarantines) != len(set(quarantines)):
        raise RuntimeError(
            "at least one quarantine is specified multiple times "
            "in quarantines option")
    if "global" in quarantines:
        quarantines.remove("global")
        logger.warning(
            "removed illegal quarantine name 'global' from list of "
            "active quarantines")
    if not quarantines:
        raise RuntimeError("no quarantines configured")

    milter_quarantines = []
    logger.debug("preparing milter configuration ...")
    # iterate quarantine names
    for index, name in enumerate(quarantines):
        # check if config section for current quarantine exists
        if name not in parser.sections():
            raise RuntimeError(
                f"config section '{name}' does not exist")

        cfg = dict(parser.items(name))
        quarantine = Quarantine(name, index)
        quarantine.setup_from_cfg(global_cfg, cfg, test)
        milter_quarantines.append(quarantine)

    QuarantineMilter.preferred_action = preferred_action
    QuarantineMilter.quarantines = milter_quarantines


def reload_config():
    "Reload the configuration of QuarantineMilter class."
    logger = logging.getLogger(__name__)

    try:
        setup_milter()
    except RuntimeError as e:
        logger.info(e)
        logger.info("daemon is still running with previous configuration")
    else:
        logger.info("reloaded configuration")
