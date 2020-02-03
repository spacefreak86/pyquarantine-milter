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

__all__ = [
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

name = "pyquarantine"

import Milter
import configparser
import logging
import os
import re
import sys

from Milter.utils import parse_addr
from collections import defaultdict
from io import BytesIO
from itertools import groupby
from netaddr import IPAddress, IPNetwork
from pyquarantine import mailer
from pyquarantine import notifications
from pyquarantine import storages
from pyquarantine import whitelists


class Quarantine(object):
    """Quarantine class suitable for QuarantineMilter

    The class holds all the objects and functions needed for QuarantineMilter quarantine.

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
        if regex:
            self.regex = re.compile(
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
                    "mandatory option '{}' not present in config section '{}' or 'global'".format(
                        opt, self.name))

        # pre-compile regex
        self.logger.debug(
            "{}: compiling regex '{}'".format(
                self.name, cfg["regex"]))
        self.regex = re.compile(
            cfg["regex"], re.MULTILINE + re.DOTALL + re.IGNORECASE)

        self.smtp_host = cfg["smtp_host"]
        self.smtp_port = cfg["smtp_port"]

        # create storage instance
        storage_type = cfg["storage_type"].lower()
        if storage_type in storages.TYPES:
            self.logger.debug(
                "{}: initializing storage type '{}'".format(
                    self.name,
                    storage_type.upper()))
            self.storage = storages.TYPES[storage_type](
                self.name, global_cfg, cfg, test)
        elif storage_type == "none":
            self.logger.debug("{}: storage is NONE".format(self.name))
            self.storage = None
        else:
            raise RuntimeError(
                "{}: unknown storage type '{}'".format(
                    self.name, storage_type))

        # create whitelist instance
        whitelist_type = cfg["whitelist_type"].lower()
        if whitelist_type in whitelists.TYPES:
            self.logger.debug(
                "{}: initializing whitelist type '{}'".format(
                    self.name,
                    whitelist_type.upper()))
            self.whitelist = whitelists.TYPES[whitelist_type](
               self.name, global_cfg, cfg, test)
        elif whitelist_type == "none":
            logger.debug("{}: whitelist is NONE".format(self.name))
            self.whitelist = None
        else:
            raise RuntimeError(
                "{}: unknown whitelist type '{}'".format(
                    self.name, whitelist_type))

        # create notification instance
        notification_type = cfg["notification_type"].lower()
        if notification_type in notifications.TYPES:
            self.logger.debug(
                "{}: initializing notification type '{}'".format(
                    self.name,
                    notification_type.upper()))
            self.notification = notifications.TYPES[notification_type](
                self.name, global_cfg, cfg, test)
        elif notification_type == "none":
            self.logger.debug("{}: notification is NONE".format(self.name))
            self.notification = None
        else:
            raise RuntimeError(
                "{}: unknown notification type '{}'".format(
                    self.name, notification_type))

        # determining milter action for this quarantine
        action = cfg["action"].upper()
        if action in self._actions:
            self.logger.debug("{}: action is {}".format(self.name, action))
            self.action = action
            self.milter_action = self._actions[action]
        else:
            raise RuntimeError(
                "{}: unknown action '{}'".format(self._name, action))

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
                raise RuntimeError("{}: error parsing host_whitelist: {}".format(
                    self.name, e))
            else:
                self.host_whitelist.append(net)
        if self.host_whitelist:
            self.logger.debug(
                "{}: host whitelist: {}".format(
                    self.name,
                    ", ".join([str(ip) for ip in host_whitelist])))

    def notify(self, storage_id, recipient=None, synchronous=True):
        "Notify recipient about email in storage."
        if not self.storage:
            raise RuntimeError(
                "storage type is set to None, unable to send notification")

        if not self.notification:
            raise RuntimeError(
                "notification type is set to None, unable to send notification")

        fp, metadata = self.storage.get_mail(storage_id)

        if recipient is not None:
            if recipient not in metadata["recipients"]:
                raise RuntimeError("invalid recipient '{}'".format(recipient))
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
            raise RuntimeError("unable to read data file: {}".format(e))

        if recipients and type(recipients) == str:
            recipients = [recipients]
        else:
            recipients = metadata["recipients"]

        for recipient in recipients:
            if recipient not in metadata["recipients"]:
                raise RuntimeError("invalid recipient '{}'".format(recipient))

            try:
                mailer.smtp_send(
                    self.smtp_host,
                    self.smtp_port,
                    metadata["mailfrom"],
                    recipient,
                    mail)
            except Exception as e:
                raise RuntimeError(
                    "error while sending email to '{}': {}".format(
                        recipient, e))
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
                return true
        return False

    def match(self, header):
        return self.regex.search(header)


class QuarantineMilter(Milter.Base):
    """QuarantineMilter based on Milter.Base to implement milter communication

    The class variable quarantines needs to be filled by runng the setup_milter function.

    """
    quarantines = []
    preferred_quarantine_action = "first"

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
            q for q in self.recipients_quarantines.values() if q]
        if self.preferred_quarantine_action == "first":
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
            "accepted milter connection from {} port {}".format(
                *hostaddr))
        for quarantine in self.quarantines.copy():
            if quarantine.host_in_whitelist(hostaddr):
                self.logger.debug(
                    "host {} is in whitelist of quarantine {}".format(
                        hostaddr[0], quarantine["name"]))
                self.quarantines.remove(quarantine)
                if not self.quarantines:
                    self.logger.debug(
                        "host {} is in whitelist of all quarantines, "
                        "skip further processing",
                        hostaddr[0])
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
        self.queueid = self.getsymval('i')
        self.logger.debug(
            "{}: received queue-id from MTA".format(self.queueid))
        self.recipients = list(self.recipients)
        self.headers = []
        self.logger.debug(
            "{}: initializing memory buffer to save email data".format(
                self.queueid))
        # initialize memory buffer to save email data
        self.fp = BytesIO()
        return Milter.CONTINUE

    @Milter.noreply
    def header(self, name, value):
        try:
            # write email header to memory buffer
            self.fp.write("{}: {}\r\n".format(name, value).encode(
                encoding="ascii", errors="surrogateescape"))
            # keep copy of header without surrogates for later use
            self.headers.append((
                name.encode(errors="surrogateescape").decode(errors="replace"),
                value.encode(errors="surrogateescape").decode(errors="replace")))
        except Exception as e:
            self.logger.exception(
                "an exception occured in header function: {}".format(e))
            return Milter.TEMPFAIL

        return Milter.CONTINUE

    def eoh(self):
        try:
            self.fp.write("\r\n".encode(encoding="ascii"))
            self.whitelist_cache = whitelists.WhitelistCache()

            # initialize dicts to set quaranines per recipient and keep matches
            self.recipients_quarantines = {}
            self.quarantines_matches = {}

            # iterate email headers
            recipients_to_check = self.recipients.copy()
            for name, value in self.headers:
                header = "{}: {}".format(name, value)
                self.logger.debug(
                    "{}: checking header against configured quarantines: {}".format(
                        self.queueid, header))
                # iterate quarantines
                for quarantine in self.quarantines:
                    if len(self.recipients_quarantines) == len(
                            self.recipients):
                        # every recipient matched a quarantine already
                        if quarantine.index >= max(
                                [q.index for q in self.recipients_quarantines.values()]):
                            # all recipients matched a quarantine with at least
                            # the same precedence already, skip checks against
                            # quarantines with lower precedence
                            self.logger.debug(
                                "{}: {}: skip further checks of this header".format(
                                    self.queueid, quarantine.name))
                            break

                    # check email header against quarantine regex
                    self.logger.debug(
                        "{}: {}: checking header against regex '{}'".format(
                            self.queueid, quarantine.name, quarantine.regex))
                    match = quarantine.match(header)
                    if match:
                        self.logger.debug(
                            "{}: {}: header matched regex".format(
                                self.queueid, quarantine.name))
                        # check for whitelisted recipients
                        whitelist = quarantine.get_whitelist()
                        if whitelist:
                            try:
                                whitelisted_recipients = self.whitelist_cache.get_whitelisted_recipients(
                                    whitelist, self.mailfrom, recipients_to_check)
                            except RuntimeError as e:
                                self.logger.error(
                                    "{}: {}: unable to query whitelist: {}".format(
                                        self.queueid, quarantine.name, e))
                                return Milter.TEMPFAIL
                        else:
                            whitelisted_recipients = {}

                        # iterate recipients
                        for recipient in recipients_to_check.copy():
                            if recipient in whitelisted_recipients:
                                # recipient is whitelisted in this quarantine
                                self.logger.debug(
                                    "{}: {}: recipient '{}' is whitelisted".format(
                                        self.queueid, quarantine.name, recipient))
                                continue

                            if recipient not in self.recipients_quarantines.keys() or \
                                    self.recipients_quarantines[recipient].index > quarantine.index:
                                self.logger.debug(
                                    "{}: {}: set quarantine for recipient '{}'".format(
                                        self.queueid, quarantine.name, recipient))
                                # save match for later use as template
                                # variables
                                self.quarantines_matches[quarantine.name] = match
                                self.recipients_quarantines[recipient] = quarantine
                                if quarantine.index == 0:
                                    # we do not need to check recipients which
                                    # matched the quarantine with the highest
                                    # precedence already
                                    recipients_to_check.remove(recipient)
                            else:
                                self.logger.debug(
                                    "{}: {}: a quarantine with same or higher precedence "
                                    "matched already for recipient '{}'".format(
                                        self.queueid, quarantine.name, recipient))

                if not recipients_to_check:
                    self.logger.debug(
                        "{}: all recipients matched the first quarantine, "
                        "skipping all remaining header checks".format(
                            self.queueid))
                    break

            # check if no quarantine has matched for all recipients
            if not self.recipients_quarantines:
                # accept email
                self.logger.info(
                    "{}: passed clean for all recipients".format(
                        self.queueid))
                return Milter.ACCEPT

            # check if the mail body is needed
            for recipient, quarantine in self.recipients_quarantines.items():
                if quarantine.get_storage() or quarantine.get_notification():
                    # mail body is needed, continue processing
                    return Milter.CONTINUE

            # quarantine and notification are disabled on all matching
            # quarantines, just return configured action
            quarantine = self._get_preferred_quarantine()
            self.logger.info(
                "{}: {} matching quarantine is '{}', performing milter action {}".format(
                    self.queueid,
                    self.preferred_quarantine_action,
                    quarantine.name,
                    quarantine.action))
            if quarantine.action == "REJECT":
                self.setreply("554", "5.7.0", quarantine.reject_reason)
            return quarantine.milter_action

        except Exception as e:
            self.logger.exception(
                "an exception occured in eoh function: {}".format(e))
            return Milter.TEMPFAIL

    def body(self, chunk):
        try:
            # save received body chunk
            self.fp.write(chunk)
        except Exception as e:
            self.logger.exception(
                "an exception occured in body function: {}".format(e))
            return Milter.TEMPFAIL
        return Milter.CONTINUE

    def eom(self):
        try:
            # processing recipients grouped by quarantines
            quarantines = []
            for quarantine, recipients in groupby(
                    sorted(self.recipients_quarantines,
                           key=lambda x: self.recipients_quarantines[x].index),
                    lambda x: self.recipients_quarantines[x]):
                quarantines.append((quarantine, list(recipients)))

            # iterate quarantines sorted by index
            for quarantine, recipients in sorted(
                    quarantines, key=lambda x: x[0].index):
                headers = defaultdict(str)
                for name, value in self.headers:
                    headers[name.lower()] = value
                subgroups = self.quarantines_matches[quarantine.name].groups(
                    default="")
                named_subgroups = self.quarantines_matches[quarantine.name].groupdict(
                    default="")

                # check if a storage is configured
                storage_id = ""
                storage = quarantine.get_storage()
                if storage:
                    # add email to quarantine
                    self.logger.info("{}: adding to quarantine '{}' for: {}".format(
                        self.queueid, quarantine.name, ", ".join(recipients)))
                    try:
                        storage_id = storage.add(
                            self.queueid, self.mailfrom, recipients, headers, self.fp,
                            subgroups, named_subgroups)
                    except RuntimeError as e:
                        self.logger.error(
                            "{}: unable to add to quarantine '{}': {}".format(
                                self.queueid, quarantine.name, e))
                        return Milter.TEMPFAIL

                # check if a notification is configured
                notification = quarantine.get_notification()
                if notification:
                    # notify
                    self.logger.info(
                        "{}: sending notification for quarantine '{}' to: {}".format(
                            self.queueid, quarantine.name, ", ".join(recipients)))
                    try:
                        notification.notify(
                            self.queueid, storage_id,
                            self.mailfrom, recipients, headers, self.fp,
                            subgroups, named_subgroups)
                    except RuntimeError as e:
                        self.logger.error(
                            "{}: unable to send notification for quarantine '{}': {}".format(
                                self.queueid, quarantine.name, e))
                        return Milter.TEMPFAIL

                # remove processed recipient
                for recipient in recipients:
                    self.delrcpt(recipient)
                    self.recipients.remove(recipient)

            self.fp.close()

            # email passed clean for at least one recipient, accepting email
            if self.recipients:
                self.logger.info(
                    "{}: passed clean for: {}".format(
                        self.queueid, ", ".join(
                            self.recipients)))
                return Milter.ACCEPT

            # return configured action
            quarantine = self._get_preferred_quarantine()
            self.logger.info(
                "{}: {} matching quarantine is '{}', performing milter action {}".format(
                    self.queueid,
                    self.preferred_quarantine_action,
                    quarantine.name,
                    quarantine.action))
            if quarantine.action == "REJECT":
                self.setreply("554", "5.7.0", quarantine.reject_reason)
            return quarantine.milter_action

        except Exception as e:
            self.logger.exception(
                "an exception occured in eom function: {}".format(e))
            return Milter.TEMPFAIL

    def close(self):
        self.logger.debug(
            "disconnect from {} port {}".format(
                *self.hostaddr))
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
                "mandatory option '{}' not present in config section 'global'".format(option))

    # read global config section
    global_cfg = dict(parser.items("global"))
    preferred_quarantine_action = global_cfg["preferred_quarantine_action"].lower()
    if preferred_quarantine_action not in ["first", "last"]:
        raise RuntimeError(
            "option preferred_quarantine_action has illegal value")

    # read active quarantine names
    quarantines = [
        q.strip() for q in global_cfg["quarantines"].split(",")]
    if len(quarantines) != len(set(quarantines)):
        raise RuntimeError(
            "at least one quarantine is specified multiple times in quarantines option")
    if "global" in quarantines:
        quarantines.remove("global")
        logger.warning(
            "removed illegal quarantine name 'global' from list of active quarantines")
    if not quarantines:
        raise RuntimeError("no quarantines configured")

    milter_quarantines = []
    logger.debug("preparing milter configuration ...")
    # iterate quarantine names
    for index, name in enumerate(quarantines):
        # check if config section for current quarantine exists
        if name not in parser.sections():
            raise RuntimeError(
                "config section '{}' does not exist".format(name))

        cfg = dict(parser.items(name))
        quarantine = Quarantine(name, index)
        quarantine.setup_from_cfg(global_cfg, cfg, test)
        milter_quarantines.append(quarantine)

    QuarantineMilter.preferred_quarantine_action = preferred_quarantine_action
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
