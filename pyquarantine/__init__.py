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
    "QuarantineMilter",
    "generate_milter_config",
    "reload_config",
    "cli",
    "mailer",
    "notifications",
    "quarantines",
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
from pyquarantine import quarantines
from pyquarantine import notifications
from pyquarantine import whitelists


class QuarantineMilter(Milter.Base):
    """QuarantineMilter based on Milter.Base to implement milter communication

    The class variable config needs to be filled with the result of the generate_milter_config function.

    """
    config = None
    global_config = None

    # list of default config files
    _config_files = [
        "/etc/pyquarantine/pyquarantine.conf",
        os.path.expanduser('~/pyquarantine.conf'),
        "pyquarantine.conf"]
    # list of possible actions
    _actions = {
        "ACCEPT": Milter.ACCEPT,
        "REJECT": Milter.REJECT,
        "DISCARD": Milter.DISCARD}

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # save config, it must not change during runtime
        self.global_config = QuarantineMilter.global_config
        self.config = QuarantineMilter.config

    def _get_preferred_quarantine(self):
        matching_quarantines = [
            q for q in self.recipients_quarantines.values() if q]
        if self.global_config["preferred_quarantine_action"] == "first":
            quarantine = sorted(
                matching_quarantines,
                key=lambda x: x["index"])[0]
        else:
            quarantine = sorted(
                matching_quarantines,
                key=lambda x: x["index"],
                reverse=True)[0]
        return quarantine

    @staticmethod
    def get_configfiles():
        return QuarantineMilter._config_files

    @staticmethod
    def get_actions():
        return QuarantineMilter._actions

    @staticmethod
    def set_configfiles(config_files):
        QuarantineMilter._config_files = config_files

    def connect(self, IPname, family, hostaddr):
        self.logger.debug(
            "accepted milter connection from {} port {}".format(
                *hostaddr))
        ip = IPAddress(hostaddr[0])
        for quarantine in self.config.copy():
            for ignore in quarantine["ignore_hosts_list"]:
                if ip in ignore:
                    self.logger.debug(
                        "host {} is ignored by quarantine {}".format(
                            hostaddr[0], quarantine["name"]))
                    self.config.remove(quarantine)
                    break
            if not self.config:
                self.logger.debug(
                    "host {} is ignored by all quarantines, "
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
        return Milter.CONTINUE

    @Milter.noreply
    def header(self, name, value):
        self.headers.append((name, value))
        return Milter.CONTINUE

    def eoh(self):
        try:
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
                for quarantine in self.config:
                    if len(self.recipients_quarantines) == len(
                            self.recipients):
                        # every recipient matched a quarantine already
                        if quarantine["index"] >= max(
                                [q["index"] for q in self.recipients_quarantines.values()]):
                            # all recipients matched a quarantine with at least
                            # the same precedence already, skip checks against
                            # quarantines with lower precedence
                            self.logger.debug(
                                "{}: {}: skip further checks of this header".format(
                                    self.queueid, quarantine["name"]))
                            break

                    # check email header against quarantine regex
                    self.logger.debug(
                        "{}: {}: checking header against regex '{}'".format(
                            self.queueid, quarantine["name"], quarantine["regex"]))
                    match = quarantine["regex_compiled"].search(header)
                    if match:
                        self.logger.debug(
                            "{}: {}: header matched regex".format(
                                self.queueid, quarantine["name"]))
                        # check for whitelisted recipients
                        whitelist = quarantine["whitelist_obj"]
                        if whitelist is not None:
                            try:
                                whitelisted_recipients = self.whitelist_cache.get_whitelisted_recipients(
                                    whitelist, self.mailfrom, recipients_to_check)
                            except RuntimeError as e:
                                self.logger.error(
                                    "{}: {}: unable to query whitelist: {}".format(
                                        self.queueid, quarantine["name"], e))
                                return Milter.TEMPFAIL
                        else:
                            whitelisted_recipients = {}

                        # iterate recipients
                        for recipient in recipients_to_check.copy():
                            if recipient in whitelisted_recipients:
                                # recipient is whitelisted in this quarantine
                                self.logger.debug(
                                    "{}: {}: recipient '{}' is whitelisted".format(
                                        self.queueid, quarantine["name"], recipient))
                                continue

                            if recipient not in self.recipients_quarantines.keys() or \
                                    self.recipients_quarantines[recipient]["index"] > quarantine["index"]:
                                self.logger.debug(
                                    "{}: {}: set quarantine for recipient '{}'".format(
                                        self.queueid, quarantine["name"], recipient))
                                # save match for later use as template
                                # variables
                                self.quarantines_matches[quarantine["name"]] = match
                                self.recipients_quarantines[recipient] = quarantine
                                if quarantine["index"] == 0:
                                    # we do not need to check recipients which
                                    # matched the quarantine with the highest
                                    # precedence already
                                    recipients_to_check.remove(recipient)
                            else:
                                self.logger.debug(
                                    "{}: {}: a quarantine with same or higher precedence "
                                    "matched already for recipient '{}'".format(
                                        self.queueid, quarantine["name"], recipient))

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

            # check if the email body is needed
            keep_body = False
            for recipient, quarantine in self.recipients_quarantines.items():
                if quarantine["quarantine_obj"] or quarantine["notification_obj"]:
                    keep_body = True
                    break

            if keep_body:
                self.logger.debug(
                    "{}: initializing memory buffer to save email data".format(
                        self.queueid))
                # initialize memory buffer to save email data
                self.fp = BytesIO()
                # write email headers to memory buffer
                for name, value in self.headers:
                    self.fp.write("{}: {}\n".format(name, value).encode())
                self.fp.write("\n".encode())
            else:
                # quarantine and notification are disabled on all matching
                # quarantines, return configured action
                quarantine = self._get_preferred_quarantine()
                self.logger.info(
                    "{}: {} matching quarantine is '{}', performing milter action {}".format(
                        self.queueid,
                        self.global_config["preferred_quarantine_action"],
                        quarantine["name"],
                        quarantine["action"].upper()))
                if quarantine["action"] == "reject":
                    self.setreply("554", "5.7.0", quarantine["reject_reason"])
                return quarantine["milter_action"]

            return Milter.CONTINUE

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
                           key=lambda x: self.recipients_quarantines[x]["index"]),
                    lambda x: self.recipients_quarantines[x]):
                quarantines.append((quarantine, list(recipients)))

            # iterate quarantines sorted by index
            for quarantine, recipients in sorted(
                    quarantines, key=lambda x: x[0]["index"]):
                quarantine_id = ""
                headers = defaultdict(str)
                for name, value in self.headers:
                    headers[name.lower()] = value
                subgroups = self.quarantines_matches[quarantine["name"]].groups(
                    default="")
                named_subgroups = self.quarantines_matches[quarantine["name"]].groupdict(
                    default="")

                # check if a quarantine is configured
                if quarantine["quarantine_obj"] is not None:
                    # add email to quarantine
                    self.logger.info("{}: adding to quarantine '{}' for: {}".format(
                        self.queueid, quarantine["name"], ", ".join(recipients)))
                    try:
                        quarantine_id = quarantine["quarantine_obj"].add(
                            self.queueid, self.mailfrom, recipients, headers, self.fp,
                            subgroups, named_subgroups)
                    except RuntimeError as e:
                        self.logger.error(
                            "{}: unable to add to quarantine '{}': {}".format(
                                self.queueid, quarantine["name"], e))
                        return Milter.TEMPFAIL

                # check if a notification is configured
                if quarantine["notification_obj"] is not None:
                    # notify
                    self.logger.info(
                        "{}: sending notification for quarantine '{}' to: {}".format(
                            self.queueid, quarantine["name"], ", ".join(recipients)))
                    try:
                        quarantine["notification_obj"].notify(
                            self.queueid, quarantine_id,
                            self.mailfrom, recipients, headers, self.fp,
                            subgroups, named_subgroups)
                    except RuntimeError as e:
                        self.logger.error(
                            "{}: unable to send notification for quarantine '{}': {}".format(
                                self.queueid, quarantine["name"], e))
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
                    self.global_config["preferred_quarantine_action"],
                    quarantine["name"],
                    quarantine["action"].upper()))
            if quarantine["action"] == "reject":
                self.setreply("554", "5.7.0", quarantine["reject_reason"])
            return quarantine["milter_action"]

        except Exception as e:
            self.logger.exception(
                "an exception occured in eom function: {}".format(e))
            return Milter.TEMPFAIL


def generate_milter_config(configtest=False, config_files=[]):
    "Generate the configuration for QuarantineMilter class."
    logger = logging.getLogger(__name__)

    # read config file
    parser = configparser.ConfigParser()
    if not config_files:
        config_files = parser.read(QuarantineMilter.get_configfiles())
    else:
        config_files = parser.read(config_files)
    if not config_files:
        raise RuntimeError("config file not found")

    QuarantineMilter.set_configfiles(config_files)
    os.chdir(os.path.dirname(config_files[0]))

    # check if mandatory config options in global section are present
    if "global" not in parser.sections():
        raise RuntimeError(
            "mandatory section 'global' not present in config file")
    for option in ["quarantines", "preferred_quarantine_action"]:
        if not parser.has_option("global", option):
            raise RuntimeError(
                "mandatory option '{}' not present in config section 'global'".format(option))

    # read global config section
    global_config = dict(parser.items("global"))
    global_config["preferred_quarantine_action"] = global_config["preferred_quarantine_action"].lower()
    if global_config["preferred_quarantine_action"] not in ["first", "last"]:
        raise RuntimeError(
            "option preferred_quarantine_action has illegal value")

    # read active quarantine names
    quarantine_names = [
        q.strip() for q in global_config["quarantines"].split(",")]
    if len(quarantine_names) != len(set(quarantine_names)):
        raise RuntimeError(
            "at least one quarantine is specified multiple times in quarantines option")
    if "global" in quarantine_names:
        quarantine_names.remove("global")
        logger.warning(
            "removed illegal quarantine name 'global' from list of active quarantines")
    if not quarantine_names:
        raise RuntimeError("no quarantines configured")

    milter_config = []

    logger.debug("preparing milter configuration ...")
    # iterate quarantine names
    for index, quarantine_name in enumerate(quarantine_names):

        # check if config section for current quarantine exists
        if quarantine_name not in parser.sections():
            raise RuntimeError(
                "config section '{}' does not exist".format(quarantine_name))
        config = dict(parser.items(quarantine_name))

        # check if mandatory config options are present in config
        for option in ["regex", "quarantine_type", "notification_type",
                       "action", "whitelist_type", "smtp_host", "smtp_port"]:
            if option not in config.keys() and \
                    option in global_config.keys():
                config[option] = global_config[option]
            if option not in config.keys():
                raise RuntimeError(
                    "mandatory option '{}' not present in config section '{}' or 'global'".format(
                        option, quarantine_name))

        # check if optional config options are present in config
        defaults = {
            "reject_reason": "Message rejected",
            "ignore_hosts": ""
        }
        for option in defaults.keys():
            if option not in config.keys() and \
                    option in global_config.keys():
                config[option] = global_config[option]
            if option not in config.keys():
                config[option] = defaults[option]

        # set quarantine name
        config["name"] = quarantine_name

        # set the index
        config["index"] = index

        # pre-compile regex
        logger.debug(
            "{}: compiling regex '{}'".format(
                quarantine_name,
                config["regex"]))
        config["regex_compiled"] = re.compile(
            config["regex"], re.MULTILINE + re.DOTALL + re.IGNORECASE)

        # create quarantine instance
        quarantine_type = config["quarantine_type"].lower()
        if quarantine_type in quarantines.TYPES.keys():
            logger.debug(
                "{}: initializing quarantine type '{}'".format(
                    quarantine_name,
                    quarantine_type.upper()))
            quarantine = quarantines.TYPES[quarantine_type](
                global_config, config, configtest)
        elif quarantine_type == "none":
            logger.debug("{}: quarantine is NONE".format(quarantine_name))
            quarantine = None
        else:
            raise RuntimeError(
                "{}: unknown quarantine type '{}'".format(
                    quarantine_name, quarantine_type))

        config["quarantine_obj"] = quarantine

        # create whitelist instance
        whitelist_type = config["whitelist_type"].lower()
        if whitelist_type in whitelists.TYPES.keys():
            logger.debug(
                "{}: initializing whitelist type '{}'".format(
                    quarantine_name,
                    whitelist_type.upper()))
            whitelist = whitelists.TYPES[whitelist_type](
                global_config, config, configtest)
        elif whitelist_type == "none":
            logger.debug("{}: whitelist is NONE".format(quarantine_name))
            whitelist = None
        else:
            raise RuntimeError(
                "{}: unknown whitelist type '{}'".format(
                    quarantine_name, whitelist_type))

        config["whitelist_obj"] = whitelist

        # create notification instance
        notification_type = config["notification_type"].lower()
        if notification_type in notifications.TYPES.keys():
            logger.debug(
                "{}: initializing notification type '{}'".format(
                    quarantine_name,
                    notification_type.upper()))
            notification = notifications.TYPES[notification_type](
                global_config, config, configtest)
        elif notification_type == "none":
            logger.debug("{}: notification is NONE".format(quarantine_name))
            notification = None
        else:
            raise RuntimeError(
                "{}: unknown notification type '{}'".format(
                    quarantine_name, notification_type))

        config["notification_obj"] = notification

        # determining milter action for this quarantine
        action = config["action"].upper()
        if action in QuarantineMilter.get_actions().keys():
            logger.debug("{}: action is {}".format(quarantine_name, action))
            config["milter_action"] = QuarantineMilter.get_actions()[action]
        else:
            raise RuntimeError(
                "{}: unknown action '{}'".format(
                    quarantine_name, action))

        # create host/network whitelist
        config["ignore_hosts_list"] = []
        ignored = set([p.strip()
                       for p in config["ignore_hosts"].split(",") if p])
        for ignore in ignored:
            if not ignore:
                continue
            # parse network notation
            try:
                net = IPNetwork(ignore)
            except AddrFormatError as e:
                raise RuntimeError("error parsing ignore_hosts: {}".format(e))
            else:
                config["ignore_hosts_list"].append(net)
        if config["ignore_hosts_list"]:
            logger.debug(
                "{}: ignore hosts: {}".format(
                    quarantine_name,
                    ", ".join(ignored)))

        milter_config.append(config)

    return global_config, milter_config


def reload_config():
    "Reload the configuration of QuarantineMilter class."
    logger = logging.getLogger(__name__)

    try:
        global_config, config = generate_milter_config()
    except RuntimeError as e:
        logger.info(e)
        logger.info("daemon is still running with previous configuration")
    else:
        logger.info("reloading configuration")
        QuarantineMilter.global_config = global_config
        QuarantineMilter.config = config
