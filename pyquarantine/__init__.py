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

__all__ = ["QuarantineMilter", "generate_milter_config", "reload_config", "mailer", "notifications", "run", "quarantines", "whitelists"]

import ConfigParser
import Milter
import StringIO
import logging
import os
import re
import sys

import mailer
import quarantines
import notifications
import whitelists

from Milter.utils import parse_addr



class QuarantineMilter(Milter.Base):
    """QuarantineMilter based on Milter.Base to implement milter communication

    The class variable config needs to be filled with the result of the generate_milter_config function.

    """
    config = None

    # list of default config files
    _config_files = ["/etc/pyquarantine/pyquarantine.conf", os.path.expanduser('~/pyquarantine.conf'), "pyquarantine.conf"]
    # list of possible actions
    _actions = {"ACCEPT": Milter.ACCEPT, "REJECT": Milter.REJECT, "DISCARD": Milter.DISCARD}


    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # save config, it must not change during runtime
        self.config = QuarantineMilter.config

    @staticmethod
    def get_configfiles():
        return QuarantineMilter._config_files

    @staticmethod
    def get_actions():
        return QuarantineMilter._actions

    @staticmethod
    def set_configfiles(config_files):
        QuarantineMilter._config_files = config_files

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
        self.logger.debug("{}: received queue-id from MTA".format(self.queueid))
        self.recipients = list(self.recipients)
        self.headers = []
        self.subject = ""
        return Milter.CONTINUE

    @Milter.noreply
    def header(self, name, value):
        self.headers.append("{}: {}".format(name, value))
        if name.lower() == "subject":
            self.subject = value
        return Milter.CONTINUE

    def eoh(self):
        self.matched = None
        self.whitelist = whitelists.WhitelistCache()
        # iterate email headers
        for header in self.headers:
            self.logger.debug("{}: checking header '{}' against regex of every configured quarantine".format(self.queueid, header))
            # iterate quarantines
            for name, quarantine in self.config.items():
                if self.matched != None and quarantine["index"] == self.matched["index"]:
                    # a quarantine with higher precedence already matched, skip checks of quarantines with lower precedence
                    self.logger.debug("{}: quarantine '{}' matched already, skip further checks of this header".format(self.queueid, name))
                    break
                self.logger.debug("{}: checking header against quarantine '{}'".format(self.queueid, name))
                # check if header matches regex
                if quarantine["regex_compiled"].match(header):
                    if quarantine["whitelist"] != None and \
                            len(self.whitelist.get_whitelisted_recipients(quarantine["whitelist"], self.mailfrom, self.recipients)) == len(self.recipients):
                        # all recipients are whitelisted, continue with header checks
                        self.logger.debug("{}: header matched regex, but all recipients are whitelisted in quarantine '{}', continue checking this header".format(self.queueid, name))
                        continue
                    self.matched = quarantine
                    # skip checks of this header with quarantines with lower precedence
                    self.logger.debug("{}: header matched regex in quarantine '{}', further checks of this header will be skipped".format(self.queueid, name))
                    break
            if self.matched != None and self.matched["index"] == 0:
                self.logger.debug("{}: skipping checks of remaining headers, the quarantine with highest precedence matched already".format(self.queueid))
                break
        if self.matched != None:
            self.logger.info("{}: email matched quarantine '{}'".format(self.queueid, self.matched["name"]))
            # one of the configured quarantines matched
            if self.matched["quarantine"] != None or self.matched["notification"] != None:
                self.logger.debug("{}: initializing memory buffer to save email data".format(self.queueid))
                # quarantine or notification configured, initialize memory buffer to save mail
                self.fp = StringIO.StringIO()
                # write email headers to memory buffer
                self.fp.write("{}\n".format("\n".join(self.headers)))
            else:
                # quarantine and notification disabled, return configured action
                self.logger.debug("{}: ".format(self.queueid))
                self.logger.info("{}: quarantine and notification disabled, responding with configured action: {}".format(self.queueid, self.matched["action"].upper()))
                return self.matched["milter_action"]
        else:
            # no quarantine matched, accept mail
            self.logger.info("{}: email passed clean".format(self.queueid))
            return Milter.ACCEPT
        return Milter.CONTINUE

    def body(self, chunk):
        # save received body chunk
        self.fp.write(chunk)
        return Milter.CONTINUE

    def eom(self):
        if self.matched["whitelist"] != None:
            whitelisted_recipients = self.whitelist.get_whitelisted_recipients(self.matched["whitelist"], self.mailfrom, self.recipients)
            if len(whitelisted_recipients) > 0:
                for recipient in whitelisted_recipients:
                    self.recipients.remove(recipient)
                self.fp.seek(0)
                self.logger.info("{}: sending original email to whitelisted recipient(s): {}".format(self.queueid, "<{}>".format(">,<".join(whitelisted_recipients))))
                try:
                    mailer.sendmail(self.matched["smtp_host"], self.matched["smtp_port"], self.queueid, self.mailfrom, whitelisted_recipients, self.fp.read())
                except Exception as e:
                    self.logger.error("{}: unable to send original email: {}".format(self.queueid, e))
                    return Milter.TEMPFAIL
        if len(self.recipients) > 0:
            quarantine_id = ""
            if self.matched["quarantine"] != None:
                # add email to quarantine
                self.fp.seek(0)
                try:
                    quarantine_id = self.matched["quarantine"].add(self.queueid, self.mailfrom, self.recipients, fp=self.fp)
                except Exception as e:
                    self.logger.error("{}: unable to add email to quarantine: {}".format(self.queueid, e))
                    return Milter.TEMPFAIL
                else:
                    self.logger.info("{}: added email to quarantine of recipient(s): {}".format(self.queueid, "<{}>".format(">,<".join(self.recipients))))
            if self.matched["notification"] != None:
                # notify
                self.fp.seek(0)
                try:
                    self.matched["notification"].notify(self.queueid, quarantine_id, self.subject, self.mailfrom, self.recipients, fp=self.fp)
                except Exception as e:
                    self.logger.error("{}: unable to send notification(s): {}".format(self.queueid, e))
                    return Milter.TEMPFAIL
                else:
                    self.logger.info("{}: sent notification(s) to: {}".format(self.queueid, "<{}>".format(">,<".join(self.recipients))))
        self.fp.close()
        # return configured action
        self.logger.info("{}: responding with configured action: {}".format(self.queueid, self.matched["action"].upper()))
        return self.matched["milter_action"]



def generate_milter_config(configtest=False):
    "Generate the configuration for QuarantineMilter class."
    logger = logging.getLogger(__name__)
    # read config file
    parser = ConfigParser.ConfigParser()
    config_files = parser.read(QuarantineMilter.get_configfiles())
    if len(config_files) == 0:
        raise RuntimeError("config file not found")
    QuarantineMilter.set_configfiles(config_files)
    os.chdir(os.path.dirname(config_files[0]))
    # check if mandatory config options in global section are present
    if "global" not in parser.sections():
        raise RuntimeError("mandatory section 'global' not present in config file")
    for option in ["quarantines"]:
        if not parser.has_option("global", option):
            raise RuntimeError("mandatory option '{}' not present in config section 'global'".format(option))
    config = {}
    config["global"] = dict(parser.items("global"))
    # iterate configured quarantines
    quarantine_names = list(set(map(str.strip, parser.get("global", "quarantines").split(","))))
    if "global" in quarantine_names:
        logger.warning("removed illegal quarantine name 'global' from list of active quarantines")
        del(quarantine_names["global"])
    if len(quarantine_names) == 0:
        raise RuntimeError("no quarantines configured")
    idx = 0
    for name in quarantine_names:
        name = name.strip()
        # check if config section for current quarantine is present
        if name not in parser.sections():
            raise RuntimeError("config section '{}' is not present".format(name))
        config[name] = dict(parser.items(name))
        config[name]["name"] = name
        # check if mandatory config options are present in config
        for option in ["regex", "type", "notification", "action", "whitelist", "smtp_host", "smtp_port"]:
            if option not in config[name].keys() and \
                    option in config["global"].keys():
                config[name][option] = config["global"][option]
            if option not in config[name].keys():
                raise RuntimeError("mandatory option '{}' not present in config section '{}' or 'global'".format(option, name))
        logger.debug("preparing configuration for quarantine '{}' ...".format(name))
        ## add the index
        config[name]["index"] = idx
        idx += 1
        # compile regex
        regex = config[name]["regex"]
        logger.debug("=> compiling regex '{}'".format(regex))
        config[name]["regex_compiled"] = re.compile(regex)
        # create quarantine instance
        quarantine_type = config[name]["type"].lower()
        if quarantine_type in quarantines.quarantine_types.keys():
            logger.debug("=> initializing quarantine type '{}'".format(quarantine_type))
            quarantine = quarantines.quarantine_types[quarantine_type](name, config, configtest)
        elif quarantine_type == "none":
            logger.debug("=> setting quarantine to NONE")
            quarantine = None
        else:
            raise RuntimeError("unknown quarantine_type '{}'".format(quarantine_type))
        config[name]["quarantine"] = quarantine
        # create whitelist instance
        whitelist = config[name]["whitelist"]
        if whitelist.lower() == "none":
            logger.debug("=> setting whitelist to NONE")
            config[name]["whitelist"] = None
        else:
            logger.debug("=> initializing whitelist database")
            config[name]["whitelist"] = whitelists.Whitelist(name, config, configtest)
        # create notification instance
        notification_type = config[name]["notification"].lower()
        if notification_type in notifications.notification_types.keys():
            logger.debug("=> initializing notification type '{}'".format(notification_type))
            notification = notifications.notification_types[notification_type](name, config, configtest)
        elif notification_type == "none":
            logger.debug("=> setting notification to NONE")
            notification = None
        else:
            raise RuntimeError("unknown notification type '{}'".format(notification_type))
        config[name]["notification"] = notification
        # determining milter action for this quarantine
        action = config[name]["action"].upper()
        if action in QuarantineMilter.get_actions().keys():
            logger.debug("=> setting action to {}".format(action))
            config[name]["milter_action"] = QuarantineMilter.get_actions()[action]
        else:
            raise RuntimeError("unknown action '{}' configured for quarantine '{}'".format(action, name))
    # remove global section from config, every section should be a quarantine
    del(config["global"])
    if configtest:
        print("Configuration ok")
    return config



def reload_config():
    "Reload the configuration of QuarantineMilter class."
    logger = logging.getLogger(__name__)
    logger.debug("received SIGUSR1")
    try:
        config = generate_milter_config()
    except RuntimeError as e:
        logger.info(e)
        logger.info("daemon is still running with previous configuration")
    else:
        logger.info("reloading configuration")
        QuarantineMilter.config = config
