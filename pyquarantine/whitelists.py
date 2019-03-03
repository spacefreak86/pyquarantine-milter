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

import datetime
import logging
import peewee
import re
import sys
from playhouse.db_url import connect



class WhitelistModel(peewee.Model):
    mailfrom = peewee.CharField()
    recipient = peewee.CharField()
    created = peewee.DateTimeField(default=datetime.datetime.now)
    last_used = peewee.DateTimeField(default=datetime.datetime.now)
    comment = peewee.TextField(default="")
    permanent = peewee.BooleanField(default=False)



class Meta(object):
    indexes = (
        (('mailfrom', 'recipient'), True), # trailing comma is mandatory if only one index should be created
    )



class Whitelist(object):
    "Whitelist base class"
    _whitelists = {}

    def __init__(self, name, config, configtest=False):
        self.name = name
        self.config = config[name]
        self.global_config = config["global"]
        self.logger = logging.getLogger(__name__)
        # check if mandatory options are present in config
        for option in ["whitelist_table"]:
            if option not in self.config.keys() and option in self.global_config.keys():
                self.config[option] = self.global_config[option]
            if option not in self.config.keys():
                raise RuntimeError("mandatory option '{}' not present in config section '{}' or 'global'".format(option, self.name))
        self.tablename = self.config["whitelist_table"]
        connection_string = self.config["whitelist"]
        if connection_string in Whitelist._whitelists.keys():
            self.db = Whitelist._whitelists[connection_string]
            return
        try:
            # connect to database
            self.logger.debug("connecting to database '{}'".format(re.sub(r"(.*?://.*?):.*?(@.*)", r"\1:<PASSWORD>\2", connection_string)))
            self.db = connect(connection_string)
        except Exception as e:
            raise RuntimeError("unable to connect to database: {}".format(e))
        else:
            Whitelist._whitelists[connection_string] = self.db
        if configtest: return
        self.Meta = Meta
        self.Meta.database = self.db
        self.Meta.table_name = self.tablename
        self.Whitelist = type("WhitelistModel_{}".format(name), (WhitelistModel,), {
            "Meta": self.Meta 
        })
        try:
            self.db.create_tables([self.Whitelist])
        except Exception as e:
            raise RuntimeError("unable to initialize table '{}': {}".format(self.tablename, e))

    def get_weight(self, entry):
        value = 0
        for address in [entry.mailfrom, entry.recipient]:
            if address == "":
                value += 2
            elif address[0] == "@":
                value += 1
        return value

    def check(self, mailfrom, recipient):
        # generate list of possible mailfroms
        self.logger.debug("query database for whitelist entries from <{}> to <{}>".format(mailfrom, recipient))
        mailfroms = [""]
        if "@" in mailfrom:
            mailfroms.append("@{}".format(mailfrom.split("@")[1]))
        mailfroms.append(mailfrom)
        # generate list of possible recipients
        recipients = [""]
        if "@" in recipient:
            recipients.append("@{}".format(recipient.split("@")[1]))
        recipients.append(recipient)
        # query the database
        try:
            entries = list(self.Whitelist.select().where(self.Whitelist.mailfrom.in_(mailfroms), self.Whitelist.recipient.in_(recipients)))
        except Exception as e:
            entries = []
            self.logger.error("unable to query whitelist database: {}".format(e))
        if len(entries) == 0:
            # no whitelist entry found
            return False 
        print(entries)
        if len(entries) > 1:
            entries.sort(key=lambda x: self.get_weight(x))
        # use entry with the highest weight
        entry = entries[-1]
        entry.last_used = datetime.datetime.now()
        entry.save()
        return True



class WhitelistCache(object):
    def __init__(self):
        self.cache = {}

    def load(self, whitelist, mailfrom, recipients):
        for recipient in recipients:
            self.check(whitelist, mailfrom, recipient)

    def check(self, whitelist, mailfrom, recipient):
        if whitelist not in self.cache.keys(): self.cache[whitelist] = {}
        if recipient not in self.cache[whitelist].keys(): self.cache[whitelist][recipient] = None
        if self.cache[whitelist][recipient] == None:
            self.cache[whitelist][recipient] = whitelist.check(mailfrom, recipient)
        return self.cache[whitelist][recipient]

    def get_whitelisted_recipients(self, whitelist, mailfrom, recipients):
        self.load(whitelist, mailfrom, recipients)
        return filter(lambda x: self.cache[whitelist][x] == True, self.cache[whitelist].keys())
