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


class WhitelistBase(object):
    "Whitelist base class"
    def __init__(self, global_config, config, configtest=False):
        self.global_config = global_config
        self.config = config
        self.configtest = configtest
        self.name = config["name"]
        self.logger = logging.getLogger(__name__)
        self.valid_entry_regex = re.compile(r"^[a-zA-Z0-9_.+-]*?(@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)?$")

    def check(self, mailfrom, recipient):
        "Check if mailfrom/recipient combination is whitelisted."
        return

    def find(self, mailfrom=None, recipients=None, older_than=None):
        "Find whitelist entries."
        return

    def add(self, mailfrom, recipient, comment, permanent):
        "Add entry to whitelist."
        # check if mailfrom and recipient are valid
        if not self.valid_entry_regex.match(mailfrom):
            raise RuntimeError("invalid from address")
        if not self.valid_entry_regex.match(recipient):
            raise RuntimeError("invalid recipient")
        return

    def delete(self, whitelist_id):
        "Delete entry from whitelist."
        return


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


class DatabaseWhitelist(WhitelistBase):
    "Whitelist class to store whitelist in a database"
    _db_connections = {}
    _db_tables = {}

    def __init__(self, global_config, config, configtest=False):
        super(DatabaseWhitelist, self).__init__(global_config, config, configtest)

        # check if mandatory options are present in config
        for option in ["whitelist_db_connection", "whitelist_db_table"]:
            if option not in self.config.keys() and option in self.global_config.keys():
                self.config[option] = self.global_config[option]
            if option not in self.config.keys():
                raise RuntimeError("mandatory option '{}' not present in config section '{}' or 'global'".format(option, self.name))

        tablename = self.config["whitelist_db_table"]
        connection_string = self.config["whitelist_db_connection"]

        if connection_string in DatabaseWhitelist._db_connections.keys():
            db = DatabaseWhitelist._db_connections[connection_string]
        else:
            try:
                # connect to database
                self.logger.debug("connecting to database '{}'".format(re.sub(r"(.*?://.*?):.*?(@.*)", r"\1:<PASSWORD>\2", connection_string)))
                db = connect(connection_string)
            except Exception as e:
                raise RuntimeError("unable to connect to database: {}".format(e))

            DatabaseWhitelist._db_connections[connection_string] = db

        # generate model meta class
        self.meta = Meta
        self.meta.database = db
        self.meta.table_name = tablename
        self.model = type("WhitelistModel_{}".format(self.name), (WhitelistModel,), {
            "Meta": self.meta 
        })

        if connection_string not in DatabaseWhitelist._db_tables.keys():
            DatabaseWhitelist._db_tables[connection_string] = []

        if tablename not in DatabaseWhitelist._db_tables[connection_string]:
            DatabaseWhitelist._db_tables[connection_string].append(tablename)
            if not self.configtest:
                try:
                    db.create_tables([self.model])
                except Exception as e:
                    raise RuntimeError("unable to initialize table '{}': {}".format(tablename, e))

    def _entry_to_dict(self, entry):
        result = {}
        result[entry.id] = {
            "id": entry.id,
            "mailfrom": entry.mailfrom,
            "recipient": entry.recipient,
            "created": entry.created,
            "last_used": entry.last_used,
            "comment": entry.comment,
            "permanent": entry.permanent
        }
        return result

    def get_weight(self, entry):
        value = 0
        for address in [entry.mailfrom, entry.recipient]:
            if address == "":
                value += 2
            elif address[0] == "@":
                value += 1
        return value

    def check(self, mailfrom, recipient):
        # check if mailfrom/recipient combination is whitelisted
        super(DatabaseWhitelist, self).check(mailfrom, recipient)

        # generate list of possible mailfroms
        self.logger.debug("query database for whitelist entries from <{}> to <{}>".format(mailfrom, recipient))
        mailfroms = [""]
        if "@" in mailfrom and not mailfrom.startswith("@"):
            mailfroms.append("@{}".format(mailfrom.split("@")[1]))
        mailfroms.append(mailfrom)

        # generate list of possible recipients
        recipients = [""]
        if "@" in recipient and not recipient.startswith("@"):
            recipients.append("@{}".format(recipient.split("@")[1]))
        recipients.append(recipient)

        # query the database
        try:
            entries = list(self.model.select().where(self.model.mailfrom.in_(mailfroms), self.model.recipient.in_(recipients)))
        except Exception as e:
            raise RuntimeError("unable to query database: {}".format(e))

        if not entries:
            # no whitelist entry found
            return {}

        if len(entries) > 1:
            entries.sort(key=lambda x: self.get_weight(x), reverse=True)

        # use entry with the highest weight
        entry = entries[0]
        entry.last_used = datetime.datetime.now()
        entry.save()
        result = {}
        for entry in entries:
            result.update(self._entry_to_dict(entry))

        return result

    def find(self, mailfrom=None, recipients=None, older_than=None):
        "Find whitelist entries."
        super(DatabaseWhitelist, self).find(mailfrom, recipients, older_than)

        if type(mailfrom) == str: mailfrom = [mailfrom]
        if type(recipients) == str: recipients = [recipients]

        entries = {}
        try:
            for entry in list(self.model.select()):
                if older_than != None: 
                    if (datetime.datetime.now() - entry.last_used).total_seconds() < (older_than * 24 * 3600):
                        continue

                if mailfrom != None:
                    if entry.mailfrom not in mailfrom:
                        continue

                if recipients != None:
                    if entry.recipient not in recipients:
                        continue

                entries.update(self._entry_to_dict(entry))
        except Exception as e:
            raise RuntimeError("unable to query database: {}".format(e))

        return entries

    def add(self, mailfrom, recipient, comment, permanent):
        "Add entry to whitelist."
        super(DatabaseWhitelist, self).add(mailfrom, recipient, comment, permanent)

        try:
            self.model.create(mailfrom=mailfrom, recipient=recipient, comment=comment, permanent=permanent)
        except Exception as e:
            raise RuntimeError("unable to add entry to database: {}".format(e))

    def delete(self, whitelist_id):
        "Delete entry from whitelist."
        super(DatabaseWhitelist, self).delete(whitelist_id)

        try:
            query = self.model.delete().where(self.model.id == whitelist_id)
            deleted = query.execute()
        except Exception as e:
            raise RuntimeError("unable to delete entry from database: {}".format(e))

        if deleted == 0:
            raise RuntimeError("invalid whitelist id")


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
        return list(filter(lambda x: self.cache[whitelist][x], self.cache[whitelist].keys()))


# list of whitelist types and their related whitelist classes
TYPES = {"db": DatabaseWhitelist}
