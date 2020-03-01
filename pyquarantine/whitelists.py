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
import peewee
import re

from datetime import datetime
from playhouse.db_url import connect


class WhitelistBase(object):
    "Whitelist base class"

    whitelist_type = "base"

    def __init__(self, name, global_cfg, cfg, test=False):
        self.name = name
        self.test = test
        self.logger = logging.getLogger(__name__)
        self.valid_entry_regex = re.compile(
            r"^[a-zA-Z0-9_.=+-]*?(@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)?$")

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
    created = peewee.DateTimeField(default=datetime.now)
    last_used = peewee.DateTimeField(default=datetime.now)
    comment = peewee.TextField(default="")
    permanent = peewee.BooleanField(default=False)


class Meta(object):
    indexes = (
        # trailing comma is mandatory if only one index should be created
        (('mailfrom', 'recipient'), True),
    )


class DatabaseWhitelist(WhitelistBase):
    "Whitelist class to store whitelist in a database"
    whitelist_type = "db"
    _db_connections = {}
    _db_tables = {}

    def __init__(self, name, global_cfg, cfg, test=False):
        super(
            DatabaseWhitelist,
            self).__init__(
            global_cfg,
            cfg,
            test)

        defaults = {}

        # check config
        for opt in ["whitelist_db_connection",
                    "whitelist_db_table"] + list(defaults.keys()):
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

        tablename = cfg["whitelist_db_table"]
        connection_string = cfg["whitelist_db_connection"]

        if connection_string in DatabaseWhitelist._db_connections.keys():
            db = DatabaseWhitelist._db_connections[connection_string]
        else:
            try:
                # connect to database
                conn = re.sub(
                    r"(.*?://.*?):.*?(@.*)",
                    r"\1:<PASSWORD>\2",
                    connection_string)
                self.logger.debug(
                    f"connecting to database '{conn}'")
                db = connect(connection_string)
            except Exception as e:
                raise RuntimeError(
                    f"unable to connect to database: {e}")

            DatabaseWhitelist._db_connections[connection_string] = db

        # generate model meta class
        self.meta = Meta
        self.meta.database = db
        self.meta.table_name = tablename
        self.model = type(f"WhitelistModel_{self.name}", (WhitelistModel,), {
            "Meta": self.meta
        })

        if connection_string not in DatabaseWhitelist._db_tables.keys():
            DatabaseWhitelist._db_tables[connection_string] = []

        if tablename not in DatabaseWhitelist._db_tables[connection_string]:
            DatabaseWhitelist._db_tables[connection_string].append(tablename)
            if not self.test:
                try:
                    db.create_tables([self.model])
                except Exception as e:
                    raise RuntimeError(
                        f"unable to initialize table '{tablename}': {e}")

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
        self.logger.debug(
            f"query database for whitelist entries from <{mailfrom}> "
            f"to <{recipient}>")
        mailfroms = [""]
        if "@" in mailfrom and not mailfrom.startswith("@"):
            domain = mailfrom.split("@")[1]
            mailfroms.append(f"@{domain}")
        mailfroms.append(mailfrom)

        # generate list of possible recipients
        recipients = [""]
        if "@" in recipient and not recipient.startswith("@"):
            domain = recipient.split("@")[1]
            recipients.append(f"@{domain}")
        recipients.append(recipient)

        # query the database
        try:
            entries = list(
                self.model.select().where(
                    self.model.mailfrom.in_(mailfroms),
                    self.model.recipient.in_(recipients)))
        except Exception as e:
            raise RuntimeError(f"unable to query database: {e}")

        if not entries:
            # no whitelist entry found
            return {}

        if len(entries) > 1:
            entries.sort(key=lambda x: self.get_weight(x), reverse=True)

        # use entry with the highest weight
        entry = entries[0]
        entry.last_used = datetime.now()
        entry.save()
        result = {}
        for entry in entries:
            result.update(self._entry_to_dict(entry))

        return result

    def find(self, mailfrom=None, recipients=None, older_than=None):
        "Find whitelist entries."
        super(DatabaseWhitelist, self).find(mailfrom, recipients, older_than)

        if isinstance(mailfrom, str):
            mailfrom = [mailfrom]
        if isinstance(recipients, str):
            recipients = [recipients]

        entries = {}
        try:
            for entry in list(self.model.select()):
                if older_than is not None:
                    delta = (datetime.now() - entry.last_used).total_seconds()
                    if delta < (older_than * 86400):
                        continue

                if mailfrom is not None:
                    if entry.mailfrom not in mailfrom:
                        continue

                if recipients is not None:
                    if entry.recipient not in recipients:
                        continue

                entries.update(self._entry_to_dict(entry))
        except Exception as e:
            raise RuntimeError(f"unable to query database: {e}")

        return entries

    def add(self, mailfrom, recipient, comment, permanent):
        "Add entry to whitelist."
        super(
            DatabaseWhitelist,
            self).add(
            mailfrom,
            recipient,
            comment,
            permanent)

        try:
            self.model.create(
                mailfrom=mailfrom,
                recipient=recipient,
                comment=comment,
                permanent=permanent)
        except Exception as e:
            raise RuntimeError(f"unable to add entry to database: {e}")

    def delete(self, whitelist_id):
        "Delete entry from whitelist."
        super(DatabaseWhitelist, self).delete(whitelist_id)

        try:
            query = self.model.delete().where(self.model.id == whitelist_id)
            deleted = query.execute()
        except Exception as e:
            raise RuntimeError(
                f"unable to delete entry from database: {e}")

        if deleted == 0:
            raise RuntimeError("invalid whitelist id")


class WhitelistCache(object):
    def __init__(self):
        self.cache = {}

    def load(self, whitelist, mailfrom, recipients):
        for recipient in recipients:
            self.check(whitelist, mailfrom, recipient)

    def check(self, whitelist, mailfrom, recipient):
        if whitelist not in self.cache.keys():
            self.cache[whitelist] = {}
        if recipient not in self.cache[whitelist].keys():
            self.cache[whitelist][recipient] = None
        if self.cache[whitelist][recipient] is None:
            self.cache[whitelist][recipient] = whitelist.check(
                mailfrom, recipient)
        return self.cache[whitelist][recipient]

    def get_recipients(self, whitelist, mailfrom, recipients):
        self.load(whitelist, mailfrom, recipients)
        return list(filter(
            lambda x: self.cache[whitelist][x],
            self.cache[whitelist].keys()))


# list of whitelist types and their related whitelist classes
TYPES = {"db": DatabaseWhitelist}
