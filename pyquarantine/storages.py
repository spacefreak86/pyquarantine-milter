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

import json
import logging
import os

from calendar import timegm
from datetime import datetime
from glob import glob
from shutil import copyfileobj
from time import gmtime


class BaseMailStorage(object):
    "Mail storage base class"
    storage_type = "base"

    def __init__(self, name, global_cfg, cfg, test=False):
        self.name = name
        self.logger = logging.getLogger(__name__)

    def add(self, queueid, mailfrom, recipients, headers,
            fp, subgroups=None, named_subgroups=None):
        "Add email to storage."
        fp.seek(0)
        return ""

    def find(self, mailfrom=None, recipients=None, older_than=None):
        "Find emails in storage."
        return

    def get_metadata(self, storage_id):
        "Return metadata of email in storage."
        return

    def delete(self, storage_id, recipients=None):
        "Delete email from storage."
        return

    def get_mail(self, storage_id):
        "Return a file pointer to the email and metadata."
        return


class FileMailStorage(BaseMailStorage):
    "Storage class to store mails on filesystem."
    storage_type = "file"

    def __init__(self, name, global_cfg, cfg, test=False):
        super(FileMailStorage, self).__init__(name, global_cfg, cfg, test)

        defaults = {}
        # check config

        for opt in ["storage_directory"] + list(defaults.keys()):
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
        self.directory = cfg["storage_directory"]

        # check if quarantine directory exists and is writable
        if not os.path.isdir(self.directory) or not os.access(
                self.directory, os.W_OK):
            raise RuntimeError(
                "file quarantine directory '{}' does not exist or is not writable".format(
                    self.directory))
        self._metadata_suffix = ".metadata"

    def _save_datafile(self, storage_id, fp):
        datafile = os.path.join(self.directory, storage_id)
        try:
            with open(datafile, "wb") as f:
                copyfileobj(fp, f)
        except IOError as e:
            raise RuntimeError("unable save data file: {}".format(e))

    def _save_metafile(self, storage_id, metadata):
        metafile = os.path.join(
            self.directory, "{}{}".format(
                storage_id, self._metadata_suffix))
        try:
            with open(metafile, "w") as f:
                json.dump(metadata, f, indent=2)
        except IOError as e:
            raise RuntimeError("unable to save metadata file: {}".format(e))

    def _remove(self, storage_id):
        datafile = os.path.join(self.directory, storage_id)
        metafile = "{}{}".format(datafile, self._metadata_suffix)

        try:
            os.remove(metafile)
        except IOError as e:
            raise RuntimeError("unable to remove metadata file: {}".format(e))

        try:
            os.remove(datafile)
        except IOError as e:
            raise RuntimeError("unable to remove data file: {}".format(e))

    def add(self, queueid, mailfrom, recipients, headers,
            fp, subgroups=None, named_subgroups=None):
        "Add email to file storage and return storage id."
        super(
            FileMailStorage,
            self).add(
            queueid,
            mailfrom,
            recipients,
            headers,
            fp,
            subgroups,
            named_subgroups)
        storage_id = "{}_{}".format(
            datetime.now().strftime("%Y%m%d%H%M%S"), queueid)

        # save mail
        self._save_datafile(storage_id, fp)

        # save metadata
        metadata = {
            "mailfrom": mailfrom,
            "recipients": recipients,
            "headers": headers,
            "date": timegm(gmtime()),
            "queue_id": queueid,
            "subgroups": subgroups,
            "named_subgroups": named_subgroups
        }
        try:
            self._save_metafile(storage_id, metadata)
        except RuntimeError as e:
            datafile = os.path.join(self.directory, storage_id)
            os.remove(datafile)
            raise e

        return storage_id

    def get_metadata(self, storage_id):
        "Return metadata of email in storage."
        super(FileMailStorage, self).get_metadata(storage_id)

        metafile = os.path.join(
            self.directory, "{}{}".format(
                storage_id, self._metadata_suffix))
        if not os.path.isfile(metafile):
            raise RuntimeError(
                "invalid storage id '{}'".format(storage_id))

        try:
            with open(metafile, "r") as f:
                metadata = json.load(f)
        except IOError as e:
            raise RuntimeError("unable to read metadata file: {}".format(e))
        except json.JSONDecodeError as e:
            raise RuntimeError(
                "invalid meta file '{}': {}".format(
                    metafile, e))

        return metadata

    def find(self, mailfrom=None, recipients=None, older_than=None):
        "Find emails in storage."
        super(FileMailStorage, self).find(mailfrom, recipients, older_than)
        if isinstance(mailfrom, str):
            mailfrom = [mailfrom]
        if isinstance(recipients, str):
            recipients = [recipients]

        emails = {}
        metafiles = glob(os.path.join(
            self.directory, "*{}".format(self._metadata_suffix)))
        for metafile in metafiles:
            if not os.path.isfile(metafile):
                continue

            storage_id = os.path.basename(
                metafile[:-len(self._metadata_suffix)])
            metadata = self.get_metadata(storage_id)
            if older_than is not None:
                if timegm(gmtime()) - metadata["date"] < (older_than * 86400):
                    continue

            if mailfrom is not None:
                if metadata["mailfrom"] not in mailfrom:
                    continue

            if recipients is not None:
                if len(recipients) == 1 and \
                        recipients[0] not in metadata["recipients"]:
                    continue
                elif len(set(recipients + metadata["recipients"])) == len(recipients + metadata["recipients"]):
                    continue

            emails[storage_id] = metadata

        return emails

    def delete(self, storage_id, recipients=None):
        "Delete email from storage."
        super(FileMailStorage, self).delete(storage_id, recipients)

        try:
            metadata = self.get_metadata(storage_id)
        except RuntimeError as e:
            raise RuntimeError("unable to delete email: {}".format(e))

        if not recipients:
            self._remove(storage_id)
        else:
            if type(recipients) == str:
                recipients = [recipients]
            for recipient in recipients:
                if recipient not in metadata["recipients"]:
                    raise RuntimeError("invalid recipient '{}'".format(recipient))
                metadata["recipients"].remove(recipient)
                if not metadata["recipients"]:
                    self._remove(storage_id)
                else:
                    self._save_metafile(storage_id, metadata)

    def get_mail(self, storage_id):
        super(FileMailStorage, self).get_mail(storage_id)

        metadata = self.get_metadata(storage_id)
        datafile = os.path.join(self.directory, storage_id)
        try:
            fp = open(datafile, "rb")
        except IOError as e:
            raise RuntimeError("unable to open email data file: {}".format(e))
        return (fp, metadata)


# list of storage types and their related storage classes
TYPES = {"file": FileMailStorage}
