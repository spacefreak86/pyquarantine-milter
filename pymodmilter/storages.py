# PyMod-Milter is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# PyMod-Milter is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with PyMod-Milter.  If not, see <http://www.gnu.org/licenses/>.
#

import json
import logging
import os

from calendar import timegm
from datetime import datetime
from glob import glob
from time import gmtime


class BaseMailStorage(object):
    "Mail storage base class"
    def __init__(self):
        return

    def add(self, data, qid, mailfrom="", recipients=[]):
        "Add email to storage."
        return ("", "")

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
        "Return email and metadata."
        return


class FileMailStorage(BaseMailStorage):
    "Storage class to store mails on filesystem."
    def __init__(self, directory, original=False, skip_metadata=False):
        super().__init__()
        self.directory = directory
        self.original = original
        self.skip_metadata = skip_metadata
        self._metadata_suffix = ".metadata"

    def _save_datafile(self, storage_id, data):
        datafile = os.path.join(self.directory, storage_id)
        try:
            with open(datafile, "wb") as f:
                f.write(data)
        except IOError as e:
            raise RuntimeError(f"unable save data file: {e}")

        return datafile

    def _save_metafile(self, storage_id, metadata):
        metafile = os.path.join(
            self.directory, f"{storage_id}{self._metadata_suffix}")
        try:
            with open(metafile, "w") as f:
                json.dump(metadata, f, indent=2)
        except IOError as e:
            raise RuntimeError(f"unable to save metadata file: {e}")

    def _remove(self, storage_id):
        datafile = os.path.join(self.directory, storage_id)
        metafile = f"{datafile}{self._metadata_suffix}"

        try:
            os.remove(metafile)
        except IOError as e:
            raise RuntimeError(f"unable to remove metadata file: {e}")

        try:
            os.remove(datafile)
        except IOError as e:
            raise RuntimeError(f"unable to remove data file: {e}")

    def add(self, data, qid, mailfrom="", recipients=[], subject=""):
        "Add email to file storage and return storage id."
        super().add(data, qid, mailfrom, recipients)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        storage_id = f"{timestamp}_{qid}"

        # save mail
        datafile = self._save_datafile(storage_id, data)

        if not self.skip_metadata:
            # save metadata
            metadata = {
                "mailfrom": mailfrom,
                "recipients": recipients,
                "subject": subject,
                "timestamp": timegm(gmtime()),
                "queue_id": qid}

            try:
                self._save_metafile(storage_id, metadata)
            except RuntimeError as e:
                os.remove(datafile)
                raise e

        return (storage_id, datafile)

    def execute(self, milter, pretend=False,
                logger=logging.getLogger(__name__)):
        if self.original:
            milter.fp.seek(0)
            data = milter.fp.read
            mailfrom = milter.mailfrom
            recipients = list(milter.rcpts)
            subject = ""
        else:
            data = milter.msg.as_bytes
            mailfrom = milter.msginfo["mailfrom"]
            recipients = list(milter.msginfo["rcpts"])
            subject = milter.msg["subject"] or ""

        storage_id, datafile = self.add(
            data(), milter.qid, mailfrom, recipients, subject)
        logger.info(f"stored message in file {datafile}")
        milter.msginfo["storage_id"] = storage_id

    def get_metadata(self, storage_id):
        "Return metadata of email in storage."
        super(FileMailStorage, self).get_metadata(storage_id)

        metafile = os.path.join(
            self.directory, f"{storage_id}{self._metadata_suffix}")
        if not os.path.isfile(metafile):
            raise RuntimeError(
                f"invalid storage id '{storage_id}'")

        try:
            with open(metafile, "r") as f:
                metadata = json.load(f)
        except IOError as e:
            raise RuntimeError(f"unable to read metadata file: {e}")
        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"invalid metafile '{metafile}': {e}")

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
            self.directory, f"*{self._metadata_suffix}"))
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
                elif len(set(recipients + metadata["recipients"])) == \
                        len(recipients + metadata["recipients"]):
                    continue

            emails[storage_id] = metadata

        return emails

    def delete(self, storage_id, recipients=None):
        "Delete email from storage."
        super(FileMailStorage, self).delete(storage_id, recipients)

        try:
            metadata = self.get_metadata(storage_id)
        except RuntimeError as e:
            raise RuntimeError(f"unable to delete email: {e}")

        if not recipients:
            self._remove(storage_id)
        else:
            if type(recipients) == str:
                recipients = [recipients]
            for recipient in recipients:
                if recipient not in metadata["recipients"]:
                    raise RuntimeError(f"invalid recipient '{recipient}'")
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
            raise RuntimeError(f"unable to open email data file: {e}")
        return (fp, metadata)
