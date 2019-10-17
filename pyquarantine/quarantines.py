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

from pyquarantine import mailer


class BaseQuarantine(object):
    "Quarantine base class"

    def __init__(self, global_config, config, configtest=False):
        self.name = config["name"]
        self.global_config = global_config
        self.config = config
        self.logger = logging.getLogger(__name__)

    def add(self, queueid, mailfrom, recipients, headers,
            fp, subgroups=None, named_subgroups=None):
        "Add email to quarantine."
        fp.seek(0)
        return ""

    def find(self, mailfrom=None, recipients=None, older_than=None):
        "Find emails in quarantine."
        return

    def get_metadata(self, quarantine_id):
        "Return metadata of quarantined email."
        return

    def delete(self, quarantine_id, recipient=None):
        "Delete email from quarantine."
        return

    def notify(self, quarantine_id, recipient=None):
        "Notify recipient about email in quarantine."
        if not self.config["notification_obj"]:
            raise RuntimeError(
                "notification type is set to None, unable to send notifications")
        return

    def release(self, quarantine_id, recipient=None):
        "Release email from quarantine."
        return


class FileQuarantine(BaseQuarantine):
    "Quarantine class to store mails on filesystem."

    def __init__(self, global_config, config, configtest=False):
        super(FileQuarantine, self).__init__(global_config, config, configtest)

        # check if mandatory options are present in config
        for option in ["quarantine_directory"]:
            if option not in self.config.keys() and option in self.global_config.keys():
                self.config[option] = self.global_config[option]
            if option not in self.config.keys():
                raise RuntimeError(
                    "mandatory option '{}' not present in config section '{}' or 'global'".format(
                        option, self.name))
        self.directory = self.config["quarantine_directory"]

        # check if quarantine directory exists and is writable
        if not os.path.isdir(self.directory) or not os.access(
                self.directory, os.W_OK):
            raise RuntimeError(
                "file quarantine directory '{}' does not exist or is not writable".format(
                    self.directory))
        self._metadata_suffix = ".metadata"

    def _save_datafile(self, quarantine_id, fp):
        datafile = os.path.join(self.directory, quarantine_id)
        try:
            with open(datafile, "wb") as f:
                copyfileobj(fp, f)
        except IOError as e:
            raise RuntimeError("unable save data file: {}".format(e))

    def _save_metafile(self, quarantine_id, metadata):
        metafile = os.path.join(
            self.directory, "{}{}".format(
                quarantine_id, self._metadata_suffix))
        try:
            with open(metafile, "w") as f:
                json.dump(metadata, f, indent=2)
        except IOError as e:
            raise RuntimeError("unable to save metadata file: {}".format(e))

    def _remove(self, quarantine_id):
        datafile = os.path.join(self.directory, quarantine_id)
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
        "Add email to file quarantine and return quarantine-id."
        super(
            FileQuarantine,
            self).add(
            queueid,
            mailfrom,
            recipients,
            headers,
            fp,
            subgroups,
            named_subgroups)
        quarantine_id = "{}_{}".format(
            datetime.now().strftime("%Y%m%d%H%M%S"), queueid)

        # save mail
        self._save_datafile(quarantine_id, fp)

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
            self._save_metafile(quarantine_id, metadata)
        except RuntimeError as e:
            datafile = os.path.join(self.directory, quarantine_id)
            os.remove(datafile)
            raise e

        return quarantine_id

    def get_metadata(self, quarantine_id):
        "Return metadata of quarantined email."
        super(FileQuarantine, self).get_metadata(quarantine_id)

        metafile = os.path.join(
            self.directory, "{}{}".format(
                quarantine_id, self._metadata_suffix))
        if not os.path.isfile(metafile):
            raise RuntimeError(
                "invalid quarantine id '{}'".format(quarantine_id))

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
        "Find emails in quarantine."
        super(FileQuarantine, self).find(mailfrom, recipients, older_than)
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

            quarantine_id = os.path.basename(
                metafile[:-len(self._metadata_suffix)])
            metadata = self.get_metadata(quarantine_id)
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

            emails[quarantine_id] = metadata

        return emails

    def delete(self, quarantine_id, recipient=None):
        "Delete email in quarantine."
        super(FileQuarantine, self).delete(quarantine_id, recipient)

        try:
            metadata = self.get_metadata(quarantine_id)
        except RuntimeError as e:
            raise RuntimeError("unable to delete email: {}".format(e))

        if recipient is None:
            self._remove(quarantine_id)
        else:
            if recipient not in metadata["recipients"]:
                raise RuntimeError("invalid recipient '{}'".format(recipient))

            metadata["recipients"].remove(recipient)
            if not metadata["recipients"]:
                self._remove(quarantine_id)
            else:
                self._save_metafile(quarantine_id, metadata)

    def notify(self, quarantine_id, recipient=None):
        "Notify recipient about email in quarantine."
        super(FileQuarantine, self).notify(quarantine_id, recipient)

        try:
            metadata = self.get_metadata(quarantine_id)
        except RuntimeError as e:
            raise RuntimeError("unable to release email: {}".format(e))

        if recipient is not None:
            if recipient not in metadata["recipients"]:
                raise RuntimeError("invalid recipient '{}'".format(recipient))
            recipients = [recipient]
        else:
            recipients = metadata["recipients"]

        datafile = os.path.join(self.directory, quarantine_id)
        try:
            with open(datafile, "rb") as fp:
                self.config["notification_obj"].notify(
                    metadata["queue_id"], quarantine_id, metadata["mailfrom"],
                    recipients, metadata["headers"], fp,
                    metadata["subgroups"], metadata["named_subgroups"],
                    synchronous=True)
        except IOError as e:
            raise RuntimeError

    def release(self, quarantine_id, recipient=None):
        "Release email from quarantine."
        super(FileQuarantine, self).release(quarantine_id, recipient)

        try:
            metadata = self.get_metadata(quarantine_id)
        except RuntimeError as e:
            raise RuntimeError("unable to release email: {}".format(e))

        if recipient is not None:
            if recipient not in metadata["recipients"]:
                raise RuntimeError("invalid recipient '{}'".format(recipient))
            recipients = [recipient]
        else:
            recipients = metadata["recipients"]

        datafile = os.path.join(self.directory, quarantine_id)
        try:
            with open(datafile, "rb") as f:
                mail = f.read()
        except IOError as e:
            raise RuntimeError("unable to read data file: {}".format(e))

        for recipient in recipients:
            try:
                mailer.smtp_send(
                    self.config["smtp_host"],
                    self.config["smtp_port"],
                    metadata["mailfrom"],
                    recipient,
                    mail)
            except Exception as e:
                raise RuntimeError(
                    "error while sending email to '{}': {}".format(
                        recipient, e))

            self.delete(quarantine_id, recipient)


# list of quarantine types and their related quarantine classes
TYPES = {"file": FileQuarantine}
