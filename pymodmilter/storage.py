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

__all__ = [
    "BaseMailStorage",
    "FileMailStorage",
    "Store",
    "Quarantine"]

import json
import logging
import os

from calendar import timegm
from datetime import datetime
from glob import glob
from time import gmtime

from pymodmilter.base import CustomLogger
from pymodmilter.conditions import Conditions
from pymodmilter.config import ActionConfig
from pymodmilter.notify import Notify


class BaseMailStorage:
    "Mail storage base class"
    _headersonly = True

    def __init__(self, original=False, metadata=False, metavar=None,
                 pretend=False):
        self.original = original
        self.metadata = metadata
        self.metavar = metavar
        self.pretend = False

    def add(self, data, qid, mailfrom="", recipients=[]):
        "Add email to storage."
        return ("", "")

    def execute(self, milter, logger):
        return

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
    _headersonly = False

    def __init__(self, directory, original=False, metadata=False, metavar=None,
                 mode=None, pretend=False):
        super().__init__(original, metadata, metavar, pretend)
        # check if directory exists and is writable
        if not os.path.isdir(directory) or \
                not os.access(directory, os.W_OK):
            raise RuntimeError(
                f"directory '{directory}' does not exist or is "
                f"not writable")
        self.directory = directory
        try:
            self.mode = int(mode, 8) if mode is not None else None
            if self.mode is not None and self.mode > 511:
                raise ValueError
        except ValueError:
            raise RuntimeError(f"invalid mode '{mode}'")

        self._metadata_suffix = ".metadata"

    def __str__(self):
        cfg = []
        cfg.append(f"metadata={self.metadata}")
        cfg.append(f"metavar={self.metavar}")
        cfg.append(f"pretend={self.pretend}")
        cfg.append(f"directory={self.directory}")
        cfg.append(f"original={self.original}")
        return "FileMailStorage(" + ", ".join(cfg) + ")"

    def get_storageid(self, qid):
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        return f"{timestamp}_{qid}"

    def _get_file_paths(self, storage_id):
        datafile = os.path.join(self.directory, storage_id)
        metafile = f"{datafile}{self._metadata_suffix}"
        return metafile, datafile

    def _save_datafile(self, datafile, data):
        try:
            if self.mode is None:
                with open(datafile, "wb") as f:
                    f.write(data)
            else:
                umask = os.umask(0)
                with open(
                        os.open(datafile, os.O_CREAT | os.O_WRONLY, self.mode),
                        "wb") as f:
                    f.write(data)
                os.umask(umask)

        except IOError as e:
            raise RuntimeError(f"unable save data file: {e}")

    def _save_metafile(self, metafile, metadata):
        try:
            if self.mode is None:
                with open(metafile, "w") as f:
                    json.dump(metadata, f, indent=2)
            else:
                umask = os.umask(0)
                with open(
                        os.open(metafile, os.O_CREAT | os.O_WRONLY, self.mode),
                        "w") as f:
                    json.dump(metadata, f, indent=2)
                os.umask(umask)

        except IOError as e:
            raise RuntimeError(f"unable to save metadata file: {e}")

    def _remove(self, storage_id):
        metafile, datafile = self._get_file_paths(storage_id)

        try:
            if self.metadata:
                os.remove(metafile)

            os.remove(datafile)
        except IOError as e:
            raise RuntimeError(f"unable to remove file: {e}")

    def add(self, data, qid, mailfrom="", recipients=[], subject=""):
        "Add email to file storage and return storage id."
        super().add(data, qid, mailfrom, recipients)

        storage_id = self.get_storageid(qid)
        metafile, datafile = self._get_file_paths(storage_id)

        # save mail
        self._save_datafile(datafile, data)

        if not self.metadata:
            return storage_id, None, datafile

        # save metadata
        metadata = {
            "mailfrom": mailfrom,
            "recipients": recipients,
            "subject": subject,
            "timestamp": timegm(gmtime()),
            "queue_id": qid}

        try:
            self._save_metafile(metafile, metadata)
        except RuntimeError as e:
            os.remove(datafile)
            raise e

        return storage_id, metafile, datafile

    def execute(self, milter, logger):
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

        if not self.pretend:
            storage_id, metafile, datafile = self.add(
                data(), milter.qid, mailfrom, recipients, subject)
            logger.info(f"stored message in file {datafile}")
        else:
            storage_id = self.get_storageid(milter.qid)
            metafile, datafile = self._get_file_paths(storage_id)

        if self.metavar:
            milter.msginfo["vars"][f"{self.metavar}_ID"] = storage_id
            milter.msginfo["vars"][f"{self.metavar}_DATAFILE"] = datafile
            if self.metadata:
                milter.msginfo["vars"][f"{self.metavar}_METAFILE"] = metafile

    def get_metadata(self, storage_id):
        "Return metadata of email in storage."
        super().get_metadata(storage_id)

        if not self.metadata:
            return None

        metafile, _ = self._get_file_paths(storage_id)
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
        super().find(mailfrom, recipients, older_than)
        if isinstance(mailfrom, str):
            mailfrom = [mailfrom]
        if isinstance(recipients, str):
            recipients = [recipients]

        if not self.metadata:
            return {}

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
        super().delete(storage_id, recipients)

        if not recipients or not self.metadata:
            self._remove(storage_id)
            return

        try:
            metadata = self.get_metadata(storage_id)
        except RuntimeError as e:
            raise RuntimeError(f"unable to delete email: {e}")

        metafile, _ = self._get_file_paths(storage_id)

        if type(recipients) == str:
            recipients = [recipients]

        for recipient in recipients:
            if recipient not in metadata["recipients"]:
                raise RuntimeError(f"invalid recipient '{recipient}'")
            metadata["recipients"].remove(recipient)
            if not metadata["recipients"]:
                self._remove(storage_id)
            else:
                self._save_metafile(metafile, metadata)

    def get_mail(self, storage_id):
        super().get_mail(storage_id)

        metadata = self.get_metadata(storage_id)
        _, datafile = self._get_file_paths(storage_id)
        try:
            data = open(datafile, "rb").read()
        except IOError as e:
            raise RuntimeError(f"unable to open email data file: {e}")
        return (metadata, data)


class Store:
    STORAGE_TYPES = {
        "file": FileMailStorage}

    def __init__(self, cfg, local_addrs, debug):
        self.cfg = cfg
        self.logger = logging.getLogger(cfg["name"])
        self.logger.setLevel(cfg.get_loglevel(debug))

        storage_type = cfg["args"]["type"]
        del cfg["args"]["type"]
        cfg["args"]["pretend"] = cfg["pretend"]
        self._storage = self.STORAGE_TYPES[storage_type](
            **cfg["args"])
        self._headersonly = self._storage._headersonly

    def __str__(self):
        cfg = []
        for key, value in self.cfg["args"].items():
            cfg.append(f"{key}={value}")
        class_name = type(self._storage).__name__
        return f"{class_name}(" + ", ".join(cfg) + ")"

    def execute(self, milter):
        logger = CustomLogger(
            self.logger, {"name": self.cfg["name"], "qid": milter.qid})
        self._storage.execute(milter, logger)


class Quarantine:
    "Quarantine class."
    _headersonly = False

    def __init__(self, cfg, local_addrs, debug):
        self.cfg = cfg
        self.logger = logging.getLogger(cfg["name"])
        self.logger.setLevel(cfg.get_loglevel(debug))

        store_cfg = ActionConfig({
            "name": cfg["name"],
            "loglevel": cfg["loglevel"],
            "pretend": cfg["pretend"],
            "type": "store",
            "args": cfg["args"]["store"].get_config()})
        store_cfg["args"]["metadata"] = True
        self.store = Store(store_cfg, local_addrs, debug)

        self.notify = None
        if "notify" in cfg["args"]:
            notify_cfg = ActionConfig({
                "name": cfg["name"],
                "loglevel": cfg["loglevel"],
                "pretend": cfg["pretend"],
                "type": "notify",
                "args": cfg["args"]["notify"].get_config()})
            self.notify = Notify(notify_cfg, local_addrs, debug)

        self.whitelist = None
        if "whitelist" in cfg["args"]:
            whitelist_cfg = cfg["args"]["whitelist"]
            whitelist_cfg["name"] = cfg["name"]
            whitelist_cfg["loglevel"] = cfg["loglevel"]
            self.whitelist = Conditions(
                whitelist_cfg,
                local_addrs=[],
                debug=debug)

        self.milter_action = None
        if "milter_action" in cfg["args"]:
            self.milter_action = cfg["args"]["milter_action"]
        self.reject_reason = None
        if "reject_reason" in cfg["args"]:
            self.reject_reason = cfg["args"]["reject_reason"]

    def __str__(self):
        cfg = []
        cfg.append(f"store={str(self.store)}")
        if self.notify is not None:
            cfg.append(f"notify={str(self.notify)}")
        if self.whitelist is not None:
            cfg.append(f"whitelist={str(self.whitelist)}")
        for key in ["milter_action", "reject_reason"]:
            if key not in self.cfg["args"]:
                continue
            value = self.cfg["args"][key]
            cfg.append(f"{key}={value}")
        class_name = type(self).__name__
        return f"{class_name}(" + ", ".join(cfg) + ")"

    def execute(self, milter):
        logger = CustomLogger(
            self.logger, {"name": self.cfg["name"], "qid": milter.qid})
        wl_rcpts = []
        if self.whitelist:
            wl_rcpts = self.whitelist.get_wl_rcpts(
                milter.msginfo["mailfrom"], milter.msginfo["rcpts"], logger)
            logger.info(f"whitelisted recipients: {wl_rcpts}")

        rcpts = [
            rcpt for rcpt in milter.msginfo["rcpts"] if rcpt not in wl_rcpts]

        if not rcpts:
            # all recipients whitelisted
            return

        logger.info(f"add to quarantine for recipients: {rcpts}")
        milter.msginfo["rcpts"] = rcpts

        self.store.execute(milter)

        if self.notify is not None:
            self.notify.execute(milter)

        milter.msginfo["rcpts"].extend(wl_rcpts)
        milter.delrcpt(rcpts)

        if self.milter_action is not None and not milter.msginfo["rcpts"]:
            return (self.milter_action, self.reject_reason)
