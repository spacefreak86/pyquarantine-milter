# pyquarantine is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# pyquarantine is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with pyquarantine.  If not, see <http://www.gnu.org/licenses/>.
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
from email import message_from_bytes
from email.policy import SMTP
from glob import glob
from time import gmtime

from pyquarantine import mailer
from pyquarantine.base import CustomLogger, MilterMessage
from pyquarantine.conditions import Conditions
from pyquarantine.config import ActionConfig
from pyquarantine.notify import Notify


class BaseMailStorage:
    "Mail storage base class"
    _headersonly = True

    def __init__(self, original=False, metadata=False, metavar=None,
                 pretend=False):
        self.original = original
        self.metadata = metadata
        self.metavar = metavar
        self.pretend = False

    def add(self, data, qid, mailfrom, recipients, subject, variables):
        "Add message to storage."
        return ("", "")

    def execute(self, milter, logger):
        return

    def find(self, mailfrom=None, recipients=None, older_than=None):
        "Find messages in storage."
        return

    def get_metadata(self, storage_id):
        "Return metadata of message in storage."
        return

    def delete(self, storage_id, recipients=None):
        "Delete message from storage."
        return

    def get_mail(self, storage_id):
        "Return message and metadata."
        return


class FileMailStorage(BaseMailStorage):
    "Storage class to store mails on filesystem."
    _headersonly = False

    def __init__(self, directory, original=False, metadata=False, metavar=None,
                 mode=None, pretend=False):
        super().__init__(original, metadata, metavar, pretend)
        # check if directory exists and is writable
        if not os.path.isdir(directory) or \
                not os.access(directory, os.R_OK):
            raise RuntimeError(
                f"directory '{directory}' does not exist or is "
                f"not readable")
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
                        os.open(datafile,
                                os.O_CREAT | os.O_WRONLY | os.O_TRUNC,
                                self.mode),
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
                        os.open(metafile,
                                os.O_CREAT | os.O_WRONLY | os.O_TRUNC,
                                self.mode),
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

    def add(self, data, qid, mailfrom, recipients, subject, variables, logger):
        "Add message to file storage and return storage id."
        super().add(data, qid, mailfrom, recipients, subject, variables)

        storage_id = self.get_storageid(qid)
        metafile, datafile = self._get_file_paths(storage_id)

        if self.metavar:
            variables[f"{self.metavar}_ID"] = storage_id
            variables[f"{self.metavar}_DATAFILE"] = datafile
            if self.metadata:
                variables[f"{self.metavar}_METAFILE"] = metafile

        if self.pretend:
            return

        # save mail
        logger.debug(f"save message to {datafile}")
        self._save_datafile(datafile, data)
        logger.info(f"stored message with id {storage_id}")

        if not self.metadata:
            return storage_id, None, datafile

        # save metadata
        metadata = {
            "mailfrom": mailfrom,
            "recipients": recipients,
            "subject": subject,
            "timestamp": timegm(gmtime()),
            "queue_id": qid,
            "vars": variables}

        try:
            logger.debug(f"save metadata to {metafile}")
            self._save_metafile(metafile, metadata)
        except RuntimeError as e:
            os.remove(datafile)
            raise e

    def execute(self, milter, logger):
        if self.original:
            milter.fp.seek(0)
            data = milter.fp.read
            mailfrom = milter.mailfrom
            recipients = list(milter.rcpts)
            # getting the subject is the only operation that needs any
            # parsing of the message, catch all exceptions here
            try:
                subject = milter.msg["subject"] or ""
            except Exception:
                subject = ""
        else:
            data = milter.msg_as_bytes
            mailfrom = milter.msginfo["mailfrom"]
            recipients = list(milter.msginfo["rcpts"])
            subject = milter.msg["subject"] or ""

        self.add(data(), milter.qid, mailfrom, recipients, subject,
                 milter.msginfo["vars"], logger)

    def get_metadata(self, storage_id):
        "Return metadata of message in storage."
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

        # convert metafile structure, this can be removed in the future
        converted = False
        if "subject" not in metadata:
            try:
                metadata["subject"] = metadata["headers"]["subject"]
            except KeyError:
                metadata["subject"] = ""
            converted = True
        if "timestamp" not in metadata:
            try:
                metadata["timestamp"] = metadata["date"]
            except KeyError:
                metadata["timestamp"] = 0
            converted = True
        if "vars" not in metadata:
            try:
                metadata["vars"] = metadata["named_subgroups"]
            except KeyError:
                metadata["vars"] = {}
            converted = True
        if "headers" in metadata:
            del metadata["headers"]
            converted = True
        if "date" in metadata:
            del metadata["date"]
            converted = True
        if "named_subgroups" in metadata:
            del metadata["named_subgroups"]
            converted = True
        if "subgroups" in metadata:
            del metadata["subgroups"]
            converted = True
        if converted:
            self._save_metafile(metafile, metadata)

        return metadata

    def find(self, mailfrom=None, recipients=None, older_than=None):
        "Find messages in storage."
        super().find(mailfrom, recipients, older_than)
        if isinstance(mailfrom, str):
            mailfrom = [mailfrom]
        if isinstance(recipients, str):
            recipients = [recipients]

        if not self.metadata:
            return {}

        msgs = {}
        metafiles = glob(os.path.join(
            self.directory, f"*{self._metadata_suffix}"))
        for metafile in metafiles:
            if not os.path.isfile(metafile):
                continue

            storage_id = os.path.basename(
                metafile[:-len(self._metadata_suffix)])
            metadata = self.get_metadata(storage_id)
            if older_than is not None:
                age = timegm(gmtime()) - metadata["timestamp"]
                if age < (older_than * 86400):
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

            msgs[storage_id] = metadata

        return msgs

    def delete(self, storage_id, recipients=None):
        "Delete message from storage."
        super().delete(storage_id, recipients)
        if not recipients or not self.metadata:
            self._remove(storage_id)
            return

        try:
            metadata = self.get_metadata(storage_id)
        except RuntimeError as e:
            raise RuntimeError(f"unable to delete message: {e}")

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

    def get_mail_bytes(self, storage_id):
        _, datafile = self._get_file_paths(storage_id)
        try:
            with open(datafile, "rb") as fh:
                data = fh.read()
        except IOError as e:
            raise RuntimeError(f"unable to open data file: {e}")
        return data

    def get_mail(self, storage_id):
        super().get_mail(storage_id)

        metadata = self.get_metadata(storage_id)
        msg = message_from_bytes(
            self.get_mail_bytes(storage_id),
            _class=MilterMessage,
            policy=SMTP.clone(refold_source='none'))
        return (metadata, msg)


class Store:
    STORAGE_TYPES = {
        "file": FileMailStorage}

    def __init__(self, cfg, local_addrs, debug):
        self.cfg = cfg
        self.logger = logging.getLogger(cfg["name"])
        self.logger.setLevel(cfg.get_loglevel(debug))

        storage_type = cfg["options"]["type"]
        del cfg["options"]["type"]
        cfg["options"]["pretend"] = cfg["pretend"]
        self._storage = self.STORAGE_TYPES[storage_type](
            **cfg["options"])
        self._headersonly = self._storage._headersonly

    def __str__(self):
        cfg = []
        for key, value in self.cfg["options"].items():
            cfg.append(f"{key}={value}")
        class_name = type(self._storage).__name__
        return f"{class_name}(" + ", ".join(cfg) + ")"

    def get_storage(self):
        return self._storage

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

        storage_cfg = ActionConfig({
            "name": cfg["name"],
            "loglevel": cfg["loglevel"],
            "pretend": cfg["pretend"],
            "type": "store",
            "options": cfg["options"]["store"].get_config()})
        self._storage = Store(storage_cfg, local_addrs, debug)

        self.smtp_host = cfg["options"]["smtp_host"]
        self.smtp_port = cfg["options"]["smtp_port"]

        self._notification = None
        if "notify" in cfg["options"]:
            notify_cfg = ActionConfig({
                "name": cfg["name"],
                "loglevel": cfg["loglevel"],
                "pretend": cfg["pretend"],
                "type": "notify",
                "options": cfg["options"]["notify"].get_config()})
            self._notification = Notify(notify_cfg, local_addrs, debug)

        self._whitelist = None
        if "whitelist" in cfg["options"]:
            whitelist_cfg = cfg["options"]["whitelist"]
            whitelist_cfg["name"] = cfg["name"]
            whitelist_cfg["loglevel"] = cfg["loglevel"]
            self._whitelist = Conditions(
                whitelist_cfg,
                local_addrs=[],
                debug=debug)

        self._milter_action = None
        if "milter_action" in cfg["options"]:
            self._milter_action = cfg["options"]["milter_action"].upper()
            assert self._milter_action in ["ACCEPT", "REJECT", "DISCARD"], \
                f"invalid milter_action '{cfg['args']['milter_action']}'"

        self._reason = None
        if self._milter_action == "REJECT":
            if "reject_reason" in cfg["options"]:
                self._reason = cfg["options"]["reject_reason"]
            else:
                self._reason = "Message rejected"

    def __str__(self):
        cfg = []
        cfg.append(f"store={str(self._storage)}")
        if self._notification is not None:
            cfg.append(f"notify={str(self._notification)}")
        if self._whitelist is not None:
            cfg.append(f"whitelist={str(self._whitelist)}")
        for key in ["milter_action", "reject_reason"]:
            if key not in self.cfg["options"]:
                continue
            value = self.cfg["options"][key]
            cfg.append(f"{key}={value}")
        class_name = type(self).__name__
        return f"{class_name}(" + ", ".join(cfg) + ")"

    @property
    def name(self):
        return self.cfg["name"]

    @property
    def storage(self):
        return self._storage.get_storage()

    @property
    def notification(self):
        if self._notification is None:
            return None
        return self._notification.get_notification()

    @property
    def whitelist(self):
        if self._whitelist is None:
            return None
        return self._whitelist.get_whitelist()

    @property
    def milter_action(self):
        return self._milter_action

    def notify(self, storage_id, recipient=None):
        "Notify recipient about message in storage."
        if not self._notification:
            raise RuntimeError(
                "notification not defined, "
                "unable to send notification")
        metadata, msg = self.storage.get_mail(storage_id)

        if recipient is not None:
            if recipient not in metadata["recipients"]:
                raise RuntimeError(f"invalid recipient '{recipient}'")
            recipients = [recipient]
        else:
            recipients = metadata["recipients"]

        self.notification.notify(msg, metadata["queue_id"],
                                 metadata["mailfrom"], recipients,
                                 self.logger, metadata["vars"],
                                 synchronous=True)

    def release(self, storage_id, recipients=None):
        metadata, msg = self.storage.get_mail(storage_id)
        if recipients and type(recipients) == str:
            recipients = [recipients]
        else:
            recipients = metadata["recipients"]

        for recipient in recipients:
            if recipient not in metadata["recipients"]:
                raise RuntimeError(f"invalid recipient '{recipient}'")
            try:
                mailer.smtp_send(
                    self.smtp_host,
                    self.smtp_port,
                    metadata["mailfrom"],
                    recipient,
                    msg.as_string())

            except Exception as e:
                raise RuntimeError(
                    f"error while sending message to '{recipient}': {e}")
            self.storage.delete(storage_id, recipient)

        return recipients

    def execute(self, milter):
        logger = CustomLogger(
            self.logger, {"name": self.cfg["name"], "qid": milter.qid})
        rcpts = milter.msginfo["rcpts"]
        wl_rcpts = []
        if self._whitelist:
            wl_rcpts = self._whitelist.get_wl_rcpts(
                milter.msginfo["mailfrom"], rcpts, logger)
            if wl_rcpts:
                logger.info(f"whitelisted recipients: {wl_rcpts}")
            rcpts = [rcpt for rcpt in rcpts if rcpt not in wl_rcpts]
            if not rcpts:
                # all recipients whitelisted
                return
            milter.msginfo["rcpts"] = rcpts.copy()

        if self._milter_action in ["REJECT", "DISCARD"]:
            logger.info(f"quarantine message for {rcpts}")

        self._storage.execute(milter)

        if self._notification is not None:
            self._notification.execute(milter)

        milter.msginfo["rcpts"].extend(wl_rcpts)

        if self._milter_action is not None:
            milter.delrcpt(rcpts)
            if not milter.msginfo["rcpts"]:
                return (self._milter_action, self._reason)
