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
import json
import logging
import os

from shutil import copyfileobj



class BaseQuarantine(object):
    "Quarantine base class"
    def __init__(self, name, config, configtest=False):
        self.name = name
        self.config = config[name]
        self.global_config = config["global"]
        self.logger = logging.getLogger(__name__)

    def add(self, queueid, mailfrom, recipients, fp):
        "Add mail to quarantine."
        return ""



class FileQuarantine(BaseQuarantine):
    "Quarantine class to store mails on filesystem."
    def __init__(self, name, config, configtest=False):
        super(FileQuarantine, self).__init__(name, config, configtest)
        # check if mandatory options are present in config
        for option in ["directory"]:
            if option not in self.config.keys() and option in self.global_config.keys():
                self.config[option] = self.global_config[option]
            if option not in self.config.keys():
                raise RuntimeError("mandatory option '{}' not present in config section '{}' or 'global'".format(option, self.name))
        self.directory = self.config["directory"]
        # check if quarantine directory exists and is writable
        if not os.path.isdir(self.directory) or not os.access(self.directory, os.W_OK):
            raise RuntimeError("file quarantine directory '{}' does not exist or is not writable".format(self.directory))

    def add(self, queueid, mailfrom, recipients, fp):
        "Add mail to file quarantine and return quarantine-id."
        super(FileQuarantine, self).add(queueid, mailfrom, recipients, fp)
        quarantine_id = "{}_{}".format(datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S"), queueid)
        # save mail
        with open(os.path.join(self.directory, quarantine_id), "wb") as f:
            copyfileobj(fp, f)
        # save metadata
        metadata = {
            "from": mailfrom,
            "recipients": recipients
        }
        with open(os.path.join(self.directory, "{}.metadata".format(quarantine_id)), "wb") as f:
            json.dump(metadata, f, indent=2)
        return quarantine_id



# list of quarantine types and their related quarantine classes
quarantine_types = {"file": FileQuarantine}
