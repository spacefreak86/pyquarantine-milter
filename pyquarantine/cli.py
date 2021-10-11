#!/usr/bin/env python
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

import argparse
import json
import logging
import logging.handlers
import sys
import time

from pyquarantine.config import get_milter_config, ActionConfig
from pyquarantine.storage import Quarantine
from pyquarantine import __version__ as version


def _get_quarantine(quarantines, name, debug):
    try:
        quarantine = next((q for q in quarantines if q["name"] == name))
    except StopIteration:
        raise RuntimeError(f"invalid quarantine '{name}'")
    return Quarantine(ActionConfig(quarantine), [], debug)


def _get_notification(quarantines, name, debug):
    notification = _get_quarantine(quarantines, name, debug).notification
    if not notification:
        raise RuntimeError(
                "notification type is set to NONE")
    return notification


def _get_whitelist(quarantines, name, debug):
    whitelist = _get_quarantine(quarantines, name, debug).whitelist
    if not whitelist:
        raise RuntimeError(
                "whitelist type is set to NONE")
    return whitelist


def print_table(columns, rows):
    if not rows:
        return

    column_lengths = []
    column_formats = []

    # iterate columns to display
    for header, key in columns:
        # get the length of the header string
        lengths = [len(header)]
        # get the length of the longest value
        lengths.append(
            len(str(max(rows, key=lambda x: len(str(x[key])))[key])))
        # use the longer one
        length = max(lengths)
        column_lengths.append(length)
        column_formats.append(f"{{:<{length}}}")

    # define row format
    row_format = " | ".join(column_formats)

    # define header/body separator
    separators = []
    for length in column_lengths:
        separators.append("-" * length)
    separator = "-+-".join(separators)

    # print header and separator
    print(row_format.format(*[column[0] for column in columns]))
    print(separator)

    keys = [entry[1] for entry in columns]
    # print rows
    for entry in rows:
        row = []
        for key in keys:
            row.append(entry[key])
        print(row_format.format(*row))


def list_quarantines(quarantines, args):
    if args.batch:
        print("\n".join([q["name"] for q in quarantines]))
    else:
        qlist = []
        for q in quarantines:
            cfg = q["options"]
            storage_type = cfg["store"]["type"]

            if "notify" in cfg:
                notification_type = cfg["notify"]["type"]
            else:
                notification_type = "NONE"

            if "whitelist" in cfg:
                whitelist_type = cfg["whitelist"]["type"]
            else:
                whitelist_type = "NONE"

            if "milter_action" in cfg:
                milter_action = cfg["milter_action"]
            else:
                milter_action = "NONE"

            qlist.append({
                "name": q["name"],
                "storage": storage_type,
                "notification": notification_type,
                "whitelist": whitelist_type,
                "action": milter_action})

        print_table(
            [("Name", "name"),
             ("Storage", "storage"),
             ("Notification", "notification"),
             ("Whitelist", "whitelist"),
             ("Action", "action")],
            qlist
        )


def list_quarantine_emails(quarantines, args):
    storage = _get_quarantine(quarantines, args.quarantine, args.debug).storage

    # find emails and transform some metadata values to strings
    rows = []
    emails = storage.find(
        args.mailfrom, args.recipients, args.older_than)
    for storage_id, metadata in emails.items():
        row = emails[storage_id]
        row["storage_id"] = storage_id
        row["timestamp"] = time.strftime(
            '%Y-%m-%d %H:%M:%S',
            time.localtime(
                metadata["timestamp"]))
        row["mailfrom"] = metadata["mailfrom"]
        row["recipient"] = metadata["recipients"].pop(0)
        if "subject" not in emails[storage_id]:
            emails[storage_id]["subject"] = ""
        row["subject"] = emails[storage_id]["subject"][:60].strip()
        rows.append(row)

        if metadata["recipients"]:
            row = {
                "storage_id": "",
                "timestamp": "",
                "mailfrom": "",
                "recipient": metadata["recipients"].pop(0),
                "subject": ""
            }
            rows.append(row)

    if args.batch:
        # batch mode, print quarantine IDs, each on a new line
        print("\n".join(emails.keys()))
        return

    if not emails:
        print(f"quarantine '{args.quarantine}' is empty")
        return

    print_table(
        [("Quarantine-ID", "storage_id"), ("When", "timestamp"),
         ("From", "mailfrom"), ("Recipient(s)", "recipient"),
         ("Subject", "subject")],
        rows
    )


def list_whitelist(quarantines, args):
    whitelist = _get_whitelist(quarantines, args.quarantine, args.debug)

    # find whitelist entries
    entries = whitelist.find(
        mailfrom=args.mailfrom,
        recipients=args.recipients,
        older_than=args.older_than)
    if not entries:
        print(f"whitelist of quarantine '{args.quarantine}' is empty")
        return

    # transform some values to strings
    for eid, entry in entries.items():
        entries[eid]["permanent_str"] = str(entry["permanent"])
        entries[eid]["created_str"] = entry["created"].strftime(
            '%Y-%m-%d %H:%M:%S')
        entries[eid]["last_used_str"] = entry["last_used"].strftime(
            '%Y-%m-%d %H:%M:%S')

    print_table(
        [
            ("ID", "id"), ("From", "mailfrom"), ("To", "recipient"),
            ("Created", "created_str"), ("Last used", "last_used_str"),
            ("Comment", "comment"), ("Permanent", "permanent_str")
        ],
        entries.values()
    )


def add_whitelist_entry(quarantines, args):
    logger = logging.getLogger(__name__)
    whitelist = _get_whitelist(quarantines, args.quarantine, args.debug)

    # check existing entries
    entries = whitelist.check(args.mailfrom, args.recipient, logger)
    if entries:
        # check if the exact entry exists already
        for entry in entries.values():
            if entry["mailfrom"] == args.mailfrom and \
                    entry["recipient"] == args.recipient:
                raise RuntimeError(
                    "an entry with this from/to combination already exists")

        if not args.force:
            # the entry is already covered by others
            for eid, entry in entries.items():
                entries[eid]["permanent_str"] = str(entry["permanent"])
                entries[eid]["created_str"] = entry["created"].strftime(
                    '%Y-%m-%d %H:%M:%S')
                entries[eid]["last_used_str"] = entry["last_used"].strftime(
                    '%Y-%m-%d %H:%M:%S')
            print_table(
                [
                    ("ID", "id"), ("From", "mailfrom"), ("To", "recipient"),
                    ("Created", "created_str"), ("Last used", "last_used_str"),
                    ("Comment", "comment"), ("Permanent", "permanent_str")
                ],
                entries.values()
            )
            print("")
            raise RuntimeError(
                "from/to combination is already covered by the entries above, "
                "use --force to override.")

    # add entry to whitelist
    whitelist.add(args.mailfrom, args.recipient, args.comment, args.permanent)
    print("whitelist entry added successfully")


def delete_whitelist_entry(quarantines, args):
    whitelist = _get_whitelist(quarantines, args.quarantine, args.debug)
    whitelist.delete(args.whitelist_id)
    print("whitelist entry deleted successfully")


def notify(quarantines, args):
    quarantine = _get_quarantine(quarantines, args.quarantine, args.debug)
    quarantine.notify(args.quarantine_id, args.recipient)
    print("notification sent successfully")


def release(quarantines, args):
    logger = logging.getLogger(__name__)
    quarantine = _get_quarantine(quarantines, args.quarantine, args.debug)
    rcpts = quarantine.release(args.quarantine_id, args.recipient)
    rcpts = ", ".join(rcpts)
    logger.info(
        f"{args.quarantine}: released message with id {args.quarantine_id} "
        f"for {rcpts}")


def delete(quarantines, args):
    storage = _get_quarantine(quarantines, args.quarantine, args.debug).storage
    storage.delete(args.quarantine_id, args.recipient)
    print("quarantined message deleted successfully")


def get(quarantines, args):
    storage = _get_quarantine(quarantines, args.quarantine, args.debug).storage
    data = storage.get_mail_bytes(args.quarantine_id)
    sys.stdout.buffer.write(data)


def metadata(quarantines, args):
    storage = _get_quarantine(quarantines, args.quarantine, args.debug).storage
    metadata = storage.get_metadata(args.quarantine_id)
    print(json.dumps(metadata))


class StdErrFilter(logging.Filter):
    def filter(self, rec):
        return rec.levelno in (logging.ERROR, logging.WARNING)


class StdOutFilter(logging.Filter):
    def filter(self, rec):
        return rec.levelno in (logging.DEBUG, logging.INFO)


def main():
    python_version = ".".join([str(v) for v in sys.version_info[0:3]])
    python_version = f"{python_version}-{sys.version_info[3]}"

    "PyQuarantine command-line interface."
    # parse command line
    def formatter_class(prog): return argparse.HelpFormatter(
        prog, max_help_position=50, width=140)
    parser = argparse.ArgumentParser(
        description="PyQuarantine CLI",
        formatter_class=formatter_class)
    parser.add_argument(
        "-c", "--config", help="Config file to read.",
        default="/etc/pyquarantine/pyquarantine.conf")
    parser.add_argument(
        "-d", "--debug",
        help="Log debugging messages.",
        action="store_true")
    parser.add_argument(
        "-v", "--version",
        help="Print version.",
        action="version",
        version=f"%(prog)s {version} (python {python_version})")
    parser.set_defaults(syslog=False)
    subparsers = parser.add_subparsers(
        dest="command",
        title="Commands")
    subparsers.required = True

    # list command
    list_parser = subparsers.add_parser(
        "list",
        help="List available quarantines.",
        formatter_class=formatter_class)
    list_parser.add_argument(
        "-b", "--batch",
        help="Print results using only quarantine names, each on a new line.",
        action="store_true")
    list_parser.set_defaults(func=list_quarantines)

    # quarantine command group
    quar_parser = subparsers.add_parser(
        "quarantine",
        description="Manage quarantines.",
        help="Manage quarantines.",
        formatter_class=formatter_class)
    quar_parser.add_argument(
        "quarantine",
        metavar="QUARANTINE",
        help="Quarantine name.")
    quar_subparsers = quar_parser.add_subparsers(
        dest="command",
        title="Quarantine commands")
    quar_subparsers.required = True
    # quarantine list command
    quar_list_parser = quar_subparsers.add_parser(
        "list",
        description="List emails in quarantines.",
        help="List emails in quarantine.",
        formatter_class=formatter_class)
    quar_list_parser.add_argument(
        "-f", "--from",
        dest="mailfrom",
        help="Filter emails by from address.",
        default=None,
        nargs="+")
    quar_list_parser.add_argument(
        "-t", "--to",
        dest="recipients",
        help="Filter emails by recipient address.",
        default=None,
        nargs="+")
    quar_list_parser.add_argument(
        "-o", "--older-than",
        dest="older_than",
        help="Filter emails by age (days).",
        default=None,
        type=float)
    quar_list_parser.add_argument(
        "-b", "--batch",
        help="Print results using only email quarantine IDs, "
             "each on a new line.",
        action="store_true")
    quar_list_parser.set_defaults(func=list_quarantine_emails)
    # quarantine notify command
    quar_notify_parser = quar_subparsers.add_parser(
        "notify",
        description="Notify recipient about email in quarantine.",
        help="Notify recipient about email in quarantine.",
        formatter_class=formatter_class)
    quar_notify_parser.add_argument(
        "quarantine_id",
        metavar="ID",
        help="Quarantine ID.")
    quar_notify_parser_grp = quar_notify_parser.add_mutually_exclusive_group(
        required=True)
    quar_notify_parser_grp.add_argument(
        "-t", "--to",
        dest="recipient",
        help="Release email for one recipient address.")
    quar_notify_parser_grp.add_argument(
        "-a", "--all",
        help="Release email for all recipients.",
        action="store_true")
    quar_notify_parser.set_defaults(func=notify)
    # quarantine release command
    quar_release_parser = quar_subparsers.add_parser(
        "release",
        description="Release email from quarantine.",
        help="Release email from quarantine.",
        formatter_class=formatter_class)
    quar_release_parser.add_argument(
        "quarantine_id",
        metavar="ID",
        help="Quarantine ID.")
    quar_release_parser.add_argument(
        "-n",
        "--disable-syslog",
        dest="syslog",
        help="Disable syslog messages.",
        action="store_false")
    quar_release_parser_grp = quar_release_parser.add_mutually_exclusive_group(
        required=True)
    quar_release_parser_grp.add_argument(
        "-t", "--to",
        dest="recipient",
        help="Release email for one recipient address.")
    quar_release_parser_grp.add_argument(
        "-a", "--all",
        help="Release email for all recipients.",
        action="store_true")
    quar_release_parser.set_defaults(func=release)
    # quarantine delete command
    quar_delete_parser = quar_subparsers.add_parser(
        "delete",
        description="Delete email from quarantine.",
        help="Delete email from quarantine.",
        formatter_class=formatter_class)
    quar_delete_parser.add_argument(
        "quarantine_id",
        metavar="ID",
        help="Quarantine ID.")
    quar_delete_parser.add_argument(
        "-n", "--disable-syslog",
        dest="syslog",
        help="Disable syslog messages.",
        action="store_false")
    quar_delete_parser_grp = quar_delete_parser.add_mutually_exclusive_group(
        required=True)
    quar_delete_parser_grp.add_argument(
        "-t", "--to",
        dest="recipient",
        help="Delete email for one recipient address.")
    quar_delete_parser_grp.add_argument(
        "-a", "--all",
        help="Delete email for all recipients.",
        action="store_true")
    quar_delete_parser.set_defaults(func=delete)
    # quarantine get command
    quar_get_parser = quar_subparsers.add_parser(
        "get",
        description="Get email from quarantine.",
        help="Get email from quarantine",
        formatter_class=formatter_class)
    quar_get_parser.add_argument(
        "quarantine_id",
        metavar="ID",
        help="Quarantine ID.")
    quar_get_parser.set_defaults(func=get)
    # quarantine metadata command
    quar_metadata_parser = quar_subparsers.add_parser(
        "metadata",
        description="Get metadata of email from quarantine.",
        help="Get metadata of email from quarantine",
        formatter_class=formatter_class)
    quar_metadata_parser.add_argument(
        "quarantine_id",
        metavar="ID",
        help="Quarantine ID.")
    quar_metadata_parser.set_defaults(func=metadata)

    # whitelist command group
    whitelist_parser = subparsers.add_parser(
        "whitelist",
        description="Manage whitelists.",
        help="Manage whitelists.",
        formatter_class=formatter_class)
    whitelist_parser.add_argument(
        "quarantine",
        metavar="QUARANTINE",
        help="Quarantine name.")
    whitelist_subparsers = whitelist_parser.add_subparsers(
        dest="command",
        title="Whitelist commands")
    whitelist_subparsers.required = True
    # whitelist list command
    whitelist_list_parser = whitelist_subparsers.add_parser(
        "list",
        description="List whitelist entries.",
        help="List whitelist entries.",
        formatter_class=formatter_class)
    whitelist_list_parser.add_argument(
        "-f", "--from",
        dest="mailfrom",
        help="Filter entries by from address.",
        default=None,
        nargs="+")
    whitelist_list_parser.add_argument(
        "-t", "--to",
        dest="recipients",
        help="Filter entries by recipient address.",
        default=None,
        nargs="+")
    whitelist_list_parser.add_argument(
        "-o", "--older-than",
        dest="older_than",
        help="Filter emails by last used date (days).",
        default=None,
        type=float)
    whitelist_list_parser.set_defaults(func=list_whitelist)
    # whitelist add command
    whitelist_add_parser = whitelist_subparsers.add_parser(
        "add",
        description="Add whitelist entry.",
        help="Add whitelist entry.",
        formatter_class=formatter_class)
    whitelist_add_parser.add_argument(
        "-f", "--from",
        dest="mailfrom",
        help="From address.",
        required=True)
    whitelist_add_parser.add_argument(
        "-t", "--to",
        dest="recipient",
        help="Recipient address.",
        required=True)
    whitelist_add_parser.add_argument(
        "-c", "--comment",
        help="Comment.",
        default="added by CLI")
    whitelist_add_parser.add_argument(
        "-p", "--permanent",
        help="Add a permanent entry.",
        action="store_true")
    whitelist_add_parser.add_argument(
        "--force",
        help="Force adding an entry, "
             "even if already covered by another entry.",
        action="store_true")
    whitelist_add_parser.set_defaults(func=add_whitelist_entry)
    # whitelist delete command
    whitelist_delete_parser = whitelist_subparsers.add_parser(
        "delete",
        description="Delete whitelist entry.",
        help="Delete whitelist entry.",
        formatter_class=formatter_class)
    whitelist_delete_parser.add_argument(
        "whitelist_id",
        metavar="ID",
        help="Whitelist ID.")
    whitelist_delete_parser.set_defaults(func=delete_whitelist_entry)

    args = parser.parse_args()

    # setup logging
    loglevel = logging.INFO
    root_logger = logging.getLogger()
    root_logger.setLevel(loglevel)

    # setup console log
    if args.debug:
        formatter = logging.Formatter(
            "%(levelname)s: [%(name)s] - %(message)s")
    else:
        formatter = logging.Formatter("%(levelname)s: %(message)s")
    # stdout
    stdouthandler = logging.StreamHandler(sys.stdout)
    stdouthandler.setLevel(logging.DEBUG)
    stdouthandler.setFormatter(formatter)
    stdouthandler.addFilter(StdOutFilter())
    root_logger.addHandler(stdouthandler)
    # stderr
    stderrhandler = logging.StreamHandler(sys.stderr)
    stderrhandler.setLevel(logging.WARNING)
    stderrhandler.setFormatter(formatter)
    stderrhandler.addFilter(StdErrFilter())
    root_logger.addHandler(stderrhandler)
    logger = logging.getLogger(__name__)

    try:
        logger.debug("read milter configuration")
        cfg = get_milter_config(args.config, raw=True)
        if "rules" not in cfg or not cfg["rules"]:
            raise RuntimeError("no rules configured")

        for rule in cfg["rules"]:
            if "actions" not in rule or not rule["actions"]:
                raise RuntimeError(
                    f"{rule['name']}: no actions configured")
    except (RuntimeError, AssertionError) as e:
        logger.error(f"config error: {e}")
        sys.exit(255)

    quarantines = []
    for rule in cfg["rules"]:
        for action in rule["actions"]:
            if action["type"] == "quarantine":
                quarantines.append(action)

    if args.syslog:
        # setup syslog
        sysloghandler = logging.handlers.SysLogHandler(
            address="/dev/log",
            facility=logging.handlers.SysLogHandler.LOG_MAIL)
        sysloghandler.setLevel(loglevel)
        if args.debug:
            formatter = logging.Formatter(
                "pyquarantine: [%(name)s] [%(levelname)s] %(message)s")
        else:
            formatter = logging.Formatter("pyquarantine: %(message)s")
        sysloghandler.setFormatter(formatter)
        root_logger.addHandler(sysloghandler)

    # call the commands function
    try:
        args.func(quarantines, args)
    except RuntimeError as e:
        logger.error(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
