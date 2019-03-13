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

import Milter
import argparse
import logging
import logging.handlers
import sys

import pyquarantine


def main():
    "Run PyQuarantine-Milter."
    # parse command line
    parser = argparse.ArgumentParser(description="PyQuarantine milter daemon",
            formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=45, width=140))
    parser.add_argument("-c", "--config", help="List of config files to read.", nargs="+",
            default=pyquarantine.QuarantineMilter.get_configfiles())
    parser.add_argument("-s", "--socket", help="Socket used to communicate with the MTA.", required=True)
    parser.add_argument("-d", "--debug", help="Log debugging messages.", action="store_true")
    parser.add_argument("-t", "--test", help="Check configuration.", action="store_true")
    args = parser.parse_args()

    # setup logging
    loglevel = logging.INFO
    logname = "pyquarantine-milter"
    syslog_name = logname
    if args.debug:
        loglevel = logging.DEBUG
        logname = "{}[%(name)s]".format(logname)
        syslog_name = "{}: [%(name)s] %(levelname)s".format(syslog_name)

    # set config files for milter class
    pyquarantine.QuarantineMilter.set_configfiles(args.config)
    root_logger = logging.getLogger()
    root_logger.setLevel(loglevel)

    # setup console log
    stdouthandler = logging.StreamHandler(sys.stdout)
    stdouthandler.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(message)s".format(logname))
    stdouthandler.setFormatter(formatter)
    root_logger.addHandler(stdouthandler)
    logger = logging.getLogger(__name__)
    if args.test:
        try:
            pyquarantine.generate_milter_config(args.test)
            print("Configuration ok")
        except RuntimeError as e:
            logger.error(e)
            sys.exit(255)
        else:
            sys.exit(0)
    formatter = logging.Formatter("%(asctime)s {}: [%(levelname)s] %(message)s".format(logname), datefmt="%Y-%m-%d %H:%M:%S")
    stdouthandler.setFormatter(formatter)

    # setup syslog
    sysloghandler = logging.handlers.SysLogHandler(address="/dev/log", facility=logging.handlers.SysLogHandler.LOG_MAIL)
    sysloghandler.setLevel(loglevel)
    formatter = logging.Formatter("{}: %(message)s".format(syslog_name))
    sysloghandler.setFormatter(formatter)
    root_logger.addHandler(sysloghandler)

    logger.info("PyQuarantine-Milter starting")
    try:
        # generate milter config
        global_config, config = pyquarantine.generate_milter_config()
    except RuntimeError as e:
        logger.error(e)
        sys.exit(255)

    pyquarantine.QuarantineMilter.global_config = global_config
    pyquarantine.QuarantineMilter.config = config

    # register to have the Milter factory create instances of your class:
    Milter.factory = pyquarantine.QuarantineMilter
    Milter.set_exception_policy(Milter.TEMPFAIL)
    #Milter.set_flags(0)       # tell sendmail which features we use

    # run milter
    rc = 0
    try:
        Milter.runmilter("pyquarantine-milter", socketname=args.socket, timeout=300)
    except Milter.milter.error as e:
        logger.error(e)
        rc = 255
    pyquarantine.mailer.queue.put(None)
    logger.info("PyQuarantine-Milter terminated")
    sys.exit(rc)


if __name__ == "__main__":
    main()
