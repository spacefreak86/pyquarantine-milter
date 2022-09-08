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

from sys import version_info
import encodings


#####################################
#    patch pythons email library    #
#####################################
#
# https://bugs.python.org/issue27257
# https://bugs.python.org/issue30988
#
# fix: https://github.com/python/cpython/pull/15600

import email._header_value_parser
from email._header_value_parser import TokenList, NameAddr
from email._header_value_parser import get_display_name, get_angle_addr
from email._header_value_parser import get_cfws, errors
from email._header_value_parser import CFWS_LEADER, PHRASE_ENDS


class DisplayName(email._header_value_parser.DisplayName):
    @property
    def display_name(self):
        res = TokenList(self)
        if len(res) == 0:
            return res.value
        if res[0].token_type == 'cfws':
            res.pop(0)
        else:
            if isinstance(res[0], TokenList) and \
                    res[0][0].token_type == 'cfws':
                res[0] = TokenList(res[0][1:])
        if res[-1].token_type == 'cfws':
            res.pop()
        else:
            if isinstance(res[-1], TokenList) and \
                    res[-1][-1].token_type == 'cfws':
                res[-1] = TokenList(res[-1][:-1])
        return res.value


def get_name_addr(value):
    """ name-addr = [display-name] angle-addr

    """
    name_addr = NameAddr()
    # Both the optional display name and the angle-addr can start with cfws.
    leader = None
    if value[0] in CFWS_LEADER:
        leader, value = get_cfws(value)
        if not value:
            raise errors.HeaderParseError(
                "expected name-addr but found '{}'".format(leader))
    if value[0] != '<':
        if value[0] in PHRASE_ENDS:
            raise errors.HeaderParseError(
                "expected name-addr but found '{}'".format(value))
        token, value = get_display_name(value)
        if not value:
            raise errors.HeaderParseError(
                "expected name-addr but found '{}'".format(token))
        if leader is not None:
            if isinstance(token[0], TokenList):
                token[0][:0] = [leader]
            else:
                token[:0] = [leader]
            leader = None
        name_addr.append(token)
    token, value = get_angle_addr(value)
    if leader is not None:
        token[:0] = [leader]
    name_addr.append(token)
    return name_addr, value


setattr(email._header_value_parser, "DisplayName", DisplayName)
setattr(email._header_value_parser, "get_name_addr", get_name_addr)


# https://bugs.python.org/issue42484
#
# fix: https://github.com/python/cpython/pull/24669

from email._header_value_parser import DOT, ObsLocalPart, ValueTerminal, get_word


def get_obs_local_part(value):
    """ obs-local-part = word *("." word)
    """
    obs_local_part = ObsLocalPart()
    last_non_ws_was_dot = False
    while value and (value[0]=='\\' or value[0] not in PHRASE_ENDS):
        if value[0] == '.':
            if last_non_ws_was_dot:
                obs_local_part.defects.append(errors.InvalidHeaderDefect(
                    "invalid repeated '.'"))
            obs_local_part.append(DOT)
            last_non_ws_was_dot = True
            value = value[1:]
            continue
        elif value[0]=='\\':
            obs_local_part.append(ValueTerminal(value[0],
                                                'misplaced-special'))
            value = value[1:]
            obs_local_part.defects.append(errors.InvalidHeaderDefect(
                "'\\' character outside of quoted-string/ccontent"))
            last_non_ws_was_dot = False
            continue
        if obs_local_part and obs_local_part[-1].token_type != 'dot':
            obs_local_part.defects.append(errors.InvalidHeaderDefect(
                "missing '.' between words"))
        try:
            token, value = get_word(value)
            last_non_ws_was_dot = False
        except errors.HeaderParseError:
            if value[0] not in CFWS_LEADER:
                raise
            token, value = get_cfws(value)
        obs_local_part.append(token)
    if not obs_local_part:
        return obs_local_part, value
    if (obs_local_part[0].token_type == 'dot' or
            obs_local_part[0].token_type=='cfws' and
            obs_local_part[1].token_type=='dot'):
        obs_local_part.defects.append(errors.InvalidHeaderDefect(
            "Invalid leading '.' in local part"))
    if (obs_local_part[-1].token_type == 'dot' or
            obs_local_part[-1].token_type=='cfws' and
            obs_local_part[-2].token_type=='dot'):
        obs_local_part.defects.append(errors.InvalidHeaderDefect(
            "Invalid trailing '.' in local part"))
    if obs_local_part.defects:
        obs_local_part.token_type = 'invalid-obs-local-part'
    return obs_local_part, value


setattr(email._header_value_parser, "get_obs_local_part", get_obs_local_part)


#######################################
#  add charset alias for windows-874  #
#######################################
#
# https://bugs.python.org/issue17254
#
# fix: https://github.com/python/cpython/pull/10237

aliases = encodings.aliases.aliases

for alias in ["windows-874", "windows_874"]:
    if alias not in aliases:
        aliases[alias] = "cp874"

setattr(encodings.aliases, "aliases", aliases)


if version_info.major == 3 and version_info.minor < 10:
    # https://bugs.python.org/issue30681
    #
    # fix: https://github.com/python/cpython/pull/22090

    import email.errors
    from email.errors import HeaderDefect


    class InvalidDateDefect(HeaderDefect):
        """Header has unparseable or invalid date"""


    setattr(email.errors, "InvalidDateDefect", InvalidDateDefect)


    import email.utils
    from email.utils import _parsedate_tz
    import datetime


    def parsedate_to_datetime(data):
        parsed_date_tz = _parsedate_tz(data)
        if parsed_date_tz is None:
            raise ValueError('Invalid date value or format "%s"' % str(data))
        *dtuple, tz = parsed_date_tz
        if tz is None:
            return datetime.datetime(*dtuple[:6])
        return datetime.datetime(*dtuple[:6],
                tzinfo=datetime.timezone(datetime.timedelta(seconds=tz)))


    setattr(email.utils, "parsedate_to_datetime", parsedate_to_datetime)


    import email.headerregistry
    from email import utils, _header_value_parser as parser

    @classmethod
    def parse(cls, value, kwds):
        if not value:
            kwds['defects'].append(errors.HeaderMissingRequiredValue())
            kwds['datetime'] = None
            kwds['decoded'] = ''
            kwds['parse_tree'] = parser.TokenList()
            return
        if isinstance(value, str):
            kwds['decoded'] = value
            try:
                value = utils.parsedate_to_datetime(value)
            except ValueError:
                kwds['defects'].append(errors.InvalidDateDefect('Invalid date value or format'))
                kwds['datetime'] = None
                kwds['parse_tree'] = parser.TokenList()
                return
        kwds['datetime'] = value
        kwds['decoded'] = utils.format_datetime(kwds['datetime'])
        kwds['parse_tree'] = cls.value_parser(kwds['decoded'])


    setattr(email.headerregistry.DateHeader, "parse", parse)
