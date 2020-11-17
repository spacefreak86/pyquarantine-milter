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
