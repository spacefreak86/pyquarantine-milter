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
    "CustomLogger",
    "MilterMessage",
    "replace_illegal_chars"]

import logging

from email.message import MIMEPart


class CustomLogger(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        if "name" in self.extra:
            msg = f"{self.extra['name']}: {msg}"

        if "qid" in self.extra:
            msg = f"{self.extra['qid']}: {msg}"

        if self.logger.getEffectiveLevel() != logging.DEBUG:
            msg = msg.replace("\n", "").replace("\r", "")

        return msg, kwargs


class MilterMessage(MIMEPart):
    def replace_header(self, _name, _value, idx=None):
        _name = _name.lower()
        counter = 0
        for i, (k, v) in zip(range(len(self._headers)), self._headers):
            if k.lower() == _name:
                counter += 1
                if not idx or counter == idx:
                    self._headers[i] = self.policy.header_store_parse(
                        k, _value)
                    break

        else:
            raise KeyError(_name)

    def remove_header(self, name, idx=None):
        name = name.lower()
        newheaders = []
        counter = 0
        for k, v in self._headers:
            if k.lower() == name:
                counter += 1
                if counter != idx:
                    newheaders.append((k, v))
            else:
                newheaders.append((k, v))

        self._headers = newheaders

    def _find_body_parent(self, part, preferencelist, parent=None):
        if part.is_attachment():
            return
        maintype, subtype = part.get_content_type().split("/")
        if maintype == "text":
            if subtype in preferencelist:
                yield(preferencelist.index(subtype), parent)
            return
        if maintype != "multipart" or not self.is_multipart():
            return
        if subtype != "related":
            for subpart in part.iter_parts():
                yield from self._find_body_parent(
                    subpart, preferencelist, part)
            return
        if 'related' in preferencelist:
            yield(preferencelist.index('related'), parent)
        candidate = None
        start = part.get_param('start')
        if start:
            for subpart in part.iter_parts():
                if subpart['content-id'] == start:
                    candidate = subpart
                    break
        if candidate is None:
            subparts = part.get_payload()
            candidate = subparts[0] if subparts else None
        if candidate is not None:
            yield from self._find_body_parent(candidate, preferencelist, part)

    def get_body_parent(self, preferencelist=("related", "html", "plain")):
        best_prio = len(preferencelist)
        body_parent = None
        for prio, parent in self._find_body_parent(self, preferencelist):
            if prio < best_prio:
                best_prio = prio
                body_parent = parent
                if prio == 0:
                    break
        return body_parent

    def get_body_content(self, pref):
        part = None
        content = None
        if not self.is_multipart() and \
                self.get_content_type() == f"text/{pref}":
            part = self
        else:
            part = self.get_body(preferencelist=(pref))

        if part is not None:
            content = part.get_content()

        return (part, content)

    def set_body(self, text_content=None, html_content=None):
        parent = self.get_body_parent() or self
        if "Content-Type" not in parent:
            # set Content-Type header if not present, otherwise
            # make_alternative and make_mixed skip the payload
            parent["Content-Type"] = parent.get_content_type()

        maintype, subtype = parent.get_content_type().split("/")
        if not parent.is_multipart() or maintype != "multipart":
            if maintype == "text" and subtype in ("html", "plain"):
                parent.make_alternative()
                maintype, subtype = ("multipart", "alternative")
            else:
                parent.make_mixed()
                maintype, subtype = ("multipart", "mixed")

        text_body = parent.get_body(preferencelist=("plain"))
        html_body = parent.get_body(preferencelist=("html"))

        if text_content is not None:
            if text_body:
                text_body.set_content(text_content)
            else:
                if not html_body or subtype == "alternative":
                    inject_body_part(parent, text_content)
                else:
                    html_body.add_alternative(text_content)
                text_body = parent.get_body(preferencelist=("plain"))

        if html_content is not None:
            if html_body:
                html_body.set_content(html_content, subtype="html")
            else:
                if not text_body or subtype == "alternative":
                    inject_body_part(parent, html_content, subtype="html")
                else:
                    text_body.add_alternative(html_content, subtype="html")


def inject_body_part(part, content, subtype="plain"):
    parts = []
    text_body = None
    text_content = None
    if subtype == "html":
        text_body, text_content = part.get_body_content("plain")

    for p in part.iter_parts():
        if text_body and p == text_body:
            continue
        parts.append(p)

    boundary = part.get_boundary()
    p_subtype = part.get_content_subtype()
    part.clear_content()
    if text_content != None:
        part.set_content(text_content)
        part.add_alternative(content, subtype=subtype)
    else:
        part.set_content(content, subtype=subtype)

    if part.get_content_subtype() != p_subtype:
        if p_subtype == "alternative":
            part.make_alternative()
        elif p_subtype == "related":
            part.make_related()
        else:
            part.make_mixed()

    if boundary:
        part.set_boundary(boundary)
    for p in parts:
        part.attach(p)


def replace_illegal_chars(string):
    """Remove illegal characters from header values."""
    return "".join(string.replace("\x00", "").splitlines())
