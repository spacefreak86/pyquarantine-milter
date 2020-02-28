# pyheader-milter
A pymilter based sendmail/postfix pre-queue filter with the ability to add, remove and modify e-mail headers.

The project is currently in beta status, but it is already used in a productive enterprise environment which processes about a million e-mails per month.

## Requirements
* pymilter <https://pythonhosted.org/pymilter/>
* netaddr <https://github.com/drkjam/netaddr/>

## Configuration
The pyheader-milter uses an INI-style configuration file. The sections are described below.

### Section "global"
Any available configuration option can be set in the global section as default instead of in a rule section.

The following configuration options are mandatory in the global section:
* **rules**  
  Comma-separated, ordered list of active rules. For each, there must be a section of the same name in the configuration.

### Rule sections
The following configuration options are mandatory for each rule:
* **action**  
  Set the action of this rule. Possible values are:
  * **add**
  * **del**
  * **mod**
* **header**  
  Name of the header in case of adding a header, regular expression to match whole header lines in case of deleting or modifying a header.

The following configuration options are mandatory for an add-rule:
* **value**  
  Value of the header.

The following configuration options are mandatory for a mod-rule:
* **search**  
  Regular expression to match the value of header lines. You may use subgroups or named subgroups (python syntax) to include parts of the original value in the new value.
* **value**  
  New value of the header.

The following configuration options are optional for each rule:
* **ignore_hosts**  
  Comma-separated list of host and network addresses. The rule will be skipped if the sending host is included here.
* **only_hosts**  
  Comma-separated list of host and network addresses. The rule will be skipped if the sending host is not included here. If a is included in both **ignore_hosts** and **only_hosts**, the rule will be skipped.
* **log**  
  Enable or disable logging of this rule. Possible values are:
  * **true**
  * **false**

## Developer information
Everyone who wants to improve or extend this project is very welcome.
