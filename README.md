# pyquarantine-milter
A pymilter based sendmail/postfix pre-queue filter with the ability to quarantine e-mails, send notifications and modify e-mail headers and/or bodies.  
The project is currently in beta status, but it is already used in a productive enterprise environment that processes about a million e-mails per month.  

It is useful in many cases due to its flexible configuration and the ability to handle any number of quarantines and/or modifications sequential.

The basic idea is to configure rules with optional conditions. If all conditions match, the configured actions (e.g. quarantine, modify, ...) within the rule are performed on the e-mail. Each action can have its own conditions as well.  

## Dependencies
pyquarantine is depending on these python packages, but they are installed automatically if you are working with pip.
* [jsonschema](https://github.com/Julian/jsonschema)
* [pymilter](https://github.com/sdgathman/pymilter)
* [netaddr](https://github.com/drkjam/netaddr)
* [peewee](https://github.com/coleifer/peewee)
* [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/)

## Installation
* Install pyquarantine with pip and copy the example config file.
```sh
pip install pyquarantine
cp /etc/pyquarantine/pyquarantine.conf.example /etc/pyquarantine/pyquarantine.conf
```
* Modify /etc/pyquarantine/pyquarantine.conf according to your needs.

## Configuration options
pyquarantine uses a config file in JSON format. The config file has to be JSON valid with the exception of allowed comment lines starting with **#**.  
Rules and actions are processed in the given order.

### Global
Global config options:
* **socket** (optional)  
  The socket used to communicate with the MTA. If it is not specified in the config, it has to be set as command line option.
* **local_addrs** (optional)  
  A list of hosts and network addresses which are considered local. It is used for the condition option [local](#Conditions).  
  Default: **fe80::/64, ::1/128, 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16**
* **loglevel**  (optional)
  Set the log level. This option may be overriden by any rule or action object. Possible values are:
  * **error**  
  * **warning**  
  * **info**  
  * **debug**  
  Default: **info**
* **pretend** (optional)
  Pretend actions, for test purposes. This option may be overriden by any rule or action object.
* **rules**
  List of rule objects.

### Rule
Rule config options:
* **name**  (optional)  
  Name of the rule.  
  Default: **Rule #n**
* **actions**  
  A list of action objects which are processed in the given order.
* **conditions** (optional)  
  A list of conditions which all have to be true to process the rule.
* **loglevel** (optional)  
  See section [Global](#Global).
* **pretend** (optional)  
  See section [Global](#Global).

### Action
Action config options:
* **name** (optional)  
  Name of the action.
  Default: **Action #n**
* **type**  
  See section [Actions](#Actions).
* **options**  
  Options for the action according to action type (as described below).
* **conditions** (optional)  
  A list of conditions which all have to be true to process the action.
* **loglevel** (optional)  
  See section [Global](#Global).
* **pretend** (optional)  
  See section [Global](#Global).

### Actions
The following action types are available.
* **add_header**  
  Add new header.
  * **field**  
    Name of the header.
  * **value**  
    Value of the header.

* **del_header**  
  Delete header(s).
  * **field**  
    Regular expression to match against header names.
  * **value** (optional)
    Regular expression to match against the headers value.

* **mod_header**  
  Modify header(s).
  * **field**  
    Regular expression to match against header names.
  * **search** (optional)  
    Regular expression to match against header values. You may use subgroups or named subgroups (python syntax) to include parts of the original value in the new value.
  * **value**  
    New value of the header.

* **add_disclaimer**  
  Append or prepend disclaimer to text and/or html body parts.
  * **action**  
    Action to perform with the disclaimer. Possible values are:
    * append
    * prepend
  * **html_template**  
    Path to a file which contains the html representation of the disclaimer.
  * **text_template**  
    Path to a file which contains the text representation of the disclaimer.
  * **error_policy** (optional)  
    Set the error policy in case the disclaimer cannot be added (e.g. if the html part cannot be parsed). Possible values are:
    * **wrap**  
      A new e-mail body is generated with the disclaimer as body and the original e-mail attached.
    * **ignore**  
      Ignore the error and do nothing.
    * **reject**  
      Reject the e-mail.
    Default: **wrap**
  * **add_html_body** (optional)  
    Generate a html body with the content of the text body if no html body is present.
    Default: **false**

* **store**  
  Store e-mail.
  * **type**  
    Storage type. Possible values are:
    * **file**
  * **original** (optional)  
    If set to true, store the message as received by the MTA instead of storing the current state of the message, that may was modified already by other actions.
    Default: **false**

* **file**  
  * **directory**  
  Directory used to store e-mails.
  * **metadata** (optional)  
  Store metadata file.
  Default: **false**
  * **mode**  (optional)  
  Set file mode.
  Default: system default
  * **metavar** (optional)  
  If set, some information (e.g. storage id) is saved as meta variables for later use.

* **notify**  
  Send notification to receiver.

* **quarantine**  
  Quarantine message.

* **rewrite_links**  
  Rewrite links in html body part.


### Conditions
Config options for **conditions** objects:
* **local** (optional)  
  If set to true, the rule is only executed for e-mails originating from addresses defined in local_addrs and vice versa.
* **hosts** (optional)  
  A list of hosts and network addresses for which the rule should be executed.
* **envfrom** (optional)  
  A regular expression to match against the evenlope-from addresses for which the rule should be executed.
* **envto** (optional)  
  A regular expression to match against all evenlope-to addresses. All addresses must match to fulfill the condition.


## Developer information
Everyone who wants to improve or extend this project is very welcome.
