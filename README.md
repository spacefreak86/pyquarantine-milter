# pymodmilter
A pymilter based sendmail/postfix pre-queue filter with the ability to add, remove and modify e-mail headers.  
The project is currently in beta status, but it is already used in a productive enterprise environment that processes about a million e-mails per month.  

The basic idea is to define rules with conditions and actions which are processed when all conditions are true.

## Dependencies
Pymodmilter is depending on these python packages, but they are installed automatically if you are working with pip.
* [pymilter](https://pythonhosted.org/pymilter/)
* [netaddr](https://github.com/drkjam/netaddr/)
* [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/)

## Installation
* Install pymodmilter with pip and copy the example config file.
```sh
pip install pymodmilter
cp /etc/pymodmilter/pymodmilter.conf.example /etc/pymodmilter/pymodmilter.conf
```
* Modify /etc/pymodmilter/pymodmilter.conf according to your needs.

## Configuration options
Pymodmilter uses a config file in JSON format. The config file has to be JSON valid with the exception of allowed comment lines starting with **#**. The options are described below.  
Rules and actions are processed in the given order.

### Global
Config options in **global** section:
* **socket** (optional)  
  The socket used to communicate with the MTA. If it is not specified in the config, it has to be set as command line option.
* **local_addrs** (optional)  
  A list of hosts and network addresses which are considered local. It is used to for the condition option [local](#Conditions).  
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

### Rules
Config options for **rule** objects:
* **name**  (optional)  
  Name of the rule.  
  Default: **Rule #n**
* **actions**  
  A list of action objects which are processed in the given order.
* **conditions** (optional)  
  A list of conditions which all have to be true to process the actions.
* **loglevel** (optional)  
  As described above in the [Global](#Global) section.
* **pretend** (optional)  
  As described above in the [Global](#Global) section.

### Actions
Config options for **action** objects:
* **name** (optional)  
  Name of the action.
  Default: **Action #n**
* **type**  
  Action type. Possible values are:
  * **add_header**
  * **del_header**
  * **mod_header**
  * **add_disclaimer**
  * **store**
* **conditions** (optional)  
  A list of conditions which all have to be true to process the action.
* **loglevel** (optional)  
  As described above in the [Global](#Global) section.
* **pretend** (optional)  
  As described above in the [Global](#Global) section.

Config options for **add_header** actions:
  * **field**  
    Name of the header.
  * **value**  
    Value of the header.

Config options for **del_header** actions:
  * **field**  
    Regular expression to match against header names.
  * **value** (optional)
    Regular expression to match against the headers value.

Config options for **mod_header** actions:
  * **field**  
    Regular expression to match against header names.
  * **search** (optional)  
    Regular expression to match against header values. You may use subgroups or named subgroups (python syntax) to include parts of the original value in the new value.
  * **value**  
    New value of the header.

Config options for **add_disclaimer** actions:
  * **action**  
    Action to perform with the disclaimer. Possible values are:
    * append
    * prepend
  * **html_template**  
    Path to a file which contains the html representation of the disclaimer.
  * **text_template**  
    Path to a file which contains the text representation of the disclaimer.
  * **error_policy** (optional)  
    Set the error policy in case the disclaimer cannot be added (e.g. if no body part is present in the e-mail). Possible values are:
    * **wrap**  
      A new e-mail body is generated with the disclaimer as body and the original e-mail attached.
    * **ignore**  
      Ignore the error and do nothing.
    * **reject**  
      Reject the e-mail.
    Default: **wrap**

Config options for **store** actions:
  * **storage_type**  
    Storage type. Possible values are:
    * **file**
  * **original** (optional)  
    Default: **false**
    If set to true, store the message as received by the MTA instead of storing the current state of the message, that may was modified already by other actions.

Config options for **file** storage:
  * **directory**  
  Directory used to store e-mails.

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
