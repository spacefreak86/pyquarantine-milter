# pyquarantine-milter
A pymilter based sendmail/postfix pre-queue filter with the ability to quarantine e-mails, send notifications and modify e-mail headers and/or bodies.  
The project is currently in beta status, but it is already used in a productive enterprise environment that processes about a million e-mails per month.  

It is useful in many cases due to its flexible configuration and the ability to handle any number of quarantines and/or modifications sequential and conditional.

## Dependencies
pyquarantine is depending on these python packages, they are installed automatically if you are working with pip.
* [jsonschema](https://github.com/Julian/jsonschema)
* [pymilter](https://github.com/sdgathman/pymilter)
* [netaddr](https://github.com/drkjam/netaddr)
* [peewee](https://github.com/coleifer/peewee)
* [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/)

## Installation
```sh
# Install pyquarantine with pip.
pip install pyquarantine

# Copy the example config file and modify it according to your needs.
cp /etc/pyquarantine/pyquarantine.conf.example /etc/pyquarantine/pyquarantine.conf

# Check the validity of the config file.
pyquarantine-milter -t
```

## Configuration
pyquarantine uses a config file in JSON format. It has to be JSON valid with the exception of allowed comment lines starting with **#**.  

The basic idea is to configure rules that contain actions. Both rules and actions may have conditions. An example of using rules is separating incoming and outgoing e-mails using the **local** condition. Rules and actions are always processed in the given order.  

### Global
Global config options:
* **socket** (optional)  
  Socket used to communicate with the MTA. If it is not specified in the config, it has to be set as command line option.
* **local_addrs** (optional, default: **[fe80::/64, ::1/128, 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]**)  
  List of hosts and network addresses which are considered local. It is used for the condition option [local](#Conditions).  
* **loglevel**  (optional, default: **info**)  
  Set the log level. This option may be overriden by any rule or action object.  
  Possible values:
  * **error**  
  * **warning**  
  * **info**  
  * **debug**  
* **pretend** (optional, default: **false**)  
  Pretend actions, for test purposes. This option may be overriden by any rule or action object.  
* **rules**  
  List of rule objects.

### Rule
Rule config options:
* **name**  
  Name of the rule.  
* **actions**  
  List of action objects.
* **conditions** (optional)  
  See section [Conditions](#Conditions).
* **loglevel** (optional)  
  See section [Global](#Global).
* **pretend** (optional)  
  See section [Global](#Global).

### Action
Action config options:
* **name**  
  Name of the action.
* **type**  
  See section [Actions](#Actions).
* **options**  
  Options depending on the action type, see section [Actions](#Actions).
* **conditions** (optional)  
  See section [Conditions](#Conditions).
* **loglevel** (optional)  
  See section [Global](#Global).
* **pretend** (optional)  
  See section [Global](#Global).

### Conditions
Config options for **conditions** objects:
* **local** (optional)  
  Matches outgoing e-mails (sender address matches **local_addrs**) if set to **true** or matches incoming e-mails if set to **false**.
* **hosts** (optional)  
  Matches e-mails originating from the given list of hosts and network addresses.
* **envfrom** (optional)  
  Matches e-mails for which the envelope-from address matches the given regular expression.
* **envto** (optional)  
  Matches e-mails for which all envelope-to addresses match the given regular expression.
* **headers** (optional)  
  Matches e-mails for which all regular expressions in the given list are matching at least one e-mail header.
* **whitelist** (optional)  
  Matches e-mails for which the whitelist has no entry for the envelope-from and envelope-to address combination, see section [Whitelist](#Whitelist).
* **var** (optional)  
  Matches e-mails for which a previous action or condition has set the given metavariable.
* **metavar** (optional)  
  Prefix for the name of metavariables which are possibly provided by the **envfrom**, **envto** or **headers** condition. Meta variables will be provided if the regular expressions contain named subgroups, see [python.re](https://docs.python.org/3/library/re.html) for details.  
  If not set, no metavariables will be provided.

### Whitelist
Config options for **whitelist** objects:
* **type**  
  See section [Whitelists](#Whitelists).

### Actions
The following action types and options are available.
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
    Action to perform with the disclaimer.  
    Possible values:
    * append
    * prepend
  * **html_template**  
    Path to a file which contains the html representation of the disclaimer.
  * **text_template**  
    Path to a file which contains the text representation of the disclaimer.
  * **error_policy** (optional, default: **wrap**)  
    Set the error policy in case the disclaimer cannot be added (e.g. if the html part cannot be parsed).  
    Possible values:
    * **wrap**  
      A new e-mail body is generated with the disclaimer as body and the original e-mail attached.
    * **ignore**  
      Ignore the error and do nothing.
    * **reject**  
      Reject the e-mail.
  * **add_html_body** (optional, default: **false**)  
    Generate a html body with the content of the text body if no html body is present.

* **store**  
  Store e-mail.
  * **type**  
    See section [Storages](#Storages).
  * **original** (optional, default: **false**)  
    If set to true, store the message as received by the MTA instead of storing the current state of the message, that may was modified already by other actions.
  * **metadata** (optional, default: **false**)  
    Store metadata.
  * **metavar**  (optional)
    Prefix for the metavariable names. If not set, no metavariables will be provided.
    The storage provides the following metavariables:
    * **ID** (the storage ID of the e-mail)  
    * **DATAFILE** (path to the data file)  
    * **METAFILE** (path to the meta file if **metadata** is set to **true**)  

* **notify**  
  Send notification to receiver.
  * **type**  
    See section [Notifications](#Notifications).

* **quarantine**  
  Quarantine e-mail.
  * **store**  
  Options for e-mail storage, see action **store** in section [Actions](#Actions).
  * **smtp_host**  
  SMTP host used to release e-mails from quarantine.
  * **smtp_port**  
  SMTP port used to release e-mails from quarantine.
  * **notify** (optional)  
  Options for e-mail notifications, see action **notify** in section [Actions](#Actions).
  * **milter_action** (optional)  
  Final milter action to perform. If set, no further rules or actions will be processed.  
  Possible values:
    * **ACCEPT**   (Tell MTA to accept the e-mail, skip following rules/actions.)
    * **REJECT**   (Tell MTA to reject the e-mail.)
    * **DISCARD**  (Tell MTA to discard the e-mail.)
  * **reject_reason** (optional, default: **Message rejected**)  
  Reject message used if milter_action is set to reject.
  * **whitelist** (optional)  
  Options for a whitelist, see **whitelist** in section [Conditions](#Conditions).

### Storages
The following storage types are and options are available:
* **file**  
  * **directory**  
  Directory used to store e-mails.
  * **metadata** (optional, default: **false**)  
  Store metadata file.
  * **mode**  (optional, default: system default)  
  File mode when new files are created.

### Notifications
The following notification types and options are available:
* **email**
  * **smtp_host**  
  SMTP host used to send notifications.
  * **smtp_port**  
  SMTP port used to send notifications.
  * **envelope_from**  
  Envelope-From address.
  * **from_header**  
  Value of the From header.
  * **subject**  
  Subject of the notification.
  * **template**  
  Notification template.
  * **repl_img** (optional)  
  Replacement image used to replace all images in the e-mail body.
  * **embed_imgs** (optional)  
  List of images to embed into the notification e-mail.

### Whitelists
The following whitelist types and options are available.
* **db**  
  Whitelist stored in database. The table is created automatically if it does not exist yet.
  * **connection**  
    Database connection string, see [Peewee Playhouse Extension](https://docs.peewee-orm.com/en/latest/peewee/playhouse.html#db-url).
  * **table**  
    Database table to use.

## Developer information
Everyone who wants to improve or extend this project is very welcome.
