# pyquarantine-milter
A pymilter based sendmail/postfix pre-queue filter with the ability to ...
* modify e-mail headers (add, modify, delete)
* store e-mails
* send e-mail notifications
* append and prepend disclaimers to e-mail text parts
* quarantine e-mails (store e-mail, optionally notify receivers)

It is useful in many cases due to its flexible configuration and the ability to handle any number of quarantines and modifications sequential and conditional. Storages and lists used by quarantines can be managed with the built-in CLI.  

Addionally, pyquarantine-milter provides a sanitized, harmless version of the text parts of e-mails as template variable, which can be embedded in e-mail notifications. This makes it easier for users to decide, if a match is a false-positive or not.  
It is also possible to use any metavariable as template variable (e.g. storage ID, envelope-from address, ...). This may be used to give your users the ability to release e-mails or add the from-address to an allowlist. A webservice then releases the e-mail from the quarantine.  

The project is currently in beta status, but it is already used in a productive enterprise environment that processes about a million e-mails per month.

## Dependencies
pyquarantine is depending on these python packages, they are installed automatically if you are working with pip.
* [jsonschema](https://github.com/Julian/jsonschema)
* [pymilter](https://github.com/sdgathman/pymilter)
* [netaddr](https://github.com/drkjam/netaddr)
* [peewee](https://github.com/coleifer/peewee)
* [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/)

## Installation
```sh
# install pyquarantine with pip.
pip install pyquarantine

# install service files, default config and templates
pyquarantine-milter --install

# copy default config file
cp /etc/pyquarantine/pyquarantine.conf.default /etc/pyquarantine/pyquarantine.conf

# Check the validity of the your config file.
pyquarantine-milter -t
```
## Autostart
The following init systems are supported.

### systemd
```sh
# start the daemon at boot time
systemctl enable pyquarantine-milter.service

# start the daemon immediately
systemctl start pyquarantine-milter.service
```

### OpenRC (Gentoo)
```sh
# start the daemon at boot time
rc-update add pyquarantine-milter default

# start the daemon immediately
rc-service pyquarantine-milter start
```

## Configuration
pyquarantine uses a config file in JSON format. It has to be JSON valid with the exception of allowed comment lines starting with **#**.  

The basic idea is to configure rules that contain actions. Both rules and actions may have conditions. An example of using rules is separating incoming and outgoing e-mails using the local condition. Rules and actions are always processed in the given order.  

### Global
Global config options:
* **socket** (optional)  
  Socket used to communicate with the MTA. If it is not specified in the config, it has to be set as command line option.
* **local_addrs** (optional, default: [fe80::/64, ::1/128, 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16])  
  List of hosts and network addresses which are considered local. It is used for the condition option [local](#Conditions).  
* **loglevel**  (optional, default: "info")  
  Set the log level. This option may be overriden by any rule or action object.  
  Possible values:
  * **error**  
  * **warning**  
  * **info**  
  * **debug**  
* **pretend** (optional, default: false)  
  Pretend actions, for test purposes. This option may be overriden by any rule or action object.  
* **storages**  
  Object containing Storage objects.
* **notifications**  
  Object containing Notification objects.
* **lists**  
  Object containing List objects.
* **rules**  
  List of rule objects.

### Storage
Config options for Storage objects:
* **type**  
  See section [Storage types](#Storage-types).
* **original** (optional, default: false)  
  If set to true, store the message as received by the MTA instead of storing the current state of the message, that may was modified already by other actions.
* **metadata** (optional, default: false)  
  Store metadata.
* **metavar**  (optional)  
  Prefix for the metavariable names. If not set, no metavariables will be provided.  
  The storage provides the following metavariables:
  * **ID** (the storage ID of the e-mail)  
  * **DATAFILE** (path to the data file)  
  * **METAFILE** (path to the meta file if **metadata** is set to **true**)  

### Notification
Config options for Notification objects:
* **type**  
  See section [Notification types](#Notification-types).

### List
Config options for List objects:
* **type**  
  See section [List types](#List-types).

### Rule
Config options for rule objects:
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
Config options for action objects:
* **name**  
  Name of the action.
* **type**  
  See section [Action types](#Action-types).
* **options**  
  Options depending on the action type, see section [Action types](#Action-types).
* **conditions** (optional)  
  See section [Conditions](#Conditions).
* **loglevel** (optional)  
  See section [Global](#Global).
* **pretend** (optional)  
  See section [Global](#Global).

### Conditions
Config options for conditions objects:
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
* **list** (optional)  
  Matches e-mails for which the given list has an entry for the envelope-from and envelope-to address combination, see section [List](#List) for details.
* **var** (optional)  
  Matches e-mails for which a previous action or condition has set the given metavariable.
* **metavar** (optional)  
  Prefix for the name of metavariables which are possibly provided by the **envfrom**, **envto** or **headers** condition. Meta variables will be provided if the regular expressions contain named subgroups, see [python.re](https://docs.python.org/3/library/re.html) for details.
  If not set, no metavariables will be provided.

### Action types
Available action types:
##### add_header
Add new header.  
Options:
* **field**  
  Name of the header.
* **value**  
  Value of the header.

##### del_header
Delete header(s).  
Options:
* **field**  
  Regular expression to match against header names.
* **value** (optional)  
  Regular expression to match against the headers value.

##### mod_header
Modify header(s).  
Options:
* **field**  
  Regular expression to match against header names.
* **search** (optional)  
  Regular expression to match against header values. You may use subgroups or named subgroups (python syntax) to include parts of the original value in the new value.
* **value**  
  New value of the header.

##### add_disclaimer
Append or prepend disclaimer to text and/or html body parts.  
Options:
* **action**  
  Action to perform with the disclaimer.  
  Possible values:
  * append
  * prepend
* **html_template**  
  Path to a file which contains the html representation of the disclaimer.
* **text_template**  
  Path to a file which contains the text representation of the disclaimer.
* **error_policy** (optional, default: "wrap")  
  Set the error policy in case the disclaimer cannot be added (e.g. if the html part cannot be parsed).  
  Possible values:
  * **wrap**  
    A new e-mail body is generated with the disclaimer as body and the original e-mail attached.
  * **ignore**  
    Ignore the error and do nothing.
  * **reject**  
    Reject the e-mail.
* **add_html_body** (optional, default: false)  
  Generate a html body with the content of the text body if no html body is present.

##### store
Store e-mail.  
Options:
* **storage**  
  Index of a Storage object in the global storages object.

##### notify
Send notification.  
Options:
* **notification**  
  Index of a Notification object in the global notifications object.

##### quarantine
Quarantine e-mail.  
Options:
* **storage**  
  Index of a Storage object in the global storages object.
  If the option **metadata** is not specifically set for this storage, it will be set to true.
* **smtp_host**  
  SMTP host used to release e-mails from quarantine.
* **smtp_port**  
  SMTP port used to release e-mails from quarantine.
* **notification** (optional)  
  Index of a Notification object in the global notifications object.
* **milter_action** (optional)  
  Milter action to perform. If set, no further rules or actions will be processed.  
  Please think carefully what you set here or your MTA may do something you do not want it to do.  
  Possible values:
  * **ACCEPT**  
    Tell the MTA to continue processing the e-mail.
  * **REJECT**  
    Tell the MTA to reject the e-mail.
  * **DISCARD**  
    Tell the MTA to silently discard the e-mail.
* **reject_reason** (optional, default: "Message rejected")  
  Reject message sent to MTA if milter_action is set to reject.
* **allowlist** (optional)  
  Ignore e-mails for which the given list has an entry for the envelope-from and envelope-to address combination, see section [List](#List) for details.  
  If an e-mail as multiple recipients, the decision is made per recipient.

### Storage types
Available storage types:
##### file
File storage.  
Options:
* **directory**  
  Directory used to store e-mails.
* **metadata** (optional, default: false)  
  Store metadata file.
* **mode**  (optional, default: system default)  
  File mode when new files are created.

### Notification types
Available notification types:
##### email
Generate an e-mail notification based on a template and send it to the original recipient.  
Available template variables:
* **{ENVELOPE_FROM}**  
  Sender address received by the milter.
* **{ENVELOPE_FROM_URL}**  
  Like ENVELOPE_FROM, but URL encoded.
* **{ENVELOPE_TO}**  
  Recipient address of this notification.
* **{ENVELOPE_TO_URL}**  
  Like ENVELOPE_TO, but URL encoded.
* **{FROM}**  
  Value of the FROM header of the e-mail.
* **{TO}**  
  Value of the TO header of the e-mail.
* **{SUBJECT}**  
  Configured e-mail notification subject.
* **{HTML_TEXT}**  
  Sanitized version of the e-mail text part of the e-mail. Only harmless HTML tags and attributes are included. Images are optionally stripped or replaced with the image set by **repl_img** option.

Additionally, every metavariable set by previous conditions or actions are also available as template variables. This is useful to include additional information (e.g. virus names, spam points, ...) within the notification.  

Options:
* **smtp_host**  
  SMTP host used to send notifications.
* **smtp_port**  
  SMTP port used to send notifications.
* **envelope_from**  
  Envelope-From address.
* **from_header**  
  Value of the From header. You may use the template variable **{FROM}**.
* **subject**  
  Subject of the notification e-mail. You  may use the template variable **{SUBJECT}**.
* **template**  
  Path to the HTML template.  
* **strip_imgs** (optional, default: false)  
  Strip images from e-mail. This option superseeds **repl_img**.
* **repl_img** (optional)  
  Image used to replace all images in the e-mail HTML part.
* **embed_imgs** (optional)  
  List of images to embed into the notification e-mail. The Content-ID of each image will be set to the filename, so you can reference it from the e-mail template.

### List types
Available list types:
##### db
List stored in database. The table is created automatically if it does not exist yet.  
Options:
* **connection**  
  Database connection string, see [Peewee Playhouse Extension](https://docs.peewee-orm.com/en/latest/peewee/playhouse.html#db-url).
* **table**  
  Database table to use.

### Integration with MTA
For integration with Postfix, see [Postix Milter Readme](http://www.postfix.org/MILTER_README.html).  
For integration with sendmail, see [Pymilter Sendmail Readme](https://pythonhosted.org/pymilter/milter_api/installation.html#config).

## Examples
Here are some config examples.

### Virus and spam quarantine for incoming e-mails
In this example it is assumed, that another milter (e.g. Amavisd or Rspamd) adds headers to spam and virus e-mails.
```json
{
    "socket": "unix:/tmp/pyquarantine.sock",
    "storages": {
        "virus": {
            "type": "file",
            "directory": "/mnt/data/quarantine/virus"
        },
        "spam": {
            "type": "file",
            "directory": "/mnt/data/quarantine/spam"
        }
    },
    "notifications": {
        "virus": {
            "type": "email",
            "smtp_host": "localhost",
            "smtp_port": 2525,
            "envelope_from": "notifications@example.com",
            "from_header": "{FROM}",
            "subject": "[VIRUS] {SUBJECT}",
            "template": "/etc/pyquarantine/templates/notification.template",
            "repl_img": "/etc/pyquarantine/templates/removed.png"
        },
        "spam": {
            "type": "email",
            "smtp_host": "localhost",
            "smtp_port": 2525,
            "envelope_from": "notifications@example.com",
            "from_header": "{FROM}",
            "subject": "[SPAM] {SUBJECT}",
            "template": "/etc/pyquarantine/templates/notification.template",
            "repl_img": "/etc/pyquarantine/templates/removed.png"
        }
    },
    "rules": [
        {
            "name": "inbound",
            "conditions": {
                "local": false
            },
            "actions": [
                {
                    "name": "virus",
                    "type": "quarantine",
                    "conditions": {
                        "headers": ["^X-Virus: Yes"]
                    },
                    "options": {
                        "storage": "virus",
                        "notification": "virus",
                        "smtp_host": "localhost",
                        "smtp_port": 2525,
                        "milter_action": "REJECT",
                        "reject_reason": "Message rejected due to virus"
                    }
                }, {
                    "name": "spam",
                    "type": "quarantine",
                    "conditions": {
                        "headers": ["^X-Spam: Yes"]
                    },
                    "options": {
                        "storage": "spam",
                        "notification": "spam",
                        "smtp_host": "localhost",
                        "smtp_port": 2525,
                        "milter_action": "DISCARD"
                    }
                }
            ]
        }
    ]
}
```
### Mark subject of incoming e-mails and remove the mark from outgoing e-mails
```json
{
    "socket": "unix:/tmp/pyquarantine.sock",
    "rules": [
        {
            "name": "inbound",
            "conditions": {
                "local": false
            },
            "actions": [
                {
                    "name": "add_subject_prefix",
                    "type": "mod_header",
                    "options": {
                        "field": "^(Subject|Thread-Topic)$",
                        "search": "^(?P<subject>.*)",
                        "value": "[EXTERNAL] \\g<subject>"
                    }
                }
            ]
        }, {
            "name": "outbound",
            "conditions": {
                "local": true
            },
            "actions": [
                {
                    "name": "remove_subject_prefix",
                    "type": "mod_header",
                    "options": {
                        "field": "^(Subject|Thread-Topic)$",
                        "search": "^(?P<prefix>.*)\\[EXTERNAL\\] (?P<suffix>.*)$",
                        "value": "\\g<prefix>\\g<suffix>"
                    }
                }
            ]
        }
    ]
}
```
### Store an exact copy of all incoming e-mails in directory
```json
{
    "socket": "unix:/tmp/pyquarantine.sock",
    "storages": {
        "orig": {
            "type": "file",
            "directory": "/mnt/data/incoming",
            "original": true
        }
    },
    "rules": [
        {
            "name": "inbound",
            "conditions": {
                "local": false
            },
            "actions": [
                {
                    "name": "store_original",
                    "type": "store",
                    "options": {
                        "storage": "orig"
                    }
                }
            ]
        }
    ]
}
```

## Developer information
Everyone who wants to improve or extend this project is very welcome.
