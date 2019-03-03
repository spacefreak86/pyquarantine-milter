# pyquarantine-milter
A pymilter based sendmail/postfix pre-queue filter with the ability to quarantine e-mails, sending notifications
to recipients and respond with a milter-action (ACCEPT, DISCARD or REJECT).

It is useful in many cases because of its felxible configuration and the ability to handle any number of quarantines.
The MTA can check e-mail headers using regular expressions to determine if and which quarantine to use. 
Each quarantine can be configured with a quarantine type, notification type, whitelist and an action to respond with.

Addionally, pyquarantine-milter provides a sanitized, harmless version of the text parts of e-mails, which can be embedded in e-mail notifications. This makes it easier for users to decide, if a match is a false-positive or not. If a matching quarantine provides a quarantine ID of the original e-mail, it is also available as a template variable. This is useful if you want to add links to a webservice to notification e-mails, to give your users the ability to release e-mails or whitelist the from-address for example. The webservice then releases the e-mail from the quarantine.

The project is currently in alpha status, but will soon be used in a productive enterprise environment and possibly existing bugs will be fixed.

## Requirements
* pymilter <https://pythonhosted.org/pymilter/>
* peewee <https://github.com/coleifer/peewee/>
* BeautifulSoup <https://www.crummy.com/software/BeautifulSoup/>

## Configuration
The pyquarantine module uses an INI-style configuration file. The sections are described below.

### Section "global"
Any available configuration option can be set in the global section as default instead of in a quarantine section.  

The following configuration options are mandatory in the global section:
* **quarantines**  
  Comma-separated, ordered list of active quarantines. For each, there must be a section of the same name in the configuration.
* **smtp_host**  
  SMTP host to inject original e-mails. This is needed if not all recipients of an e-mail are whitelisted
* **smtp_port**  
  SMTP port

### Quarantine sections
The following configuration options are mandatory in each quarantine section:
* **regex**  
  Regular expression to filter e-mail headers.
* **type**  
  One of the quarantine-types described below.
* **action**  
  One of the actions described below.
* **notification**  
  One of the notification types described below.
* **whitelist**  
  Database connection string (e.g. mysql://user:password@host:port) or NONE to disable whitelist.

### Quarantine types
* **NONE**  
  Original e-mails scrapped, sent to nirvana, black-holed or however you want to call it.

* **FILE**  
  Original e-mails are stored on the filesystem with a unique filename. The filename is available as a
  template variable used in notifiaction templates.  
  The following configuration options are mandatory for this quarantine type:
  * **directory**  
    The directory in which quarantined e-mails are stored.


### Notification types
* **NONE**  
  No quarantine notifications will be sent.

* **EMAIL**  
  Quarantine e-mail notifications are sent to recipients. The SMTP host and port, E-mail template, from-address and the subject are configurable for each quarantine. The templates must contain the notification e-mail text in HTML form.  

  The following template variables are available:
  * **{EMAIL_FROM}**  
    E-mail from-address received by the milter (envelope-from).
  * **{EMAIL_TO}**  
    E-mail recipient address of this notification.
  * **{EMAIL_SUBJECT}**  
    Configured e-mail subject.
  * **{EMAIL_QUARANTINE_ID}**  
    Quarantine-ID of the original e-mail if available, empty otherwise.
  * **{EMAIL_HTML_TEXT}**  
    Sanitized version of the e-mail text part of the original e-mail. Only harmless HTML tags and attributes are included. Images are replaced with the image set by notification_email_replacement_img option.

The following configuration options are mandatory for this notification type:
* **notification_email_from**  
  Notification e-mail from-address.
* **notification_email_subject**  
  Notification e-mail subject.
* **notification_email_template**  
  Notification e-mail template to use.
* **notification_email_replacement_img**  
  An image to replace images in e-mail.


### Actions
Every quarantine responds with a milter-action if an e-mail header matches the configured regular expression.  
The following actions are available:
* **ACCEPT**  
  Continue processing e-mails.
* **DISCARD**  
  Silently discard e-mails.
* **REJECT**  
  Reject e-mails.


### Whitelist
If a whitelist database connection string is configured, the following configuration options are mandatory:
* **whitelist_table**  
  Database table to use.

## Developer information
Everyone who wants to improve or extend this project is very welcome.
