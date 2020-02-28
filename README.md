# pyquarantine-milter
A pymilter based sendmail/postfix pre-queue filter with the ability to quarantine e-mails, sending notifications
to recipients and respond with a milter-action (ACCEPT, DISCARD or REJECT).

It is useful in many cases because of its felxible configuration and the ability to handle any number of quarantines.
The MTA can check e-mail headers using regular expressions to determine if and which quarantine to use. 
Each quarantine can be configured with a quarantine type, notification type, whitelist and an action to respond with.

Addionally, pyquarantine-milter provides a sanitized, harmless version of the text parts of e-mails, which can be embedded in e-mail notifications. This makes it easier for users to decide, if a match is a false-positive or not. If a matching quarantine provides a quarantine ID of the original e-mail, it is also available as a template variable. This is useful if you want to add links to a webservice to notification e-mails, to give your users the ability to release e-mails or whitelist the from-address for example. The webservice then releases the e-mail from the quarantine.

The project is currently in beta status, but it is already used in a productive enterprise environment which processes about a million e-mails per month.

## Requirements
* pymilter <https://pythonhosted.org/pymilter/>
* netaddr <https://github.com/drkjam/netaddr/>
* peewee <https://github.com/coleifer/peewee/>
* BeautifulSoup <https://www.crummy.com/software/BeautifulSoup/>

## Configuration
The pyquarantine module uses an INI-style configuration file. The sections are described below. If you have to specify a path in the config, you can always use a relative path to the last loaded config file.

### Section "global"
Any available configuration option can be set in the global section as default instead of in a quarantine section.  

The following configuration options are mandatory in the global section:
* **quarantines**  
  Comma-separated, ordered list of active quarantines. For each, there must be a section of the same name in the configuration.
* **preferred_quarantin_action**  
  Defines which quarantine action should be preferred if multiple quarantines are matching for multiple recipients.  
  If at least one recipient receives the original e-mail due to whitelisting, the action is always ACCEPT.
  Possible values are:
  * **first**
  * **last**

### Quarantine sections
The following configuration options are mandatory in each quarantine section:
* **regex**  
  Case insensitive regular expression to filter e-mail headers.
* **storage_type**  
  One of the storage types described below.
* **action**  
  One of the actions described below.
* **notification_type**  
  One of the notification types described below.
* **whitelist_type**  
  One of the whitelist types described below.
* **smtp_host**  
  SMTP host used to release original e-mails from the quarantine.
* **smtp_port**  
  SMTP port

The following configuration options are optional in each quarantine section:
* **host_whitelist**  
  Comma-separated list of host and network addresses to be ignored by this quarantine.
* **reject_reason**  
  Reason to return to the client if action is set to reject.


### Storage types
* **NONE**  
  Original e-mails scrapped, sent to nirvana, black-holed or however you want to call it.

* **FILE**  
  Original e-mails are stored on the filesystem with a unique filename. The filename is available as a
  template variable used in notifiaction templates.  
  The following configuration options are mandatory for this quarantine type:
  * **storage_directory**  
    The directory in which quarantined e-mails are stored.


### Notification types
* **NONE**  
  No quarantine notifications will be sent.

* **EMAIL**  
  Quarantine e-mail notifications are sent to recipients. The SMTP host and port, E-mail template, from-address and the subject are configurable for each quarantine. The templates must contain the notification e-mail text in HTML form.  

  The following template variables are available:
  * **{EMAIL_ENVELOPE_FROM}**  
    E-mail sender address received by the milter.
  * **{EMAIL_ENVELOPE_FROM_URL}**  
    Like EMAIL_ENVELOPE_FROM, but URL encoded
  * **{EMAIL_FROM}**  
    Value of the FROM header of the original e-mail.
  * **{EMAIL_ENVELOPE_TO}**  
    E-mail recipient address of this notification.
  * **{EMAIL_ENVELOPE_TO_URL}**  
    Like EMAIL_ENVELOPE_TO, but URL encoded
  * **{EMAIL_TO}**  
    Value of the TO header of the original e-mail.
  * **{EMAIL_SUBJECT}**  
    Configured e-mail subject.
  * **{EMAIL_QUARANTINE_ID}**  
    Quarantine-ID of the original e-mail if available, empty otherwise.
  * **{EMAIL_HTML_TEXT}**  
    Sanitized version of the e-mail text part of the original e-mail. Only harmless HTML tags and attributes are included. Images are optionally stripped or replaced with the image set by notification_email_replacement_img option.

  Some template variables are only available if the regex of the matching quarantine contains subgroups or named subgroups (python syntax). This is useful to include information (e.g. virus names, spam points, ...) of the matching header within the notification.  
  The following dynamic template variables are available:
  * **{SUBGROUP_n}**  
    Content of a subgroup, 'n' will be replaced by the index number of each subgroup, starting with 0.
  * **{subgroup_name}**  
    Content of a named subgroup, 'subgroup_name' will be replaced by its name.

  The following configuration options are mandatory for this notification type:
  * **notification_email_smtp_host**  
    SMTP host used to send notification e-mails.
  * **notification_email_smtp_port**  
    SMTP port.
  * **notification_email_envelope_from**  
    Notification e-mail envelope from-address.
  * **notification_email_from**  
    Value of the notification e-mail from header. Optionally, you may use the EMAIL_FROM template variable described above.
  * **notification_email_subject**  
    Notification e-mail subject. Optionally, you may use the EMAIL_SUBJECT template variable described above.
  * **notification_email_template**  
    Path to the notification e-mail template. It is hold in memory during runtime.
  * **notification_email_embedded_imgs**  
    Comma-separated list of images to embed into the notification e-mail. The Content-ID of each image will be set to the filename, so you can reference it from the e-mail template. All images are hold in memory during runtime.  
    Leave empty to disable.

  The following configuration options are optional for this notification type:
  * **notification_email_strip_images**  
    Enable to strip images from e-mails. This option superseeds notification_email_replacement_img.
  * **notification_email_replacement_img**  
    Path to an image to replace images in e-mails. It is hold in memory during runtime.
  * **notification_email_parser_lib**  
    HTML parser library used to parse text part of emails.


### Actions
Every quarantine responds with a milter-action if an e-mail header matches the configured regular expression. Please think carefully what you set here or your MTA will do something you do not want.  
The following actions are available:
* **ACCEPT**  
  Tell the MTA to continue processing the e-mail.
* **DISCARD**  
  Tell the MTA to silently discard the e-mail.
* **REJECT**  
  Tell the MTA to reject the e-mail.


### Whitelist types
* **NONE**  
  No whitelist will be used.

* **DB**  
  A database whitelist will be used. All database types supported by peewee are available.  

  The following configuration options are mandatory for this whitelist type:
  * **whitelist_db_connection**  
  Database connection string (e.g. mysql://user:password@host:port).  

  * **whitelist_db_table**  
  Database table to use.

## Developer information
Everyone who wants to improve or extend this project is very welcome.
