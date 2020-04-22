# pymodmilter
A pymilter based sendmail/postfix pre-queue filter with the ability to add, remove and modify e-mail headers.  
The project is currently in beta status, but it is already used in a productive enterprise environment which processes about a million e-mails per month.  

The basic idea is to define rules with conditions and do modifications when all conditions are met.

## Requirements
* pymilter <https://pythonhosted.org/pymilter/>
* netaddr <https://github.com/drkjam/netaddr/>

## Configuration
Pymodmilter uses a configuration file in JSON format. The options are described below. Make a copy of the example configuration file in the docs folder to start with.  

### global (Object)
The following optional global configuration options are available:
* **local_addrs (Array of Strings)**  
  A list of hosts and network addresses which are considered local. It is used to for the condition option 'local'. This option may be overriden within a rule object.
* **log (Bool)**  
  Enable or disable logging. This option may be overriden by a rule or modification object.

### rules (Array)
A mandatory list of rule objects which are processed in the given order.

### rule (Object)
The following configuration options are mandatory for each rule:
* **modifications (Array of Objects)**  
  A list of modification objects which are processed in the given order.

The following configuration options are optional for each rule:
* **name (String)**  
  Name of the rule.
* **conditions (Object)**  
  A list of conditions which all have to be true to process the rule.
* **local_addrs (Array of Strings)**  
  As described above in the global object section.
* **log (Bool)**  
  As described above in the global object section.

### modification (Object)
The following configuration options are mandatory for each modification:
* **type (String)**  
  Set the modification type. Possible values are:
  * **add_header**
  * **del_header**
  * **mod_header**

Additional parameters are mandatory based on the modification type.
* **add_header**  
  * **header (String)**  
    Name of the header.
  * **value (String)**  
    Value of the header.

* **del_header**  
  * **header (String)**  
    Regular expression to match against header lines.

* **mod_header**  
  * **header (String)**  
    Regular expression to match against header lines.
  * **search (String)**  
    Regular expression to match against the value of header lines. You may use subgroups or named subgroups (python syntax) to include parts of the original value in the new value.
  * **value (String)**  
    New value of the header.

The following configuration options are optional for each modification:
* **name (String)**  
  Name of the modification.
* **log (Bool)**  
  As described above in the global object section.

### conditions (Object)
The following configuration options are optional:
* **local (Bool)**  
  If set to true, the rule is only executed for emails originating from addresses defined in local_addrs and vice versa.
* **hosts (Array of Strings)**  
  A list of hosts and network addresses for which the rule should be executed.
* **envfrom (String)**  
  A regular expression to match against the evenlope-from addresses for which the rule should be executed.

## Developer information
Everyone who wants to improve or extend this project is very welcome.
