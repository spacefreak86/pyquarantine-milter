# pymodmilter
A pymilter based sendmail/postfix pre-queue filter with the ability to add, remove and modify e-mail headers.  
The project is currently in beta status, but it is already used in a productive enterprise environment which processes about a million e-mails per month.  

The basic idea is to define rules with conditions and do modifications when all conditions are met.

## Dependencies
Pymodmilter is depending on these python packages, but they are installed automatically if you are working with pip.
* [pymilter](https://pythonhosted.org/pymilter/)
* [netaddr](https://github.com/drkjam/netaddr/)

## Installation
* Install pymodmilter with pip and copy the example configuration file.
```sh
pip install pymodmilter
cp /usr/share/doc/pymodmilter/pymodmilter.conf.example /etc/pymodmilter.conf
```
* Modify /etc/pymodmilter.conf according to your needs.

## Configuration options
Pymodmilter uses a configuration file in JSON format. The options are described below. Make a copy of the [example configuration file](https://github.com/spacefreak86/pymodmilter/blob/master/docs/pymodmilter.conf.example) in the  [docs](https://github.com/spacefreak86/pymodmilter/tree/master/docs) folder to start with.  
Rules and modifications are processed in the given order.

### Global
The following global configuration options are optional:
* **socket**  
  The socket used to communicate with the MTA.
* **local_addrs**  
  A list of hosts and network addresses which are considered local. It is used to for the condition option [local](#Conditions). This option may be overriden within a rule object.
* **log**  
  Enable or disable logging. This option may be overriden by a rule or modification object.

### Rules
The following configuration options are mandatory for each rule:
* **modifications**  
  A list of modification objects which are processed in the given order.

The following configuration options are optional for each rule:
* **name**  
  Name of the rule.
* **conditions**  
  A list of conditions which all have to be true to process the rule.
* **local_addrs**  
  As described above in the [Global](#Global) section.
* **log**  
  As described above in the [Global](#Global) section.

### Modifications
The following configuration options are mandatory for each modification:
* **type**  
  Set the modification type. Possible values are:
  * **add_header**
  * **del_header**
  * **mod_header**

The following configuration options are mandatory based on the modification type in use.
* **add_header**  
  * **header**  
    Name of the header.
  * **value**  
    Value of the header.

* **del_header**  
  * **header**  
    Regular expression to match against header lines.

* **mod_header**  
  * **header**  
    Regular expression to match against header lines.
  * **search**  
    Regular expression to match against the value of header lines. You may use subgroups or named subgroups (python syntax) to include parts of the original value in the new value.
  * **value**  
    New value of the header.

The following configuration options are optional for each modification:
* **name**  
  Name of the modification.
* **log**  
  As described above in the global object section.

### Conditions
The following condition options are optional:
* **local**  
  If set to true, the rule is only executed for emails originating from addresses defined in local_addrs and vice versa.
* **hosts**  
  A list of hosts and network addresses for which the rule should be executed.
* **envfrom**  
  A regular expression to match against the evenlope-from addresses for which the rule should be executed.

## Developer information
Everyone who wants to improve or extend this project is very welcome.
