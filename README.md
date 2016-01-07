nasltokens
==========
nasltokens is a utility to extract information from NASL plugins, and generate
an intermediate JSON policy file consumable by other tools for vulnerability
analysis. The format used is the intermediate scribe vulnerability policy
format. NASL plugins that focus on authenticate package tests are supported.

Usage
-----
Typical usage involves conversion of a NASL plugin file to the JSON format, and
subsequent execution of the policy through MIG/scribe to detect instances of
packages that are vulnerable to the information specified in the plugin. Listed
packages are vulnerable to a given check if the installed version is older than
then policy version.

```
% make
cc -Wall -g -c main.c
bison --defines -v grammar.y
cc -Wall -g -c grammar.tab.c
flex tokens.l
cc -Wall -g -c lex.yy.c
cc -o nasltokens main.o grammar.tab.o lex.yy.o
% ./nasltokens ~/openvas/2015/gb_RHSA-2015_1668-01_httpd.nasl
{
    "vulnerabilities": [
        {
            "os": "redhat",
            "release": "rhel6",
            "package": "httpd",
            "version": "2.2.15-47.el6_7"
        },
        {
            "os": "redhat",
            "release": "rhel6",
            "package": "httpd-debuginfo",
            "version": "2.2.15-47.el6_7"
        },
        {
            "os": "redhat",
            "release": "rhel6",
            "package": "httpd-devel",
            "version": "2.2.15-47.el6_7"
        },
        {
            "os": "redhat",
            "release": "rhel6",
            "package": "httpd-tools",
            "version": "2.2.15-47.el6_7"
        },
        {
            "os": "redhat",
            "release": "rhel6",
            "package": "mod_ssl",
            "version": "2.2.15-47.el6_7"
        },
        {
            "os": "redhat",
            "release": "rhel6",
            "package": "httpd-manual",
            "version": "2.2.15-47.el6_7"
        }
    ]
}
```
