zfsguru-webserver
=================

Proposal for a tiny zfsguru webserver

Possible settings:
```
"log-level": 4,
"pid-file": "/var/log/zfsguru/pilight.pid",
"config-file": "/etc/zfsguru/config.json",
"log-file": "/var/log/zfsguru.log",
"webserver-enable": 1,
"webserver-root": "/usr/local/share/www/",
"webserver-port": 80,
"webserver-cache": 1,
"webserver-authentication": 0,
"webserver-username": "",
"webserver-password": "",
"whitelist": "",
```

To compile:
```
cmake .
make install
```

Command line arguments:
```
Usage: zfsguru-daemon [options]
         -H --help              display usage summary
         -V --version           display version
         -S --settings          settings file
         -D --nodaemon          do not daemonize and
                                show debug information
```