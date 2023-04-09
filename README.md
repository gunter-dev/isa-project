# ISA Project - Netflow Exporter

This is a project for the ISA course - FIT VUT.

**Final evaluation:** 16.5/20

## Author

Jméno: Lukáš Vincenc \
Login: xvince01

## Usage

To start the project, open a terminal window and launch make:

```bash
$ make
```

Then you can launch the executable with some arguments:

```bash
$ ./flow [-f <file>] [-c <netflow_collector>[:port]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]
```

* `-f <file>` - the input file (if not specified, reads from STDIN)
* `-c <netflow_collector>[:port]` - the address of the netflow collector, to which the exported data will be sent, can also include port number (default netflow collector is 127.0.0.1:2055)
* `-a <active_timer>` - time in seconds after which active flows will be exported (60 by default)
* `-i <inactive_timer>` - time in seconds after which inactive flows will be exported (10 by default)
* `-m <count>` - the max number of flows, that can be stored in the flow cache at the same time (1024 by default)
