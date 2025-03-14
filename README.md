# nightwatch

> [!NOTE]
> This software is provided by DCSO as Free Software without the
> explicit intention or expectation of providing support or further ongoing
> development activities. We will consider contributions if they are of use to
> the community if time allows but will not take feature requests.

Nightwatch is a plugin-based file analysis framework for Suricata file stores.

The Nightwatch daemon looks for new files in the Suricata file extraction target
directory and calls various plugins to analyze them. JSON reports for every
scanned file as well as the plugin output can be forwarded to an AMQP consumer
for further analysis and storage. Nightwatch currently only supports AMQP (e.g.
RabbitMQ) as an output target.

## Current plugins

* _yarascan_: scans files with a YARA ruleset downloaded from a given URL

## Building the daemon

As the YARA plugin needs the YARA library files to build, you need to install
them first (e.g. in Debian/Ubuntu):

```
apt install libyara-dev libmagic-dev
```

Nightwatch uses the default Go build system. To build the binary in the `build`
sub directory simply use the supplied Makefile:

```
make
```

The static build can be executed with:

```
./build/nightwatch -h
```

## Testing

The test suite uses the regular Go test framework and can be invoked by running:

```
make test
```

## Usage

The daemon depends on various software components to be fully functional:

* Suricata configured to extract files and dump it to `-dir`
* RabbitMQ running and accepting deliveries on `-amqpexch` for `-amqpuser` and
  `-amqppass`

This is a dump of the current command line parameters:

```
❯ ./build/nightwatch -h                                   
Usage of ./build/nightwatch:
  -amqpexch string
        Exchange to post messages to (default "nightwatch")
  -amqppass string
        Password for the AMQP connection (default "sensor")
  -amqpuri string
        Endpoint and port for the AMQP connection (default "localhost:5672")
  -amqpuser string
        User name for the AMQP connection (default "sensor")
  -data string
        Path for the file database (default "/var/lib/nightwatch/")
  -dir string
        Directory where suricata stores files (default "/var/log/suricata/files")
  -dummy
        Log verdicts to file instead of submitting to AMQP
  -log string
        Path for nightwatch log files (default "/var/log/")
  -logjson
        JSON log output
  -maxage duration
        max age of file before being cleaned up (default 8760h0m0s)
  -maxspace uint
        max total space used for files in MB (default 20000)
  -mproffile string
        Dump memory profiling information to file
  -proffile string
        Dump profiling information to file
  -profsrv
        Enable profiling server on port 6060
  -rescantime duration
        rescan files older than time period (default 72h0m0s)
  -rule-file string
        Path for compiled YARA rule file
  -rule-uri string
        Download URL for YARA rules (default "http://localhost/yara/current.yac")
  -rule-xz
        YARA rules are XZ compressed
  -socket string
        Path for fileinfo EVE input socket (default "/tmp/files.sock")
  -storeversion int
        Filestore version (default 2)
  -uploadaccesskey string
        Access key for S3 upload
  -uploadbucket string
        Bucket name for S3 upload
  -uploadendpoint string
        Endpoint for suspicious file S3 upload
  -uploadregion string
        Region for S3 upload
  -uploadscratchdir string
        Temp directory for S3 upload (default "/tmp/nightwatch_scratch")
  -uploadsecretaccesskey string
        Secret access key for S3 upload
  -uploadssl
        Use SSL for S3 upload
  -verbose
        Verbose output
```

## Running Nightwatch as a service

The `nightwatch.service` file is included to run Nightwatch if installed in
`/usr/local/bin`. It can be placed in `/etc/systemd/system` to make it usable
for the whole system (run `systemctl daemon-reload` afterwards to pick it up).
The `nightwatch.default` file can be copied to `/etc/default/nightwatch` for
easier configuration of parameters and already contains some defaults for
`-maxspace` and `-log`.

## Run-time control of the service

Once running, the behaviour of the service can be influenced by sending signals
to the `nightwatch` process:

* `SIGHUP`: reinitialize all plugins, e.g. reloading YARA rules
* `SIGUSR1`: rescans all files, without cleaning the existing database
* `SIGUSR2`: rescans all files from scratch, overwriting the existing database
