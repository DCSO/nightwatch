# nightwatch

> [!NOTE]
> This software is provided by DCSO as Free Software without the
> explicit intention or expectation of providing support or further ongoing
> development activities. We will consider contributions if they are of use to
> the community if time allows but will not take feature requests.

Nightwatch is a plugin-based file analysis framework for Suricata file stores.

The Nightwatch daemon reacts to files carved from traffic by Suricata's file
extraction functionality, calling various plugins to analyze them. JSON reports
for every scanned file, including all plugin output, can be forwarded to an AMQP
consumer for further analysis and storage. Moreover, files marked as suspicious
can optionally also be uploaded to an S3-compatible file store for later
centralized analysis.

## Current plugins

* _yarascan_: scans files with a YARA ruleset downloaded from a given URL

## Building the daemon

As the YARA plugin needs the YARA library files to build, you need to install
them first (e.g. in Debian/Ubuntu):

```
apt install libyara-dev libmagic-dev
```

Nightwatch uses the regular Go build system. To build the binary in the `build`
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

## Suricata Configuration

Note that Suricata needs libmagic support to support the identification of
executables from carved files.

### Additional EVE Output

Nightwatch builds a scanning backlog from Suricata `fileinfo` events: it
receives an EVE (Extensible Event Format) notification for each extracted file
and runs the plugins on them. In order to ensure that `fileinfo` events are
included in the output and also to reduce load on Nightwatch having to process
potentially thousands of non-`fileinfo` events per second, it is best to add a
dedicated EVE output to the Suricata configuration in `suricata.yaml`:

```yaml
outputs:

[...]

  # for nightwatch we log file events to a socket
  - eve-log:
      enabled: yes
      filetype: unix_stream
      filename: /tmp/files.sock
      types:
        - files:
            force-magic: no

[...]
```

We then configure this socket as the input for Nightwatch (`-socket` parameter).

### Ruleset Additions

Suricata needs to run some rules which detect executables in carved files and
cause them to be dumped to the filestore on disk:
```
alert http any any -> any any (msg:"FILE magic - Windows executable"; file.magic; content:"for MS Windows"; filestore; noalert; sid:1; rev:1;)
alert smtp any any -> any any (msg:"FILE magic - Windows executable"; file.magic; content:"for MS Windows"; filestore; noalert; sid:2; rev:1;)
alert smb any any -> any any (msg:"FILE magic - Windows executable"; file.magic; content:"for MS Windows"; filestore; noalert; sid:3; rev:1;)
alert nfs any any -> any any (msg:"FILE magic - Windows executable"; file.magic; content:"for MS Windows"; filestore; noalert; sid:4; rev:1;)
alert ftp-data any any -> any any (msg:"FILE magic - Windows executable"; file.magic; content:"for MS Windows"; filestore; ftpdata_command:stor; noalert; sid:5; rev:1;)
```
These can be extend as desired to support other architectures or binary types.


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

## License

3-clause BSD, see [LICENSE](LICENSE)
