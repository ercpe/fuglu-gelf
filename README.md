# fuglu-gelf

`fuglu-gelf` is a [fuglu](http://fuglu.org) plugin that logs the passing message with all informations to a [GELF](http://docs.graylog.org/en/2.1/pages/gelf.html) host.

## Configuration

After installation, make the following changes to your `fuglu.conf`

	[main]
	appenders=gelf

	[PluginAlias]
	gelf=fuglugelf.logger.GELFLogger

and restart fuglu. This will log every mail passing through fuglu to `localhost:12201` on loglevel `INFO`.

To configure the log level and/or the target host, add

	[GELFLogger]
	loglevel = DEBUG 
	gelf-host = 10.11.12.13
	gelf-port = 12345

to your `fuglu.conf` and restart fuglu.

## License

See LICENSE.txt
