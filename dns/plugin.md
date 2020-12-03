# Plugins

## Writing Plugins

The main method that gets called is `ServeDNS`. It has three parameters:

* a `context.Context`;
* `dns.ResponseWriter` that is, basically, the client's connection;
* `*dns.Msg` the request from the client.

`ServeDNS` returns two values, a response code and an error. If the error is not nil, CoreDNS
will return a SERVFAIL to the client. The response code tells CoreDNS if a *reply has been
written by the plugin chain or not*. In the latter case CoreDNS will take care of that.

CoreDNS treats:

* SERVFAIL (dns.RcodeServerFailure)
* REFUSED (dns.RcodeRefused)
* FORMERR (dns.RcodeFormatError)
* NOTIMP (dns.RcodeNotImplemented)

as special and will then assume *nothing* has been written to the client. In all other cases it
assumes something has been written to the client (by the plugin).

The [*example*](https://github.com/coredns/example) plugin shows a bare-bones implementation that
can be used as a starting point for your plugin. This plugin has tests and extensive comments in the
code.

## Hooking It Up

See a couple of blog posts on how to write and add plugin to CoreDNS:

* <https://blog.coredns.io/2017/03/01/how-to-add-plugins-to-coredns/>
* <https://blog.coredns.io/2016/12/19/writing-plugins-for-coredns/>, slightly older, but useful.

## Logging

If your plugin needs to output a log line you should use the `plugin/pkg/log` package. This package
implements log levels. The standard way of outputting is: `log.Info` for info level messages. The
levels available are `log.Info`, `log.Warning`, `log.Error`, `log.Debug`. Each of these also has
a `f` variant. The plugin's name should be included, by using the log package like so:

~~~ go
import clog "github.com/coredns/coredns/plugin/pkg/log"

var log = clog.NewWithPlugin("whoami")

log.Info("message") // outputs: [INFO] plugin/whoami: message
~~~

In general, logging should be left to the higher layers by returning an error. However, if there is
a reason to consume the error and notify the user, then logging in the plugin itself can be
acceptable. The `Debug*` functions only output something when the *debug* plugin is loaded in the
server.

## Metrics

When exporting metrics the *Namespace* should be `plugin.Namespace` (="coredns"), and the
*Subsystem* must be the name of the plugin. The README.md for the plugin should then also contain
a *Metrics* section detailing the metrics.

## Readiness

If the plugin supports signalling readiness it should have a *Ready* section detailing how it
works, and implement the `ready.Readiness` interface.

## Opening Sockets

See the plugin/pkg/reuseport for `Listen` and `ListenPacket` functions. Using these functions makes
your plugin handle reload events better.

## Documentation

Each plugin should have a README.md explaining what the plugin does and how it is configured. The
file should have the following layout:

* Title: use the plugin's name
* Subsection titled: "Name"
    with *PLUGIN* - one line description.
* Subsection titled: "Description" has a longer description.
* Subsection titled: "Syntax", syntax and supported directives.
* Subsection titled: "Examples"

More sections are of course possible.

### Style

We use the Unix manual page style:

* The name of plugin in the running text should be italic: *plugin*.
* all CAPITAL: user supplied argument, in the running text references this use strong text: `**`:
  **EXAMPLE**.
* Optional text: in block quotes: `[optional]`.
* Use three dots to indicate multiple options are allowed: `arg...`.
* Item used literal: `literal`.

### Example Domain Names

Please be sure to use `example.org` or `example.net` in any examples and tests you provide. These
are the standard domain names created for this purpose.

## Fallthrough

In a perfect world the following would be true for plugin: "Either you are responsible for a zone or
not". If the answer is "not", the plugin should call the next plugin in the chain. If "yes" it
should handle *all* names that fall in this zone and the names below - i.e. it should handle the
entire domain and all sub domains.

~~~ txt
. {
    file example.org db.example
}
~~~

In this example the *file* plugin is handling all names below (and including) `example.org`. If
a query comes in that is not a subdomain (or equal to) `example.org` the next plugin is called.

Now, the world isn't perfect, and there are may be reasons to "fallthrough" to the next plugin,
meaning a plugin is only responsible for a *subset* of names within the zone.

The `fallthrough` directive should optionally accept a list of zones. Only queries for records
in one of those zones should be allowed to fallthrough. See `plugin/pkg/fallthrough` for the
implementation.

## General Guidelines

Some general guidelines:

* logging time duration should be done in seconds (call the `Seconds()` method on any duration).
* keep logging to a minimum.
* call the main config parse function just `parse`.
* try to minimize the number of knobs in the configuration.
* use `plugin.Error()` to wrap errors returned from the `setup` function.

## Qualifying for Main Repo

Plugins for CoreDNS can live out-of-tree, `plugin.cfg` defaults to CoreDNS' repo but other
repos work just as well. So when do we consider the inclusion of a new plugin in the main repo?

* First, the plugin should be useful for other people. "Useful" is a subjective term. We will
  probably need to further refine this.
* It should be sufficiently different from other plugin to warrant inclusion.
* Current internet standards need be supported: IPv4 and IPv6, so A and AAAA records should be
  handled (if your plugin is in the business of dealing with address records that is).
* It must have tests.
* It must have a README.md for documentation.
