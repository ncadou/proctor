proctor
=======

Proctor is an HTTP proxy that will distribute requests across a number of Tor
circuits, in a round-robin fashion.

The Tor circuits are monitored for their health and restarted as appropriate.

This is highly experimental software that likely misses a lot of corner
cases. Use at your own risk.

Credits
=======

This package is built on top of two awesome projects:
* pymiproxy (Nadeem Douba)
  https://github.com/allfro/pymiproxy
* SocksiPy-branch (several people, original author was Dan-Haim)
  http://code.google.com/p/socksipy-branch/