proctor
=======

Proctor is an HTTP proxy that will distribute requests across a number of Tor
circuits, in a round-robin fashion.

The Tor circuits are monitored for their health and restarted as appropriate.

This is highly experimental software that likely misses a lot of corner
cases. The main author is a newbie in the subject matter, and while he had a
lot of fun doing this thing (which works well for his own use), use it at your
own risk.

Credits
=======

The original idea comes from this article from Sebastian Wain:
http://blog.databigbang.com/distributed-scraping-with-multiple-tor-circuits/

This package is built on top of two awesome projects:
* pymiproxy (Nadeem Douba)
  https://github.com/allfro/pymiproxy
* SocksiPy-branch (several people, original author was Dan-Haim)
  http://code.google.com/p/socksipy-branch/
