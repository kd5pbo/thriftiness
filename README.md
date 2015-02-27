thriftiness
===========
Simple layer 2 VPN, still under development
-------------------------------------------

This documentation isn't very good at the moment.  If you intend to use
Thriftiness, please contact the author via email, kd5pbo@gmail.com, or on
Freenode as MagisterQuis.

More or less feature-complete for OpenBSD.  Not so much for other platforms.

Needs loads of testing, debugging, and documentation.  Oh, and bits written for
other Operating Systems :)

Insert
------
Insert is the remote side of thriftiness.  It sits on the target computer and
either beacons to Shift or waits for a connection from Shift.  Once it
establishes a connection with shft, after an initial handshake (see the file
named protocol), it inject ethernet frames (or whatever, really)  sent by Shift
to the network, and sends ethernet frames (or whatever it sniffs) back to
Shift.

Configuration of insert is, ideall, done at compile-time.  There are quite a
few settings in insert.h.  Of course, it's not practical to recompile every
deployment, so many settings are text fields with plenty of null padding and a
unique character at the end that can be manipulated with a hex editor (or dd if
you're brave).

Shift
-----
Shift creates a platform-dependent tunnel device (tun on OpenBSD).  If your
platform isn't supported, have a look at mktun_openbsd.go for an example.

After that, you should be able to compile and build Shift.  Use -h to list
the options.  If all goes well, after a connection with Insert is established
you should have an adapter that acts more or less like it's on the network
that Insert is on.

Cryptography
------------
The author knows very little about cryptography.  This code has not been
audited.  Please read the file named protocol for more details as to just how
data is encrypted.  The goal of the encryption is to stump a curious sysadmin.
It is likely that there is an attack or two against Thriftiness.  OpenSSL (and
LibreSSL) were considered, but decided against so that a static binary could be
kept to a reasonable size.

Windows
-------
Currently, neither part of Thriftiness will build on Windows.  Putting Shift on
Windows should be as simple as adding the appropriate mktun_ file (probably,
anyways).

Putting Insert on Windows is a much less clear proposition.  It makes use of
the pthread library for a thread and a couple of mutexes, as well as pcap.  It
should be possible to port it, but that's not something that's likely to
be done by the author.  
