CrewCraft server
================

Self-hosted team chat on a server you own. The server answers only devices it has enrolled: a connection without a
device certificate it issued gets a closed connection and no bytes.

This archive holds the server program, the license files (CrewCraft is MIT OR Apache-2.0, at your option) and this
file. The program is unsigned in the beta releases. Check the download against SHA256SUMS.txt from the same release.


First run
---------

Create the installation once, in a new data directory, from an interactive terminal:

    crewcraft-server first-run <data-dir> --name <server-name> --admin <email> [--listen <address:port>]

<server-name> is the DNS name or IP address the clients connect to; the server's certificate is issued for it. The
default listen address is 127.0.0.1:7443; use 0.0.0.0:7443 (or a specific address) to accept other machines.
first-run refuses an existing directory. It writes the installation's trust root (trust-root.der) and its settings
(server.conf), and prints the trust root's SHA-256 and the administrator's invitation:

    crewcraft://enroll?server=<name:port>&code=<code>&root_sha256=<hex>

The invitation code is shown only in a private, interactive terminal. Enroll the administrator's desktop client
with it.


Serve
-----

    crewcraft-server serve <data-dir>

serves with the recorded name and listen address until it is interrupted. Run it as a service of your system (for
example a systemd unit on Linux) with the data directory readable only by the account that runs it.


Invite people and make rooms
----------------------------

    crewcraft-server invite <data-dir> <email>
    crewcraft-server room <data-dir> <owner-email> <room-name>
    crewcraft-server add-member <data-dir> <room> <owner-email> <member-email>

Each invitation prints a one-time code for that person's device. More: https://github.com/SetsuaD/crewcraft-oss
