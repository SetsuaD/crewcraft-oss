# Running a CrewCraft server

The server is one program, `crewcraft-server`, and one data folder that holds everything: its certificate authority,
accounts, rooms, journals, the settings `first-run` records and the public root certificate. Back up that folder; keep
it readable by the server's account only.

Only devices the server has enrolled get past the TLS handshake. Anything else, including a browser or a scanner, gets a
closed connection and no data.

## 1. Install

Download `crewcraft-server-<version>-<os>-<arch>` from the release page, check it against `SHA256SUMS.txt`, and unpack
it. On Linux, put the program somewhere on the system path:

```sh
sha256sum -c --ignore-missing SHA256SUMS.txt
tar -xzf crewcraft-server-0.1.0-beta.1-linux-x86_64.tar.gz
sudo install -m 0755 crewcraft-server-0.1.0-beta.1-linux-x86_64/crewcraft-server /usr/local/bin/
```

## 2. First run

Pick the name people's devices will use to reach the server (a DNS name, or an IP address) and the address to listen
on. In an interactive terminal:

```sh
crewcraft-server first-run /var/lib/crewcraft --name chat.example.org --admin admin@example.org --listen 0.0.0.0:7443
```

It prints the administrator's invitation as a `crewcraft://enroll?...` link. The link holds a one-time secret: send it
to the administrator privately. Opening it in the desktop app enrolls their device.

For a scripted install (no terminal), write the invitation to a new file instead; the file is created readable by its
owner only, and an existing file is never overwritten:

```sh
crewcraft-server first-run /var/lib/crewcraft --name chat.example.org --admin admin@example.org \
  --listen 0.0.0.0:7443 --invitation-file /root/admin-invitation.txt
```

Delete the file once the person has enrolled. Behind port forwarding (listening on 7443, reached on 443, say), add
`--public-port 443` so invitations carry the port people actually connect to.

`first-run` never changes an existing folder.

## 3. Run it as a service (systemd)

Create a system account and give it the data folder:

```sh
sudo useradd --system --home /var/lib/crewcraft --shell /usr/sbin/nologin crewcraft
sudo install -d -o crewcraft -g crewcraft -m 0700 /var/lib/crewcraft-setup
sudo -u crewcraft crewcraft-server first-run /var/lib/crewcraft --name chat.example.org --admin admin@example.org \
  --listen 0.0.0.0:7443 --invitation-file /var/lib/crewcraft-setup/admin-invitation.txt
```

Send the invitation in `/var/lib/crewcraft-setup/admin-invitation.txt` to the administrator privately, then delete it.

`/etc/systemd/system/crewcraft-server.service`:

```ini
[Unit]
Description=CrewCraft server
After=network-online.target
Wants=network-online.target

[Service]
User=crewcraft
Group=crewcraft
ExecStart=/usr/local/bin/crewcraft-server serve /var/lib/crewcraft
Restart=on-failure
# The server stops cleanly on SIGTERM: it stops accepting, lets open requests finish and closes its journals.
KillSignal=SIGTERM
TimeoutStopSec=20
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/crewcraft
UMask=0077

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now crewcraft-server
journalctl -u crewcraft-server -f      # "CrewCraft listening on 0.0.0.0:7443 as chat.example.org:7443"
```

A port below 1024 needs `AmbientCapabilities=CAP_NET_BIND_SERVICE`; forwarding a high port is usually simpler.

## 4. People and rooms

Run these as the server's account. `invite` prints a new invitation (or writes it with `--invitation-file`):

```sh
sudo -u crewcraft crewcraft-server invite /var/lib/crewcraft person@example.org --invitation-file /var/lib/crewcraft-setup/person.txt
sudo -u crewcraft crewcraft-server room /var/lib/crewcraft admin@example.org General         # prints the room's name
sudo -u crewcraft crewcraft-server add-member /var/lib/crewcraft <room> admin@example.org person@example.org
```

They work while the server runs; there is no need to stop it. A running server listens on a control socket in its data
folder (`control.sock`), which only the server's own account can use, and the commands hand it their request: the
person can enroll at once, and a new member sees the room the next time their app lists rooms. With the server stopped,
the commands open the data folder themselves, as before. Run them as any other account and they are refused.

On Windows the server has no control socket yet: stop the service, run the commands, and start it again. Otherwise they
say the folder is in use. The same message on Linux or macOS means the server could not open its control socket (it
says why when it starts; a data folder path longer than about 100 characters is too long for one) or another command
is running.

## 5. Check that it is dark

From another machine, a client without an enrolled certificate gets nothing:

```sh
openssl s_client -connect chat.example.org:7443 -servername chat.example.org </dev/null
```

The handshake ends with "unexpected eof"; no application data is ever sent.
