# Server

## Overview

There is a single application server that hosts an Apache site along with the
Python FastAPI application. The Apache site serves as a reverse proxy.

## Web Site SFTP Access

The web directory (`/var/www/scale.fresnostate.edu`) served by Apache can be
accessed from the on-campus network or the campus VPN using SFTP.

|              |                                                   |
|--------------|---------------------------------------------------|
| **host**     | stem-scale-app1.priv.fresnostate.edu              |
| **port**     | 22 (default)                                      |
| **username** | scale                                             |
| **password** | see LastPass **STEM-SCALE Project** shared folder |

### /etc/ssh/sshd_config

The following changes were made to the `sshd_config` to enable SFTP
for the `scale` user in a *chrooted* environment and to allow password
authentication. The SFTP subsystem is also changed to `internal-sftp`, which
is an in-process server and does not require running a separate process.

```
#Subsystem sftp /usr/libexec/openssh/sftp-server
Subsystem sftp internal-sftp

Match User scale
        ChrootDirectory /var/www/scale.fresnostate.edu
        PasswordAuthentication yes
        ForceCommand internal-sftp
        X11Forwarding no
        AllowTcpForwarding no
```

#### IMPORTANT NOTE

For the `ChrootDirectory` command to work, all parts of the path must be
`root` owned and no other user/group can have `write` access to any portion
of the path.

## PHP

The Dynamic Questions module (`/var/www/scale.fresnostate.edu/html/dyna`) uses
Laravel 9 and requires PHP 8.0+ and the following extensions to be installed.
It also requires the PostgreSQL driver for PHP in order to connect to the
Scale database as the `scale_dyna` user.

```bash
sudo amazon-linux-extras enable php8.0

sudo yum install -y php-cli \
  php-curl \
  php-bcmath \
  php-mbstring \
  php-xml \
  php-tokenizer \
  php-pdo \
  php-pcre \
  php-openssl \
  php-json \
  php-fileinfo \
  php-dom \
  php-ctype \
  php-pgsql
```
