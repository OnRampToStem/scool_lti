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
