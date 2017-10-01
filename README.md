# Why Splintermail?
Traditional email encryption does not encrypt the "To", "From", or "Subject" fields, but Splintermail.com encrypts *everything* to a public key which you provide.  We offer complete encryption, without breaking your favorite email client.

# What's inside

- `ditm.py` implements the Splintermail.com "Decrypter-in-the-middle" (DITM) model for offering fully-encrypted email while still supporting a standard POP3 interface.  DITM is necessary for an unmodified email client to access completely encrypted email from Splintermail.com.

- `splintermail` is command-line client to the Splintermail.com REST API.  With `splintermail`, a new free email alias can be created by simply running the command:

        splintermail new_free_alias

# Pre-installation

Before installation, you must have working `gpg` installation and must have generated valid GPG key pair.  For Windows users, we recommend [Gpg4win](www.gpg4win.org).

Linux users must also have a working installation of `python3`.  Also note that only systemd-based Linux installations are currently supported by the Linux installer script.


# Installation

## Windows
Double-click the batch script `install.bat` found in the `installers/windows` folder.

## Linux
Execute the shell script `install.sh` found in the `installers/linux` directory.

## Mac
`ditm.py` and `splintermail` should run on a Mac with `python3` and `gpg` installed, but we do not yet have a Mac installer script.

# Post Installation:

Enable full encryption of your email on Splintermail's server by uploading your GPG public key.  At the command line (`cmd.exe` for Windows) run the command:

    splintermail add_public_key you@email.com

where `you@email.com` is any email address associated with the GPG public key you want to upload.

# Connecting an email client

The DITM service presents a local POP3 interface for your email client:

    Interface:  POP3
    Host:       localhost
    Port:       1995
    Encryption: none* (see Security Note, below)
    Username:   your full Splintermail.com email address
    Password:   your Splintermail.com password

Your email client should send emails through a normal SMTPS interface:

    Interface:  SMTP or SMTPS
    Host:       splintermail.com
    Port:       465
    Encryption: SSL
    Username:   your full Splintermail.com email address
    Password:   your Splintermail.com password

### \*Security Note
Because the local POP3 interface is only for connections between your email client and the DITM service on your local machine, SSL is not enabled by default.  Most email clients *will* complain about the lack of an encrypted connection, because they do not make automatic security exceptions for connections that stay within the local machine.  Note that all connections between DITM and the Splintermail.com server use SSL encryption.

    -----POP3 Transport Security with Splintermail.com's DITM model: -----
                                    _____________________________________
     ______________                |        Your Local Machine           |
    |              |   Always      |  ______                  _________  |
    | Splintermail | SSL encrypted | | DITM | not encrypted, |  Email  | |
    |   Server   <=====================>  <-------------------> Client | |
    |______________|               | |______| but local only |_________| |
                                   |_____________________________________|
