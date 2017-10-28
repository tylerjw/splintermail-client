#!/bin/sh

# don't run this script as sudo
if [ "$EUID" -eq 0 ] ; then
    echo "this script should only be run as a regular user, try again"
    exit 1
fi

# check to make sure we have GPG and python
gpg --version > /dev/null 2>&1 || (echo "gpg not found, please install" && exit)
python3 --version > /dev/null 2>&1 || (echo "python3 not found, please install" && exit)

# set path to python 3, with pyenv installed special which command should be used
PYTHON=$(pyenv which python3 2> /dev/null)
if [ -z $PYTHON ]; then PYTHON=$(which python3); fi
echo "using python3 located at "$PYTHON

GPGBIN=$(which gpg)
echo "using gpg located at "$GPGBIN

# first hardcode the current directory into the com.splintermail.client.plist
# this supports a non-root install
cat com.splintermail.client.plist.recipe |
    sed -e 's*PYTHON*'$PYTHON'*' |
    sed -e 's*GPGBIN*'$GPGBIN'*' |
    sed -e 's*HOME*'$HOME'*' > com.splintermail.client.plist

# next create the ~/.ditm directory if it does not already exist
echo "making the ~/.ditm directory"
mkdir -p "$HOME/.ditm"

echo "copying ditm.py into ~/.ditm"
cp ../../ditm.py "$HOME/.ditm/"

# now make self-signed certificates for SSL encryption (localhost to localhost only)
# this doesn't affect security a lot but makes thunderbird offer an SSL exception rather
# than a giant red "don't do this" warning
if [ -n "$(which openssl)" ] && \
    [ -f "$HOME/.ditm/splintermail-snakeoil-cert.pem" ] && \
     [ -f "$HOME/.ditm/splintermail-snakeoil-cert.pem" ] ; then
    echo "self-signed local-to-local-only SSL certificates already exist, skipping..."
else
    openssl req -x509 -newkey rsa:4096 \
        -keyout "$HOME/.ditm/splintermail-snakeoil-key.pem" \
        -out "$HOME/.ditm/splintermail-snakeoil-cert.pem" \
        -subj '/O=Splintermail Local-only Connection/CN=localhost' -nodes -days 3560
fi

# copy com.splintermail.client.plist
echo "copying com.splintermail.client.plist into ~/Library/LaunchAgents/"
cp `pwd`/com.splintermail.client.plist "$HOME/Library/LaunchAgents/com.splintermail.client.plist"

# load the launch agent
echo "loading the Launch Agent with launchctl"
launchctl load -w "$HOME/Library/LaunchAgents/com.splintermail.client.plist"

# copy splintermail to /usr/local/bin
echo "copying splintermail into /usr/local/bin"
cp ../../splintermail /usr/local/bin/

# copy command line completions into place
if [ -d "/usr/local/etc/bash_completion.d/" ] ; then
    echo "copying bash command line completion file into place"
    cp ../../cli_completion/bash/splintermail /usr/local/etc/bash_completion.d/
fi

if [ -d "/usr/local/share/zsh/site-functions" ] ; then
    echo "copying zsh command line completion file into place"
    cp ../../cli_completion/zsh/_splintermail /usr/local/share/zsh/site-functions
fi

