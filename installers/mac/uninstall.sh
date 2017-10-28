#!/bin/sh

# don't run this script as sudo
if [ "$EUID" -eq 0 ] ; then
    echo "this script should only be run as a regular user, try again"
    exit 1
fi

# delete the launchctl links
launchctl unload com.splintermail.client.plist
rm "$HOME/Library/LaunchAgents/com.splintermail.client.plist"

# delete the com.splintermail.client.plist, leaving only the .recipe
rm com.splintermail.client.plist

# delete config files and such if they exist
[ -f "$HOME/.splintermail.gpg" ] && rm $HOME/.splintermail.gpg
[ -d "$HOME/.ditm" ] && rm -r $HOME/.ditm

# delete /usr/local/bin/splintermail if it exists
if [ -f "/usr/local/bin/splintermail" ] ; then
    echo "now deleting splintermail from /usr/local/bin"
    rm /usr/local/bin/splintermail
fi

# delete command line completions if they exist
if [ -f "/usr/local/etc/bash_completion.d/splintermail" ] ; then
    echo "now deleting bash command line completion file"
    rm /usr/local/etc/bash_completion.d/splintermail
fi

if [ -f "/usr/local/share/zsh/site-functions/_splintermail" ] ; then
    echo "now deleting zsh command line completion file"
    rm /usr/local/share/zsh/site-functions/_splintermail
fi

