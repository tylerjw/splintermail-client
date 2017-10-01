#!/bin/sh

# don't run this script as sudo
if [ "$EUID" -eq 0 ] ; then
    echo "this script should be run as your regular user," \
         "it will request sudo when necessary."
    exit 1
fi

# delete the systemctl links
systemctl --user disable ditm.service

# delete the ditm.service, leaving only the .recipe
rm ditm.service

# delete config files and such if they exist
[ -f "$HOME/.splintermail.gpg" ] && rm $HOME/.splintermail.gpg
[ -d "$HOME/.ditm" ] && rm -r $HOME/.ditm

# delete /usr/local/bin/splintermail if it exists
if [ -f "/usr/local/bin/splintermail" ] ; then
    echo "now deleting splintermail from /usr/local/bin, using sudo"
    sudo rm /usr/local/bin/splintermail
fi

# delete command line completions if they exist
if [ -f "/usr/share/bash-completion/completions/splintermail" ] ; then
    echo "now deleting bash command line completion file, using sudo"
    sudo rm /usr/share/bash-completion/completions/splintermail
fi

if [ -f "/usr/share/zsh/site-functions/_splintermail" ] ; then
    echo "now deleting zsh command line completion file, using sudo"
    sudo rm /usr/share/zsh/site-functions/_splintermail
fi

