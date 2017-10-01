#!/bin/sh

# don't run this script as sudo
if [ "$EUID" -eq 0 ] ; then
    echo "this script should be run as your regular user," \
         "it will request sudo when necessary."
    exit 1
fi

# check to make sure we have GPG and python
gpg --version > /dev/null 2>&1 || (echo "gpg not found, please install" && exit)
python3 --version > /dev/null 2>&1 || (echo "python3 not found, please install" && exit)

# first hardcode the current directory into the ditm.service
# this supports a non-root install
cat ditm.service.recipe | sed -e 's*CODEDIRECTORY*'$(cd ../.. && pwd)'*' > ditm.service

# next create the ~/.ditm directory if it does not already exist
mkdir -p $HOME/.ditm

# now make self-signed certificates for SSL encryption (localhost to localhost only)
# this doesn't affect security a lot but makes thunderbird offer an SSL exception rather
# than a giant red "don't do this" warning
if [ -n "$(which openssl)" ] && \
    [ -f "${HOME}/.ditm/splintermail-snakeoil-cert.pem" ] && \
     [ -f "${HOME}/.ditm/splintermail-snakeoil-cert.pem" ] ; then
    echo "self-signed local-to-local-only SSL certificates already exist, skipping..."
else
    openssl req -x509 -newkey rsa:4096 \
        -keyout ${HOME}/.ditm/splintermail-snakeoil-key.pem \
        -out ${HOME}/.ditm/splintermail-snakeoil-cert.pem \
        -subj '/O=Splintermail Local-only Connection/CN=localhost' -nodes -days 3560
fi

ln -sf `pwd`/ditm.service ${HOME}/.config/systemd/user/
ln -sf `pwd`/ditm.service ${HOME}/.config/systemd/user/default.target.wants
# enable/start systemd service
systemctl --user enable --now ditm.service
systemctl --user enable --now ditm.service

# copy splintermail to /usr/local/bin
echo "now copying splintermail into /usr/local/bin, using sudo"
sudo cp ../../splintermail /usr/local/bin/

# copy command line completions into place
if [ -d "/usr/share/bash-completion/completions" ] ; then
    echo "now copying bash command line completion file into place, using sudo"
    sudo cp ../../cli_completion/bash/splintermail /usr/share/bash-completion/completions
fi

if [ -d "/usr/share/zsh/site-functions" ] ; then
    echo "now copying zsh command line completion file into place, using sudo"
    sudo cp ../../cli_completion/zsh/_splintermail /usr/share/zsh/site-functions
fi

