#!/bin/bash

function startup_checks () {
    if [[ $EUID -ne 0 ]];
    then 
        echo "[X] Install scanners needs to run as root.."
        exit 1
    fi
}

function does_source_exist () {
    scanner=$1

    # Check if scanner source installed
    if [[ ! -d "$scanner" ]];
    then
        echo 1
    else
        echo 0
    fi
}

function does_cmd_exist () {
    cmd=$1
    rc=$(which $cmd)

    # Check if cmd found in PATH
    if [[ ! $rc ]];
    then
        echo 1
    else
        echo 0
    fi
}

function install_source () {
    name=$1
    repo=$2

    git clone $repo
    pushd $name

    if [[ -f requirements.txt ]];
    then
        pip3 install -r requirements.txt
        if [[ $? -ne 0 ]];
        then
            echo "[!!] Errors may have occurred installing required packages.."
            echo "for: OWASP-Nettacker"
        else
            echo "[**] Packages successfully installed for OWASP-Nettacker"
        fi
    fi

    popd
}

function install_scanner () {

    scanner=$1
    stype=$2
    repo=$3

    if [[ $stype = "source" ]];
    then
        chk=$(does_source_exist "$scanner")
        if [[ ! $chk ]];
        then
            echo "[**] Setting up the OWASP-Nettacker scanner!"
            install_source $scanner $repo
        else
            echo "[**] $scanner already installed, skipping install..."
        fi
    else
        chk=$(does_cmd_exist "$scanner")
        if [[ ! $chk ]];
        then
            echo "[**] Setting up $scanner!"
            install_cmd $scanner
        else
            echo "[**] $scanner already installed, skipping install.."
        fi
    fi
}

echo "[**] Installing some scanners for Artorias!!"
echo "[**] Doing some startup checks.."
startup_checks

pushd "sources"

# Install the scanners from souce at Github
install_scanner "OWASP-Nettacker" "source" \
    "https://github.com/zdresearch/OWASP-Nettacker.git"
install_scanner "testssl.sh" "source" \
    "https://github.com/drwetter/testssl.sh.git"

# Install these scanners through the package manager
install_scanner "nikto" "cmd"
install_scanner "nmap" "cmd"
install_scanner "skipfish" "cmd"

echo "[**] All compatable scanners have been added!"
popd

exit 0
