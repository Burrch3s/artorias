#!/bin/bash

function pip_install() {
    echo "[**] Installing python packages.."
    pip install -r requirements.txt

    if [[ ! $? ]];
    then
        echo "[!!] Error occurred installing python packages, consider"
        echo "  installing on your own. REMINDER Artorias is compatible"
        echo "  with python3.5 and higher"
    fi
}

status=$(which pip3)
if [[ $status ]];
then
    pip_install
else
    echo "[!!] pip3 not found. REMINDER Artorias is compatible with python3.5"
    echo "  and higher. If you do have python3.5 and pip3, then you can install"
    echo "  packages by hand, or run (pip install -r requirements.txt)"
fi

echo "[**] Artorias installed (hopefully lol). If an error occurred it shouldnt"
echo "  be too hard to fix, all we did here was install python packages"
