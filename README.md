# Artorias IoT Security Testing Framework
[![Build Status](https://travis-ci.com/Burrch3s/artorias.svg?branch=master)](https://travis-ci.com/Burrch3s/artorias)[![Coverage Status](https://coveralls.io/repos/github/Burrch3s/artorias/badge.svg)](https://coveralls.io/github/Burrch3s/artorias)

#### Test specific targets, or subnet of targets for vulnerabilities (Black Box)

-Identify OS Type

-Services provided/open ports

-Dictionary guessable credentials

-Vulnerabilities with web interfaces

-Identify plaintext traffic to/from device

-Drive other IoT or host based scans if host meets prerequisites


#### Prerequisites

> Python3.5 or higher

## Installation

> `virtualenv -p python3 art ; . art/bin/activate # optional steps, but recommended`
> `git clone git@github.com:Burrch3s/artorias.git`
> `cd artorias ; pip install -r requirements.txt`
> `pushd scanners; sudo ./install_scanners.sh; popd # OR just install nikto, owasp-zap, nmap, hydra and wordlist that's pointed to by settings.py`
> Then you should be good to go. Artorias utilizes the argparse module, so -h will display help messages for args

## Layout of Project

#### core

> Contains most code and object definitions for the project. Handling of tests and
scans happens here as well.

#### core/scans

> Contains scans to run against a host. These scans are sub classes of core/scan.py and should
override the parent classes methods

#### dev

> Dev scripts and templates for developers

#### scanners

> Directory containing sources of scanners to install from install\_scanners.sh,
as well as the default location for the wordlist to use. 

#### unittests

> Contains unittests for the repo. Perform unittests by running green. core/scans is omitted by unittests and coverage,
in the future, it would be for the best to implement some kind of integration test for them to test them..


## Future ideas

#### Identify Vulnerabilities (White Box)

-Use given credentials on hosts to loggin to perform basic checks (maybe try using Nessus?)

#### Web Front End

-May not be possible in timeframe wanted, but eh let's try

#### CMD Interpreter for doing individual scans

-Sounds kinda cool lol

#### Compile and Rank Results

-Take everything that is listed above and provide meaningful feedback

-Consult NIST, OWASP and other guidelines in attempt to rank findings
