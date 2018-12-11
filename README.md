# Artorias IoT Security Testing Framework
[![Build Status](https://travis-ci.com/Burrch3s/artorias.svg?branch=master)](https://travis-ci.com/Burrch3s/artorias)[![Coverage Status](https://coveralls.io/repos/github/Burrch3s/artorias/badge.svg)](https://coveralls.io/github/Burrch3s/artorias)

#### Test specific targets, or subnet of targets for vulnerabilities (Black Box)

-Identify OS Type

-Services provided/open ports

-Dictionary guessable credentials

-Vulnerabilities with web interfaces

-Identify plaintext traffic to/from device

-Drive other IoT scanners


## Layout of Project

#### core

Contains most code and object definitions for the project. Handling of tests and
scans happens here as well.

#### scanners

Directory containing sources of scanners to install from install_scanners.sh,
as well as the default location for the wordlist to use. 

#### unittests

Contains unittests for the repo. Perform unittests by running green


## Future ideas

#### Identify Vulnerabilities (White Box)

-Use given credentials on hosts to loggin to perform basic checks (maybe try using Nessus?)


#### Web Front End

-May not be possible in timeframe wanted, but eh let's try


#### Compile and Rank Results

-Take everything that is listed above and provide meaningful feedback

-Consult NIST, OWASP and other guidelines in attempt to rank findings

