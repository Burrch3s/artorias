FROM ubuntu:18.04

# Retrieve Artorias source
RUN apt-get update && \
    apt-get install -y \
        git \
        python3.6 \
        python3-pip \
        wget

RUN git clone https://github.com/Burrch3s/artorias.git
WORKDIR /artorias

RUN pip3 install -r requirements.txt

# Grab more manual-install components
WORKDIR /artorias/scanners

# TODO idk maybe grab different wordlist? overkill?
# Grab wordlist
RUN wget downloads.skullsecurity.org/passwords/rockyou.txt.bz2 && \
    bzip2 -d rockyou.txt.bz2

# Install Zap
RUN wget -nv https://download.opensuse.org/repositories/home:cabelo/xUbuntu_18.10/Release.key -O Release.key && \
    apt-key add - < Release.key && \
    sh -c "echo 'deb http://download.opensuse.org/repositories/home:/cabelo/xUbuntu_18.04/ /' > /etc/apt/sources.list.d/home:cabelo.list" && \
    apt-get update && \
    apt-get install -y owasp-zap

# Install Arachni
RUN wget https://github.com/Arachni/arachni/releases/download/v1.5.1/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz && \
    tar -zxf arachni-1.5.1-0.5.12-linux-x86_64.tar.gz && \
    ln -s arachni-1.5.1-0.5.12/bin/arachni /bin/arachni

# Install scanners for project
RUN apt-get install -y \
    hydra \
    nmap \
    nikto \
    skipfish
