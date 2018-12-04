# Current scanners to install:

### Nmap
Scanner to assess the network attack surface.

##### Helps Test OWASP Component(s):
I3: Insecure Network Services. Used to identify possibly insecure services.
I9: Insecure Software/Firmware. Slight stretch, but nmap with OS fingerprinting
can identify possible Kernel versions of a host, identifying older versions
pointing the possibility of the device needing updates.

### Nikto
Scanner to assess WebApplications that could be present.

##### Helps Test OWASP Component(s):
I1: Insecure Web Interface. Some IoT devices have Web Interfaces on them
for various reasons, some being that interface is used for control.
I2: Insufficient Authentication/Authorization. Nikto comes with some tests
for basic default passwords to these web interfaces and will report upon it.
I5: Privacy Concerns. If I2 or I1 discovered, can easily bleed into affecting
privacy concerns

### Skipfish CURRENTLY DEPRECATED
Scanner to assess WebApplications that could be present.

##### Helps Test OWASP Component(s):
I1: Insecure Web Interface. Some IoT devices have Web Interfaces on them
for various reasons, some being that interface is used for control.
I2: Insufficient Authentication/Authorization. Nikto comes with some tests
for basic default passwords to these web interfaces and will report upon it.
I5: Privacy Concerns. If I2 or I1 discovered, can easily bleed into affecting
privacy concerns

### testssl.sh CURRENTLY UNUSED
Scanner to identify cipher suites used for transport encryption

##### Helps Test OWASP Component(s):
I4: Lac of Transport Encryption. If ports utilizing web services found, will
scan them for cipher suite offered for traffic.
I5: Privacy Concerns. Issues found with I4 can easily lead to privacy concerns

### Hydra
Brute force scanner for authentication on specified ports.

##### Help Test OWASP Component(s):
I2: Ports that are able to be tested by brute forcing the credentials will prove
that default credentials are weak to dictionary attacks. Can impact I1 if admin
parts of website were "secured" with weak passwords, can also leak into I5 and I3.

### OWASP-Nettacker CURRENTLY UNUSED
Scanner that does a myriad of things, but I am still exploring it's correct
application to the framework.

##### Helps Test OWASP Component(s):
Update later



# OWASP Top Ten Coverage that is lacking and reasons:
I6 Insecure Cloud Interface: Can get into a gray area with clear legal issues
to go after a out of network service/server. Not going to design the capability
for my capstone for clear legal issues I don't want to deal with.

I7 Insecure Mobile Interface: Honestly not sure how to test mobile interfaces.
Maybe I should look more into this and expand upon it.

I8 Insufficient Security Configurability: Also not sure how I could dynamically
look for security configurations, might just be left for manual testing.

I10 Poor Physical Security: Not something I can really automate with software.

I5 Privacy concerns: Passive scanning of apps over time can reveal more issues
with privacy concerns, as well as passively listening on certain events such as
setup or interacting with the app.
