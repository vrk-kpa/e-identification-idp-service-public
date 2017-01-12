# KaPA Identity Provider service
**KaPA Shibboleth IdP 3**

This component handles the identification requests from service providers, who require identification SAML2 messages for authentication to the corresponding services.

**Compiling the component**

This component can be compiled and packaged with Maven tool with the following commands:
```
mvn clean install
mvn assembly:single
```
This produces the required tar ball that contains the necessary binaries and configuration templates.

For local testing with Vagrant environment, there exists a helper script in /script directory which does the necessary work and unpacks the built package ready for Ansible provisioning.
This assumes that there exists environment specific directory structure for Ansible. Here's the required directory structure as an example for local Vagrant environment:
```
/data00/deploy/identity-provider/vagrant
```
**Note!** Copy Ansible user's public key file into this repository's directory /ssl before running vagrant up.

**Works as follows on Ubuntu:**

Edit the hosts file
```
sudo vim /etc/hosts
```
Add the line
```
192.168.10.10	shibboleth-idp.vagrant.dev
```
Start Vagrant virtual box (could be a while)
```
vagrant up
```
Complete by pushing configurations from your Ansible repository. Example fileset can be found from 'kapa-config' repository.

**Errors**

In case of errors, bugs or security issues please contact kapa@vrk.fi.

