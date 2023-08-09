# Cross-browser Passwordless Authentication with a NOSQL Backend

### Functionality

This is a demo of [passwordless cryptographic
authentication](https://pomcor.com/2022/07/19/passwordless-authentication-for-the-consumer-space/)
to a web application.  The user registers an email address and the
JavaScript frontend of the web application creates a key pair in
browser storage, specifically in localStorage.  The user can then sign
in on any browser in any device by entering the email address in a
login form.  If there is a key pair in the browser, the user is
authenticated by a signature on an authentication challenge computed
with the private key.  If not, an email verification link is sent to
the address, and opening the link in the browser causes a key pair to
be created.  In a backend database there is a user record identified
by the email address and a credential record for each browser having a
key pair, containing the public key component of the key pair and uses
the email address to reference the user record.  This demo uses a
nosql database.  A companion repository
[fcorella/crypto-authn-demo-sql](https://github.com/fcorella/crypto-authn-demo-sql.git)
demonstrates how the same functionality can be provided by an sql
database.

### Ingredients

The app runs under Nodejs, uses MongoDB as its backend database, and
uses the Pomcor JavaScript Cryptographic Library (PJCL), refactored as
an ES6 module pjcl.js and available at
[fcorella/pjcl](https://github.com/fcorella/pjcl.git), to
provide cryptographic functionality both to the frontend and to the
backend.  The app generates random bits using a deterministic random
bit generator (DRBG) provided by PJCL, seeded with server entropy
obtained from /dev/random on the backend, and with browser entropy
from Crypto.getRandomValues() plus downloaded server entropy on the
front end.

### How to run the demo

To run the demo, launch a free-tier eligible EC2 server running Amazon
Linux 2 on AWS.  *Be sure to use Amazon Linux 2 rather than Amazon
Linux 2023*; Amazon Linux 2023 does not work MySQL community server at
this time.  Install git (sudo yum -y install git), clone the
repository into a directory /home/ec2-user/crypto-authn-demo-sql, and
change directory to crypto-authn-demo-sql.
Make sure that install-script 
and demo.mjs are executable (chmod a+x install-script demo.mjs), and run 
the bash script install-demo (sudo ./install-demo).  The script will install MongoDB,
Mongoose, Nodejs, and node modules including pjcl.

The script will ask you for the public IP address of the server or a
domain name that maps to the IP address, and will give you the option
to send the email verification link using the AWS Simple Email Service
(SES) or to simulate the email message by displaying a web page after
a small delay.  To use SES your AWS account must have moved out of the
SES sandbox, and you will have to provide a verified sender address to
the script; use simulated email if you run into any difficulty.

The demo uses a self-signed certificate cert.pem and its private key
key.pem.  To avoid the browser warnings you can replace them your own
certificate and private key in the self-signed-demo-cert folder.

### See also...

* The blog post [Passwordless Authentication for the Consumer Space](https://pomcor.com/2022/07/19/passwordless-authentication-for-the-consumer-space/)

* The [Cryptographic Authentication](https://pomcor.com/cryptographic-authentication/) page of the Pomcor site
