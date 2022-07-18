### Functionality

This is a demo of [passwordless cryptographic
authentication](https://pomcor.com/2022/07/18/passwordless-authentication-for-the-consumer-space/)
in a web application, using a nosql backend database.  A companion
repository
[fcorella/crypto-authn-demo-sql](../fcorella/crypto-authn-demo-sql)
demonstrates how the same functionality can be provided by a sql
backend.

### Ingredients

The app runs under Nodejs, uses MongoDB as its backend database, and
uses the Pomcor JavaScript Cryptographic Library (PJCL), refactored as
an ES6 module pjcl.js and available at
[fcorella/pjcl](../fcorella/pjcl), to
provide cryptographic functionality both to the frontend and to the
backend.  The app generates random bits using a deterministic random
bit generator (DRBG) provided by PJCL, seeded with server entropy
obtained from /dev/random on the backend, and with browser entropy
from Crypto.getRandomValues() plus downloaded server entropy on the
front end.

### How to run the demo

To run the demo, launch a free-tier eligible EC2 server running
Amazon Linux on AWS, clone the repository into a directory
/home/ec2-user/crypto-authn-demo-nosql, change directory to
crypto-authn-demo-nosql, and run the bash script ./install-demo.
The script will ask you for the public IP address of the server or a
domain name that maps to the IP address, to be used in a link for
creating a cryptographic credential in a browser.  The script will
install MongoDB, node and node modules including pjcl, and will start
the app as a systemd service.  You can then visit the home page of the
server to use the app.
