### Functionality

This is a demo of [passwordless cryptographic
authentication](https://pomcor.com/2022/07/19/passwordless-authentication-for-the-consumer-space/)
in a web application, using a nosql backend database.  A companion
repository
[fcorella/crypto-authn-demo-sql](https://github.com/fcorella/crypto-authn-demo-sql.git)
demonstrates how the same functionality can be provided by a sql
backend.

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

### Practical details

- In the demo, the server uses a self-signed certificate, which causes browser warnings.

- As explained in the [blog
post](https://pomcor.com/2022/07/19/passwordless-authentication-for-the-consumer-space/),
the UX calls for the app sending a dual-purpose link in an email
message.  In the demo, the message is simulated by a web page
displayed after a timeout.

### Additional information

[Passwordless Authentication for the Consumer Space](https://pomcor.com/2022/07/19/passwordless-authentication-for-the-consumer-space/)

[Cryptographic Authentication for Web Applications](https://pomcor.com/cryptographic-authentication/)
