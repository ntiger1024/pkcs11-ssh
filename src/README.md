# PKCS11 demo

Some ssh servers use public key authentication method. The client's private
key should be in an secure place, i.e., local HSM, cloud key center, etc.
Ssh client supports "-I pkcs11" option with which a pkcs11 library can be used
to communicate with private keys for user authentication. This project a demo
pkcs11 library for this.

# Build & Run for macos

```
# Build
make

# Start local server. See start-sshd.sh

# Login local ssh server.
make run-ssh
```
