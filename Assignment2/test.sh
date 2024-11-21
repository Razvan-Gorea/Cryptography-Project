#!/bin/sh

dd if=/dev/zero of=Assignment2.sha256sum bs=1 count=96
openssl dgst -sha256 -binary Assignment2.class >> Assignment2.sha256sum
openssl rsautl -raw -sign -inkey private_key.pem -in Assignment2.sha256sum -out Assignment2.sig
xxd -p Assignment2.sig