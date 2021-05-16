# CompletedProchlo

Prochlo implementation from https://github.com/google/prochlo extended

## Compiling

Using g++:

To compile the generator:
g++ generator/generator.cc lib/prochlo.cc lib/crypto.cc lib/data.h -o gen -std=c++17 -lssl -lcrypto
To compile the decoder part:
g++ mytests.cc lib/prochlo.cc lib/crypto.cc -o mytest -std=c++17 -lssl -lcrypto

## Key generation:
Generate key pairs using OpenSSL, i.e. 
openssl ecparam -genkey -name prime256V1 -genkey -noout -out key.pem
openssl ec -in key.pem -pubout key.pub

##Run

To generate 5000 Blinder items using the keys in etc/ :

./gen -o /tmp/testfile.dat -B etc/key1/pub -T etc/key2.pub -A etc/key3.pub -b etc/key1/pem -t etc/key2.pem -a etc/key3.pem -n 5000

To decode the blinder items (source file and number of items to be specified in the code):

./mytest
