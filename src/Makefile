OPENSSL_PATH := ~/Src/openssl/
FLAGS := -I $(OPENSSL_PATH)/include -L $(OPENSSL_PATH) -lcrypto

.PHONY: all run-ssh-keygen run-ssh

all: libpkcs11-soft.so pkcs11-soft

run-ssh-keygen: libpkcs11-soft.so
	DYLD_LIBRARY_PATH=$(OPENSSL_PATH) ssh-keygen -D ./libpkcs11-soft.so -e

run-ssh: libpkcs11-soft.so
	DYLD_LIBRARY_PATH=$(OPENSSL_PATH) ssh -I ./libpkcs11-soft.so localhost

libpkcs11-soft.so: pkcs11-soft.c
	gcc pkcs11-soft.c $(FLAGS) -o libpkcs11-soft.so -fPIC -shared

pkcs11-soft: main.c libpkcs11-soft.so
	gcc main.c libpkcs11-soft.so $(FLAGS) -o pkcs11-soft

.PHONY: clean
clean:
	-@rm libpkcs11-soft.so pkcs11-soft
