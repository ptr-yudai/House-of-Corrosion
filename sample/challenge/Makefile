all:
	gcc -Wl,-z,now,-z,relro main.c -o ../distfiles/chall -O2 -fstack-protector -pie
	strip ../distfiles/chall
