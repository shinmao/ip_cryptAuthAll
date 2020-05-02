ip_cryptAuthAll: ip_cryptAuthAll.o divertlib.o
	gcc ip_cryptAuthAll.o divertlib.o -o ip_cryptAuthAll -lssl
ip_cryptAuthAll.o: ip_cryptAuthAll.c
	gcc -c ip_cryptAuthAll.c -o ip_cryptAuthAll.o
divertlib.o: divertlib.c
	gcc -c divertlib.c -o divertlib.o
clean:
	rm -f *.o