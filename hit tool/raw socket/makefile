all:	
	client.c ../des/code2x.c ../des/hexstok.c server.c
client:
	gcc -Wall -o client client.c ../des/code2x.c ../des/hexstok.c
server:
	gcc -Wall -o server server.c ../des/code2x.c
cclient:	
	rm -f client
cserver:
	rm -f server
clean:
	rm -f client
	rm -f server
