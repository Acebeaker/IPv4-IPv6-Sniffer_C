CC = gcc
IDIR = ./include
CFLAGS = -I$(IDIR) -std=gnu99
LIBS = -lpcap
OBJ = main.c decodificadorARP.c decodificadorUDP.c decodificadorTCP.c decodificadorIPV6.c decodificadorIPV4.c decodificadorICMPv6.c decodificadorICMP.c decodificadorEthernet.c
DEPS = decodificadores.h

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)


ds: $(OBJ) 
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

# clean out the dross
clean:
	rm -f ds  *~ *.o 
