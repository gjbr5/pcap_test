all : pcap_test

pcap_test: main.o print_packet.o
	g++ -g -o pcap_test main.o print_packet.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

print_packet.o:
	g++ -g -c -o print_packet.o print_packet.cpp

clean:
	rm -f pcap_test
	rm -f *.o

