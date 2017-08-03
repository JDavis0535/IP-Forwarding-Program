//Jake Davis
//IP Forwarding
//Program 2
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string>

using namespace std;

void parse_IP(struct header_file *ip, const void *buffer);
void printIP(const struct header_file *ip);


struct header_file
{

		int version; //IPv4
		int header_length; //Header length
		short total_length; // datagram length
		short identifier; // 16-bit indentifier
		int flags; //flags
		int offset; //13-bit fragmentation offset
		int time_to_live; //time-to-live
		int protocol; //upper-layer protocol
		short checksum; // header checksum
		int source_address[4]; //32-bit source IP address
		int destination_address[4]; //32-bit destination IP adress
		char hop_address;
};


void parse_IP(struct header_file *ip, char *buffer){
	//extract total length, source_address and destination address
	
	ip->version = (buffer[0] & 0xf0) >> 4;
	ip->header_length = (buffer[0] &0x0f);
	unsigned short l = (buffer[2] << 8) | buffer[3];
	ip->total_length = l;
	ip->source_address[1] = (buffer[12] & 0xff);
	ip->source_address[2] = (buffer[13] & 0xff);
	ip->source_address[3] = (buffer[14] & 0xff);
	ip->source_address[4] = (buffer[15] & 0xff);
	
	ip->destination_address[1] = (buffer[16] & 0xff);
	ip->destination_address[2] = (buffer[17] & 0xff);
	ip->destination_address[3] = (buffer[18] & 0xff);
	ip->destination_address[4] = (buffer[19] & 0xff);


}

void print_IP(const struct header_file *ip){ 


	cout << "------------------" << endl;
	cout << "Version: "<< ip->version  << endl;
	cout << "Header length: " << ip-> header_length * 4 << " bytes" << endl;
	cout << "Total Length: "<< ip->total_length << " bytes" << endl;
	cout << "Source: " << ip->source_address[1] << "." << ip->source_address[2] << "." << ip->source_address[3] << "." << ip->source_address[4] << endl;
	cout << "Destination: " << ip->destination_address[1] << "." << ip->destination_address[2] << "." << ip->destination_address[3] << "." << ip->destination_address[4] << endl;
	
}



int main(int argc, char*argv[]){


	//VARIABLES
	header_file header;
	int read = 0;
	int datasize = 0;
	int number = 1;
	char line[128];

	//Get packets_in file
	char *filename = argv[1];

	//Get forwarding table file
	char *filename2 = argv[2];

	//get packets_out file
	char *filename3 = argv[3];


	//Open packet_in file for reading
	FILE *f = fopen(filename, "rb");
	
	//check if file opened correctly
	if (f == NULL){
		perror("Error opening file");
		return 1;
	}

	//open forwarding table file for reading
	FILE *f2 = fopen(filename2, "rb");

	//check if file opened correctly
	if (f2 == NULL){
		perror ("Error opening file");
		return 1;
	}

	//Open packet_out file for writing
	FILE *f3 = fopen(filename3, "wb");
	
	//check if file opened correctly
	if (f3 == NULL){
		perror("Error opening file");
		return 1;
	}

	//allocate buffer to hold content of file
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	char *buffer = (char*)malloc(sizeof(char) * (fsize +1));
	fseek(f, 0, SEEK_SET);  //same as rewind(f);

	
	//do until end of file is reached
	while(!feof(f)){

	//read the first 20 bytes of file into the allocated buffer
	fread(buffer,1, 20, f);
	
	//Parse the IP header
	parse_IP(&header, buffer);

	datasize = (header.total_length - header.header_length * 4);

	//Read from file pointer up to size of data to buffer
	fread(buffer,1 , datasize, f);

	char test[3];

	
	//Print the IP header Info
	cout << endl;
	cout << "Packet #" << number++ <<  endl;
	print_IP(&header);
	
	while (!feof(f2)){

	//read forwarding table line by line checking for destination address
	fgets (line, sizeof(line), f2);
		
	test[1] = line[2]; 
	test[2] = line[3];  
	test[3] = line[4];

	int temp = atoi(test + 1);

	char test2[13];

	if (temp == header.destination_address[1]){
		memcpy(test2, line + 31, 12 );
		cout << "Next Hop Address: " << test2 << endl;

	}

	}

	rewind(f2);
	//write buffer to file
	fwrite (buffer, 1, datasize, f3);
	
	}

	fclose(f);
	fclose(f2);
	fclose(f3);
	return 0;
}




















