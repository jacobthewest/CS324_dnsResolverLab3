#include<arpa/inet.h>
#include<netinet/in.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netdb.h>
#include<unistd.h>

typedef unsigned int dns_rr_ttl;
typedef unsigned short dns_rr_type;
typedef unsigned short dns_rr_class;
typedef unsigned short dns_rdata_len;
typedef unsigned short dns_rr_count;
typedef unsigned short dns_query_id;
typedef unsigned short dns_flags;
int MAX_SIZE = 512;
int MAXLINE = 1024;

typedef struct {
	char *name;
	dns_rr_type type;
	dns_rr_class class;
	dns_rr_ttl ttl;
	dns_rdata_len rdata_len;
	unsigned char *rdata;
} dns_rr;

struct dns_answer_entry;
struct dns_answer_entry {
	char *value;
	struct dns_answer_entry *next;
};
typedef struct dns_answer_entry dns_answer_entry;

void free_answer_entries(dns_answer_entry *ans) {
	dns_answer_entry *next;
	while (ans != NULL) {
		next = ans->next;
		free(ans->value);
		free(ans);
		ans = next;
	}
}

void print_bytes(unsigned char *bytes, int byteslen) {
	int i, j, byteslen_adjusted;
	unsigned char c;

	if (byteslen % 8) {
		byteslen_adjusted = ((byteslen / 8) + 1) * 8;
	} else {
		byteslen_adjusted = byteslen;
	}
	for (i = 0; i < byteslen_adjusted + 1; i++) {
		if (!(i % 8)) {
			if (i > 0) {
				for (j = i - 8; j < i; j++) {
					if (j >= byteslen_adjusted) {
						printf("  ");
					} else if (j >= byteslen) {
						printf("  ");
					} else if (bytes[j] >= '!' && bytes[j] <= '~') {
						printf(" %c", bytes[j]);
					} else {
						printf(" .");
					}
				}
			}
			if (i < byteslen_adjusted) {
				printf("\n%02X: ", i);
			}
		} else if (!(i % 4)) {
			printf(" ");
		}
		if (i >= byteslen_adjusted) {
			continue;
		} else if (i >= byteslen) {
			printf("   ");
		} else {
			printf("%02X ", bytes[i]);
		}
	}
	printf("\n");
}

void canonicalize_name(char *name) {
	/*
	 * Canonicalize name in place.  Change all upper-case characters to
	 * lower case and remove the trailing dot if there is any.  If the name
	 * passed is a single dot, "." (representing the root zone), then it
	 * should stay the same.
	 *
	 * INPUT:  name: the domain name that should be canonicalized in place
	 */
	
	int namelen, i;

	// leave the root zone alone
	if (strcmp(name, ".") == 0) {
		return;
	}

	namelen = strlen(name);
	// remove the trailing dot, if any
	if (name[namelen - 1] == '.') {
		name[namelen - 1] = '\0';
	}

	// make all upper-case letters lower case
	for (i = 0; i < namelen; i++) {
		if (name[i] >= 'A' && name[i] <= 'Z') {
			name[i] += 32;
		}
	}
}

int name_ascii_to_wire(char *name, unsigned char *wire) {
	/* 
	 * Convert a DNS name from string representation (dot-separated labels)
	 * to DNS wire format, using the provided byte array (wire).  Return
	 * the number of bytes used by the name in wire format.
	 *
	 * INPUT:  name: the string containing the domain name
	 * INPUT:  wire: a pointer to the array of bytes where the
	 *              wire-formatted name should be constructed
	 * OUTPUT: the length of the wire-formatted name.
	 */
}

char * name_ascii_from_wire(char *wire, int *indexp) {
	/* 
	 * Extract the wire-formatted DNS name at the offset specified by
     * *indexp in the array of bytes provided (wire) and return its string
     * representation (dot-separated labels) in a char array allocated for
     * that purpose.  Update the value pointed to by indexp to the next
     * value beyond the name.
     *
     * INPUT:  wire: a pointer to an array of bytes
     * INPUT:  indexp, a pointer to the index in the wire where the
     *              wire-formatted name begins
     * OUTPUT: a string containing the string representation of the name,
     *              allocated on the heap.
     */

     // Get name
    int tempIndex = wire[*indexp+1]; 
    int nameLength = (*indexp - 4) - tempIndex; // 4 because of the four fixed type/class bytes after the URL and before the name
    
    char *name = malloc(sizeof (char) * (nameLength + 1)); // + 1 to leave space for a null terminator
    int startPosInResp = wire[*indexp + 1];
    int counter = 0;
    
    while(1) {
        name[counter] = wire[startPosInResp];
        // fprintf(stdout, "\tname[%d] = %c\n", counter, wire[startPosInResp]);
        // fflush(stdout);
        if (wire[startPosInResp] == '\0') {
            // fprintf(stdout, "\tNull char added\n");
            // fflush(stdout);
            break;
        }
        counter++;
        startPosInResp++;
    }

    fflush(stdout);

    *indexp += 2; // Set indexp ready to begin reading the class/type values.
    return name;
}


unsigned char* get_rdata_from_wire(unsigned char* wire, int* indexp, unsigned short dataLength) {
    /*
    * INPUT: wire = the query response. indexp = pointer to location in wire. dataLength = # bytes to read 
    * OUTPUT: unsigned char* rdata. rdata is the the info we need from the wire.Needs to be formatted like a
    * normal ip address would be with the periods and everything. Example: 128.187.26.284
    */
   unsigned char* rdata = malloc(dataLength)+3; // +3 because we need to have the ip address periods in there

   int copy = *indexp; // I have to use copy because indexp gets screwed up if I don't
   for(int i = 0; i < dataLength + 3; i++) {
       // fprintf(stdout, "%d.", wire[copy]);
       // fprintf(stdout, "wire[*indexp] = %0x\n", wire[*indexp]);
       // fflush(stdout);
       int thing = (int)wire[copy];
       rdata[i] = (unsigned char)thing;
    //    unsigned char c = wire[copy];
    //    rdata[i] = c;
       i++;
       rdata[i] = '.';
       copy++;
   }
   *indexp = copy;
//    fprintf(stdout, "\n");
//    fprintf(stdout, "*indexp = %d\n", *indexp);
//    fprintf(stdout, "copy = %d\n", copy);
   fprintf(stdout, "rdata: %s\n", rdata);
   fflush(stdout);
   return rdata;
}

dns_rr rr_from_wire(unsigned char *wire, int *indexp, int query_only) {
	/* 
	 * Extract the wire-formatted resource record at the offset specified by
	 * *indexp in the array of bytes provided (wire) and return a 
	 * dns_rr (struct) populated with its contents. Update the value
	 * pointed to by indexp to the next value beyond the resource record.
	 *
	 * INPUT:  wire: a pointer to an array of bytes
	 * INPUT:  indexp: a pointer to the index in the wire where the
	 *              wire-formatted resource record begins
	 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
	 *              we are extracting a full resource record or only a
	 *              query (i.e., in the question section of the DNS
	 *              message).  In the case of the latter, the ttl,
	 *              rdata_len, and rdata are skipped.
	 * OUTPUT: the resource record (struct)
	 */
    
    dns_rr *resourceRecord = malloc(sizeof(dns_rr));

    char *name = name_ascii_from_wire(wire, indexp);

    // fprintf(stdout, "\nhere is name: %s\n", name);
    // fprintf(stdout, "Value of *indexp = %d\n\n", *indexp);
    // fflush(stdout);

    resourceRecord->name = name;

    // fprintf(stdout, "answer->name just happened\n");
    // fprintf(stdout, "Value of *indexp = %d\n\n", *indexp);
    // fflush(stdout);

    // Get type (IPV4 addres)
    int copy = *indexp; // Have to use copy because bitshifting is screwing up *indexp somehow
    unsigned short type = ((wire[copy]) << 8 | wire[copy + 1]); // combine the two bytes into a number
    resourceRecord->type = type;
    copy += 2;
    *indexp = copy;

    // fprintf(stdout, "answer->type just happened\n");
    // fprintf(stdout, "Value of *indexp = %d\n", *indexp);
    // fprintf(stdout, "Value of copy = %d\n", copy);
    // fprintf(stdout, "Value of type = %d\n\n", type);
    // fflush(stdout);

    // Get class (In, Internet)
    unsigned short class = (wire[*indexp] << 8 | wire[*indexp + 1]); // combine the two bytes into a number
    resourceRecord->class = class;
    *indexp += 2;

    // fprintf(stdout, "answer->class just happened\n");
    // fprintf(stdout, "Value of *indexp = %d\n\n", *indexp);
    // fflush(stdout);

    // Skip over TTL (Time to live) because it is useless in this lab.
    resourceRecord->ttl = 0;
    *indexp += 4; // Skip over those 4 bytes

    // fprintf(stdout, "answer->ttl just happened\n");
    // fprintf(stdout, "Value of *indexp = %d\n\n", *indexp);
    // fflush(stdout);

    // Get Data length
    copy = *indexp; // Have to use copy because bitshifting is screwing up *indexp somehow
    unsigned short dataLength = (wire[copy] << 8 | wire[copy + 1]); // combine the two bytes into a number
    resourceRecord->rdata_len = dataLength;
    copy += 2;
    *indexp = copy;

    // fprintf(stdout, "answer->rdata_len just happened\n");
    // fprintf(stdout, "Value of *indexp = %d\n", *indexp);
    // fprintf(stdout, "Value of copy = %d\n", copy);
    // fprintf(stdout, "wire[*indexp] = %0x\n", wire[*indexp]);
    // fprintf(stdout, "wire[*indexp + 1] = %0x\n\n", wire[*indexp+1]);
    // fflush(stdout);

    // Data-- Byte (NOT ASCII) encoding of the IPV4 address (can vary in length) // USE INET_NTOP
    unsigned char* rdata = get_rdata_from_wire(wire, indexp, dataLength); 
    resourceRecord->rdata = rdata;
    // fprintf(stdout, "Here is *indexp: %d\n", *indexp);
    // fflush(stdout);

    // fprintf(stdout, "answer->rdata just happened\n");
    // fflush(stdout);

    return *resourceRecord;
}

int rr_to_wire(dns_rr rr, unsigned char *wire, int query_only) {
	/* 
	 * Convert a DNS resource record struct to DNS wire format, using the
	 * provided byte array (wire).  Return the number of bytes used by the
	 * name in wire format.
	 *
	 * INPUT:  rr: the dns_rr struct containing the rr record
	 * INPUT:  wire: a pointer to the array of bytes where the
	 *             wire-formatted resource record should be constructed
	 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
	 *              we are constructing a full resource record or only a
	 *              query (i.e., in the question section of the DNS
	 *              message).  In the case of the latter, the ttl,
	 *              rdata_len, and rdata are skipped.
	 * OUTPUT: the length of the wire-formatted resource record.
	 *
	 */
}

unsigned short create_dns_query(char *qname, dns_rr_type qtype, unsigned char *wire) {
	/* 
	 * Create a wire-formatted DNS (query) message using the provided byte
	 * array (wire).  Create the header and question sections, including
	 * the qname and qtype.
	 *
	 * INPUT:  qname: the string containing the name to be queried
	 * INPUT:  qtype: the integer representation of type of the query (type A == 1)
	 * INPUT:  wire: the pointer to the array of bytes where the DNS wire
	 *               message should be constructed
	 * OUTPUT: the length of the DNS wire message
	 */
    
    // Identification (query ID)
    int num = rand();
    wire[0] = (num & 0xFF);
    wire[1] = ((num >> 8) & 0xFF);
    wire[0] = 0x04; 
    wire[1] = 0x04;
    // Query Flag - hardcoded to 1
    wire[2] = 0x01;
    wire[3] = 0x00;
    // Questions in the wire, hardcoded to 1
    wire[4] = 0x00;
    wire[5] = 0x01;
    // Answer resource records, hardcoded to 0 for a query
    wire[6] = 0x00;
    wire[7] = 0x00;

    
    // Authority/Additional Resource Records - Hard coded to 0 for this lab
    int index = 8;
    wire[index] = 0x00; index++;
    wire[index] = 0x00; index++;
    wire[index] = 0x00; index++;
    wire[index] = 0x00; index++;
    

    // Parse and add the qname to the wire
    int numCharsIndex = 12;
    index++;
    int count = 0;
    
    for(int i = 0; i < strlen(qname); i++) {
        if(qname[i] != '.') {
            unsigned char temp = qname[i];
            // fprintf(stdout, "Char: %c\n", temp);
            wire[index] = temp;
            count++;
        } else {
            // fprintf(stdout, "Adding %d to position: %d\n", count, numCharsIndex);
            wire[numCharsIndex] = (unsigned char)count;
            numCharsIndex = numCharsIndex + count + 1;
            count = 0;
        }
        index++;
    }
    wire[numCharsIndex] = (unsigned char)count;
    wire[index] = 0x00;
    index++;
    // fprintf(stdout, "wire: %s\n", wire);
    // fflush(stdout);
    // Hard code the type/class values
    wire[index] = 0x00; index++;
    wire[index] = 0x01; index++;
    wire[index] = 0x00; index++;
    wire[index] = 0x01; index++;

    unsigned short sizeOfWire = strlen(qname) + 18; // 18 Because those are required variables for 
                                         // any query message.
    return sizeOfWire;
}

dns_answer_entry *get_answer_address(char *qname, dns_rr_type qtype, unsigned char *wire) {
	/* 
	 * Extract the IPv4 address from the answer section, following any
	 * aliases that might be found, and return the string representation of
	 * the IP address.  If no address is found, then return NULL.
	 *
	 * INPUT:  qname: the string containing the name that was queried
	 * INPUT:  qtype: the integer representation of type of the query (type A == 1)
	 * INPUT:  wire: the pointer to the array of bytes representing the DNS wire message
	 * OUTPUT: a linked list of dns_answer_entrys the value member of each
	 * reflecting either the name or IP address.  If
	 */
}

int send_recv_message(unsigned char *request, int requestlen, unsigned char *response, char *server, unsigned char* port) {
    //unsigned char* port
	/* 
	 * Send a message (request) over UDP to a server (server) and port
	 * (port) and wait for a response, which is placed in another byte
	 * array (response).  Create a socket, "connect()" it to the
	 * appropriate destination, and then use send() and recv();
	 *
	 * INPUT:  request: a pointer to an array of bytes that should be sent
	 * INPUT:  requestlen: the length of request, in bytes.
	 * INPUT:  response: a pointer to an array of bytes in which the
	 *             response should be received
	 * OUTPUT: the size (bytes) of the response received
	 */

    int socketFileDescriptor;
    struct sockaddr_in servaddr;

    // Creating socket file descriptor for UDP IPV4
    if ( (socketFileDescriptor = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        perror("socket creation failed"); 
        exit(EXIT_FAILURE); 
    } 
    
    memset(&servaddr, 0, sizeof(servaddr)); 

    // Filling server information
    servaddr.sin_family = AF_INET;
    unsigned short portAsNum = (unsigned short) strtoul(port, NULL, 0);
    servaddr.sin_port = htons(portAsNum);
    inet_pton(AF_INET, server, &servaddr.sin_addr);

    int connectResult;
    if ((connectResult = connect(socketFileDescriptor, (const struct sockaddr *) &servaddr, sizeof(servaddr))) < 0) {
        close(socketFileDescriptor);
        fprintf(stdout, "connect() -- FAILURE\n\tConnection return code: %d\n", connectResult);
        fflush(stdout);
    } else {
        // fprintf(stdout, "connect() -- SUCCESS\n\tConnection return code: %d\n", connectResult);
        fflush(stdout);
    }

    int numBytesReceived, numBytesSent, bindResult, len;

    if((numBytesSent = sendto(socketFileDescriptor, (const char *)request, requestlen, 
        0, (const struct sockaddr *) &servaddr,  
            sizeof(servaddr))) < 0) {
                fprintf(stdout, "sendto() -- FAILURE\n\tError Code: %d\n", numBytesSent);
                fflush(stdout);
    } else {
        // fprintf(stdout, "sendto() -- SUCCESS\n\tBytes sent: %d\n", numBytesSent);
        // fprintf(stdout, "\tLength of request: %d\n", requestlen);
        fflush(stdout);
    }

    if((numBytesReceived = recv(socketFileDescriptor, response, MAXLINE, 0)) < 0) {
        fprintf(stdout, "recv() -- FAILURE\n\tError Code: %d\n", numBytesReceived);
        fflush(stdout);
    } else {
        // fprintf(stdout, "recv() -- SUCCESS\n\tBytes received: %d\n", numBytesReceived);
        fflush(stdout);
    }
  
    close(socketFileDescriptor); 
    return numBytesReceived; 
}

/* INPUT:
*       qname - domain name
*       server - server
*       port - port
*/
// TODO: Implement this function. The only function that I cannot delete.
dns_answer_entry *resolve(char *qname, char *server, char *port) {
    // ---Step 3 Make your query wire--- //
    // In order to send your query, you have to make a properly formatted byte wire
    // A byte wire is just an unsigned char[] or unsigned char*
    int sizeOfWire = strlen(qname) + 18; // 18 Because those are required variables for 
                                         // any query message.
    unsigned char wire[sizeOfWire];
    unsigned short dnsWireMessageLength = create_dns_query(qname, 1, wire);
    // print_bytes(wire, dnsWireMessageLength);

    // ---Step 4 Send your query--- //
    unsigned char response[MAXLINE];
    int numResponseBytes = send_recv_message(wire, dnsWireMessageLength, response, server, port);
    // fprintf(stdout, "\n------------------Printing Bytes-----------------");
    // fflush(stdout);
    // print_bytes(response, numResponseBytes);

    
    // // ---Step 5 Make a single answer--- //
    // dns_rr resourceRecord = rr_from_wire(response, &sizeOfWire, 1); // 1 means it is only a query. 0 means full resource record. 

    // // Make a new answer struct...
    // dns_answer_entry *answer_entry = malloc(sizeof(dns_answer_entry));
    
    // //... with the data from the first resource record
    // answer_entry->value = resourceRecord.rdata;

    // // Set pointer of your answer to NULL
    // answer_entry->next = NULL;

    //return answer_entry;
    return NULL;
}

int main(int argc, char *argv[]) {
	char *port;
	dns_answer_entry *ans_list, *ans;
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <domain name> <server> [ <port> ]\n", argv[0]);
		exit(1);
	}
	if (argc > 3) {
		port = argv[3];
	} else {
		port = "53";
	}
	ans = ans_list = resolve(argv[1], argv[2], port); // Resolve the domain name (where all of the action takes place)
	while (ans != NULL) { // Iterates through all of the answers and prints them.
                          // Answers are in a linked list.
		printf("%s\n", ans->value);
		ans = ans->next;
	}
	if (ans_list != NULL) {
		free_answer_entries(ans_list);
	}
}