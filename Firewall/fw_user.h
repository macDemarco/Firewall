#ifndef _FW_USER_H_
#define _FW_USER_H_


// the protocols we will work with
typedef enum {
	PROT_ICMP = 1,
	PROT_TCP = 6,
	PROT_UDP = 17,
	PROT_OTHER = 255,
	PROT_ANY = 143,
} prot_t;


// various reasons to be registered in each log entry
typedef enum {
	REASON_FW_INACTIVE			= -1,
	REASON_NO_MATCHING_RULE		= -2,
	REASON_XMAS_PACKET			= -4,
	REASON_ILLEGAL_VALUE		= -6,
	CONN_NOT_EXIST				= -8,
	TCP_NON_COMPLIANT			= -10,
	VALID_CONN					= -12,
	FTP_NON_COMPLIANT			= -14,
	VALID_FTP_DATA_CONN			= -16, 
	BLOCKED_HTTP_HOST			= -18,
	REASON_MALFORMED_PACKET		= -20,
} reason_t;


// auxiliary strings, for your convenience
#define DEVICE_NAME_RULES			"rules"
#define DEVICE_NAME_LOG				"log"
#define DEVICE_NAME_CONN_TAB		"conn_tab"
#define CLASS_NAME					"fw"
#define LOOPBACK_NET_DEVICE_NAME	"lo"
#define IN_NET_DEVICE_NAME			"eth1"
#define OUT_NET_DEVICE_NAME			"eth2"

// auxiliary values, for your convenience
#define IP_VERSION		(4)
#define PORT_ANY		(0)
#define PORT_ABOVE_1023	(1023)
#define MAX_RULES		(50)

// device minor numbers, for your convenience
typedef enum {
	MINOR_RULES			= 0,
	MINOR_LOG			= 1,
	MINOR_CONNECTIONS	= 2,
	MINOR_HOSTS			= 3,
} minor_t;

typedef enum {
	ACK_NO = 0x01,
	ACK_YES = 0x02,
	ACK_ANY = ACK_NO | ACK_YES,
} ack_t;

typedef enum {
	DIRECTION_IN = 0x01,
	DIRECTION_OUT = 0x02,
	DIRECTION_ANY = DIRECTION_IN | DIRECTION_OUT,
} direction_t;

// rule base
typedef struct {
	char rule_name[20];			// names will be no longer than 20 chars
	direction_t direction;
	unsigned int src_ip;
	unsigned int src_prefix_mask; 	// e.g., 255.255.255.0 as int in the local endianness
	char		 src_prefix_size; 	// valid values: 0-32, e.g., /24 for the example above
									// (the field is redundant - easier to print)
	unsigned int dst_ip;
	unsigned int dst_prefix_mask; 	// as above
	char		 dst_prefix_size; 	// as above	
	unsigned short	src_port; 			// number of port or 0 for any or port 1023 for any port number > 1023  
	unsigned short	dst_port; 			// number of port or 0 for any or port 1023 for any port number > 1023 
	char protocol; 			// values from: prot_t
	ack_t	ack; 				// values from: ack_t
	char action;   			// valid values: NF_ACCEPT, NF_DROP
} rule_t;

// logging
typedef struct {
	unsigned long  	timestamp;     	// time of creation/update
	unsigned char  	protocol;     	// values from: prot_t
	unsigned char  	action;       	// valid values: NF_ACCEPT, NF_DROP
	unsigned char  	hooknum;      	// as received from netfilter hook
	unsigned int  	src_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	unsigned int	dst_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	unsigned short  src_port;	  	// if you use this struct in userspace, change the type to unsigned short
	unsigned short  dst_port;	  	// if you use this struct in userspace, change the type to unsigned short
	reason_t     	reason;       	// rule#index, or values from: reason_t
	unsigned int   	count;        	// counts this line's hits
} log_row_t;

#endif // _FW_H_
