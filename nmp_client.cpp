// nmp_client.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define _CRT_SECURE_NO_WARNINGS
#define _CRTDBG_MAP_ALLOC  
#include "stdint.h"
#include "stdafx.h"
#include "windows.h"
#include "LOG.H"		// Capture putchar & printf output to a log file
#include "TMR.h"
#include "comport.h"
//#include <iostream>
//using namespace std;

#ifdef _DEBUG
#define DBG_NEW new ( _NORMAL_BLOCK , __FILE__ , __LINE__ )
// Replace _NORMAL_BLOCK with _CLIENT_BLOCK if you want the
// allocations to be of _CLIENT_BLOCK type
#else
#define DBG_NEW new
#endif

#undef TRACE
#define TRACE(fmt,...) do { if (dflag) printf(fmt,__VA_ARGS__); } while(0)
//#define TRACE(...)
#undef DEBUG
#define DEBUG(...)

extern void MEM_Dump(unsigned char* data, int len, long base);

int dflag = false;

#undef MEM_Trace
#define MEM_Trace(data,len,base) do { if (dflag) MEM_Dump(data,len,base); } while(0)
//#define MEM_Trace(fmt,...)

ComPort* com = NULL;

extern "C"
{
	void MEM_Dump(uint8_t *data, uint16_t len, uint32_t base)
	{
		uint16_t i, j;

		//if (!CFG_IsTrace(DFLAG_TRC))
		//	return;

		//CON_printf("MEM: @%08x len=%04x\n",data,len);
		for (i = 0; i < len; i += 16)
		{
			printf(" %06x: ", base + i);
			for (j = 0; j < 16; j++)
			{
				if (j != 0)
				{
					if (!(j % 8))
						printf(" ");
					if (!(j % 1))
						printf(" ");
				}
				if ((i + j) < len)
					printf("%02x", data[i + j]);
				else
					printf("  ");
			}
			printf("  ");
			for (j = 0; j < 16 && (i + j) < len; j++)
			{
				if ((i + j) < len)
				{
					if (isprint(data[i + j]))
						printf("%c", data[i + j]);
					else
						printf(".");
				}
				else
					printf(" ");
			}
			printf("\n");
		}
	}

	int COM_Init(int port,long baud)
	{
		if (com == NULL)
		{
			com = new ComPort(port, baud);
			if (com->Start())
			{
				com->Resume();
				return 0;
			}
		}
		return -1;
	}

	void COM_Term(void)
	{
		if (com)
		{
			com->Stop();
			com->Sleep(100);

			delete com;
			com = NULL;
		}
	}

	bool COM_connected(void)
	{
		return com->IsConnected();
	}

	int COM_recv_char(void)
	{
		return com->RxGetch();
	}

	long COM_recv_count(void)
	{
		return com->RxCount();
	}

	int COM_send_char(byte c)
	{
		return com->Write(c);
	}

	bool COM_send_buf(char *buf, int len)
	{
		return com->Write(buf, len);
	}

	void COM_Sleep(int ticks)
	{
		com->Sleep(ticks);
	}
}

/*
** ComPort virtual thread processing function.
*/
void ComPort::Process(void)
{
	//static int rxpacket_len = 0;
	//static int rxpacket_cnt = 0;
	static byte rxpacket[512];

	/* Rx serial processing - rx data block received is put into circular buffer. */
	int n = Read((LPSTR)rxpacket, sizeof(rxpacket) - 1);
	if (n > 0)
	{
		RxWrite(n, (char*)rxpacket);
	}

	/* Tx serial processing - tx data is sent immediately by app, so nothing to do. */

}



#include "cbor/cbor.h"

class CBOR
{
public:
	unsigned char* data;
	unsigned char* p;
	unsigned char* q;
	long base;
	int size;

	cbor_token_t* tokens;
	int tokens_size;
	int token_cnt;

	CBOR()
	{
		TRACE("CBOR()\n");
	}

	CBOR(int n)
	{
		TRACE("CBOR(%d) ", n);
		tokens = new cbor_token_t[n];
		tokens_size = n;
		TRACE("tokens[%d] @%xH\n", n, tokens);
	}

	void Init(unsigned char* data, int size)
	{
		TRACE("Init data @%xH size=%d\n", data, size);
		this->data = data;
		this->size = size;
		token_cnt = 0;
		base = 0L;
		q = data;
		p = q;
	}

	void def_map(int m)
	{
		TRACE(" map(%d)\n", m);
		p = cbor_write_map(q, size - base, m);
		MEM_Trace(q, p - q, base);
		base += p - q;
		q = p;
	}

	void def_array(int m)
	{
		TRACE(" array(%d)\n", m);
		p = cbor_write_array(q, size - base, m);
		MEM_Trace(q, p - q, base);
		base += p - q;
		q = p;
	}

	void put()
	{
		TRACE(" break\n");
		p = cbor_write_special(q, size - base, 31);
		MEM_Trace(q, p - q, base);
		base += p - q;
		q = p;
	}

	void put(int n)
	{
		TRACE(" int(%d)\n", n);
		p = cbor_write_int(q, size - base, n);
		MEM_Trace(q, p - q, base);
		base += p - q;
		q = p;
	}

	void put(unsigned int n)
	{
		TRACE(" uint(%u)\n", n);
		p = cbor_write_uint(q, size - base, n);
		MEM_Trace(q, p - q, base);
		base += p - q;
		q = p;
	}

	void put(long long n)
	{
		TRACE(" long(%lld)\n", n);
		p = cbor_write_long(q, size - base, n);
		MEM_Trace(q, p - q, base);
		base += p - q;
		q = p;
	}

	void put(unsigned long long n)
	{
		TRACE(" ulong(%llu)\n", n);
		p = cbor_write_ulong(q, size - base, n);
		MEM_Trace(q, p - q, base);
		base += p - q;
		q = p;
	}

	void put(char* s)
	{
		TRACE(" text('%s')\n", s);
		p = cbor_write_text(q, size - base, s);
		MEM_Trace(q, p - q, base);
		base += p - q;
		q = p;
	}

	void put(unsigned char* bytes, int m)
	{
		TRACE(" bytes([%d]:", m);
		for (int i = 0; i < m; i++)
		{
			TRACE("%02x ", bytes[i]);
		}
		TRACE("\n");
		p = cbor_write_bytes(q, size - base, bytes, m);
		MEM_Trace(q, p - q, base);
		base += p - q;
		q = p;
	}

	const char* typetostr(cbor_token_type_e type);

	cbor_token_t* token;

	cbor_token_t* get_first(cbor_token_type_e type);
	cbor_token_t* get_next(void);
	cbor_token_t* get_key(char* s);
	bool istype(cbor_token_type_e type);
	bool expected_next_type(cbor_token_type_e type);

	void list(void);

	virtual int parse(void);

	~CBOR()
	{
		TRACE("~CBOR() tokens @%xH size=%d:\n", tokens, tokens_size);
		if (tokens_size > 0)
		{
			delete tokens;
		}
	}
};

//#define CBOR_PARSE_MAX_TOKENS	ARRAYSIZE(CBOR_Parser::tokens)

// Find the text key value in the array of parsed tokens and return a pointer to the next token.
cbor_token_t* CBOR::get_key(char* s)
{
	bool key = false;
	for (int i = 0; i < token_cnt; i++)
	{
		if (!key && tokens[i].type == CBOR_TOKEN_TYPE_TEXT)
		{
			if (!strncmp(s, tokens[i].text_value, tokens[i].int_value))
			{
				key = true;
			}
		}
		else
		{
			if (key)
			{
				return &tokens[i];
			}
		}
	}
	return NULL;
}

cbor_token_t* CBOR::get_first(cbor_token_type_e type)
{
	for (int i = 0; i < token_cnt; i++)
	{
		if ((cbor_token_type_e)tokens[i].type == type)
		{
			return &tokens[i];
		}
	}
	return NULL;
}

cbor_token_t* CBOR::get_next(void)
{
	if (token_cnt == 0)
	{
		TRACE("get_next: No tokens[]!\n");
		return NULL;
	}
	if (token == NULL)
	{
		TRACE("get_next: NULL pointer!\n");
		return NULL;
	}
	if ((token + 1) > &tokens[token_cnt - 1])
	{
		TRACE("get_next: EOF\n");
		return NULL;
	}
	token += 1;
	//TRACE("get_next: %s\n", typetostr((cbor_token_type_e)token->type));
	return token;
}

const char* CBOR::typetostr(cbor_token_type_e type)
{
	switch (type)
	{
	case CBOR_TOKEN_TYPE_ERROR:
		return "ERROR";
	case CBOR_TOKEN_TYPE_INCOMPLETE:
		return "INCOMPLETE";
	case CBOR_TOKEN_TYPE_INT:
		return "INT";
	case CBOR_TOKEN_TYPE_LONG:
		return "LONG";
	case CBOR_TOKEN_TYPE_MAP:
		return "MAP";
	case CBOR_TOKEN_TYPE_ARRAY:
		return "ARRAY";
	case CBOR_TOKEN_TYPE_TEXT:
		return "TEXT";
	case CBOR_TOKEN_TYPE_BYTES:
		return "BYTES";
	case CBOR_TOKEN_TYPE_TAG:
		return "TAG";
	case CBOR_TOKEN_TYPE_SPECIAL:
		return "SPECIAL";
	case CBOR_TOKEN_TYPE_BREAK:
		return "BREAK";
	default:
		return "UNKNOWN";
	}
}

void CBOR::list(void)
{
	printf("%d tokens found:\n", token_cnt);
	cbor_token_t* token = tokens;
	for (int i = 0; i < token_cnt; i++, token++)
	{
		printf("%2d:\t(%d)%s\n", i, token->type, typetostr((cbor_token_type_e)token->type));
	}
}

int CBOR::parse(void)
{
	unsigned int offset = 0;
	token_cnt = 0;
	long j = 0;
	while (1)
	{
		//TRACE("cbor_parse data size=%d token_cnt=%d ", size, token_cnt);
		// Build up a list of tokens that are contained in a global array.
		if ((token_cnt + 1) > tokens_size)
		{
			printf("Out of token space!\n");
			MEM_Dump(data, size, 0L);
			return 0;
		}
		cbor_token_t* token = &tokens[token_cnt++];

		offset = cbor_read_token(data, size, offset, token);
		TRACE("cbor_read_token() offset=%d token->type=%d\n", offset, token->type);
		if (token->type == CBOR_TOKEN_TYPE_INCOMPLETE) {
			TRACE(" incomplete\n");
			break;
		}
		if (token->type == CBOR_TOKEN_TYPE_ERROR) {
			printf(" error: %s\n", token->error_value);
			MEM_Dump(data, size, 0L);
			break;
		}
		if (token->type == CBOR_TOKEN_TYPE_BREAK) {
			TRACE(" break\n");
			MEM_Trace(&data[j], offset - j, j);
			j = offset;
			continue;
		}
		if (token->type == CBOR_TOKEN_TYPE_INT) {
			TRACE(" int(%s%d)\n", token->sign < 0 ? "-" : "", (int)token->int_value);
			MEM_Trace(&data[j], offset - j, j);
			j = offset;
			continue;
		}
		if (token->type == CBOR_TOKEN_TYPE_UINT) {
			TRACE(" uint(%s%u)\n", token->sign < 0 ? "-" : "", token->int_value);
			MEM_Trace(&data[j], offset - j, j);
			j = offset;
			continue;
		}
		if (token->type == CBOR_TOKEN_TYPE_LONG) {
			TRACE(" long(%s%lld)\n", token->sign < 0 ? "-" : "", (long long)token->long_value);
			MEM_Trace(&data[j], offset - j, j);
			j = offset;
			continue;
		}
		if (token->type == CBOR_TOKEN_TYPE_ULONG) {
			TRACE(" ulong(%s%llu)\n", token->sign < 0 ? "-" : "", token->long_value);
			MEM_Trace(&data[j], offset - j, j);
			j = offset;
			continue;
		}
		if (token->type == CBOR_TOKEN_TYPE_ARRAY) {
			if (token->int_value == 31)
				TRACE(" array(*)\n");
			else
				TRACE(" array(%u)\n", token->int_value);
			MEM_Trace(&data[j], offset - j, j);
			j = offset;
			continue;
		}
		if (token->type == CBOR_TOKEN_TYPE_MAP) {
			if (token->int_value == 31)
				TRACE(" map(*)\n");
			else
				TRACE(" map(%u)\n", token->int_value);
			MEM_Trace(&data[j], offset - j, j);
			j = offset;
			continue;
		}
		if (token->type == CBOR_TOKEN_TYPE_TAG) {
			TRACE(" tag(%u)\n", token->int_value);
			MEM_Trace(&data[j], offset - j, j);
			j = offset;
			continue;
		}
		if (token->type == CBOR_TOKEN_TYPE_SPECIAL) {
			TRACE(" special(%u)\n", token->int_value);
			MEM_Trace(&data[j], offset - j, j);
			j = offset;
			continue;
		}
		if (token->type == CBOR_TOKEN_TYPE_TEXT) {
			TRACE(" text('%.*s')\n", token->int_value, token->text_value);
			MEM_Trace(&data[j], offset - j, j);
			j = offset;
			continue;
		}
		if (token->type == CBOR_TOKEN_TYPE_BYTES) {
			TRACE(" bytes([%u]:", token->int_value);
			for (int i = 0; i < token->int_value; i++)
			{
				TRACE("%02x ", token->bytes_value[i]);
			}
			TRACE(")\n");
			MEM_Trace(&data[j], offset - j, j);
			j = offset;
			continue;
		}
	}
	return offset;
}

bool CBOR::istype(cbor_token_type_e type)
{
	return token->type == type;
}

bool CBOR::expected_next_type(cbor_token_type_e type)
{
	return (token = get_next()) != NULL && istype(type);
}


#include "base64/base64.h"
#include "cbor/cbor.h"
#include "BASEFILE.HPP"

#define ERR_COM_TIMEOUT			-1
#define ERR_HCI_TIMEOUT			-2
#define ERR_NMP_DECODE			-3
#define ERR_NMP_HDR_BAD			-4
#define ERR_NMP_CRC_BAD			-5
#define ERR_FILE_NOT_FOUND		-6
#define ERR_LOAD_FAILURE		-7
#define ERR_NLIP_HDR_BAD		-8
#define ERR_NLIP_NO_LF			-9

char* ifile = NULL;						// upload image input filename
char ifname[80];

char oflag = 0;  						// capture send output 
char* ofile = NULL;						// capture send output filename
char ofname[80];

char tflag = 0;  						// load send input

char lflag = 0;  						// log text output 
char* lfile = NULL;						// log text output filename
char lfname[80];

int port = 0;							// COM port number

char nflag = 0;							// send HCI commands to enable NMP mode
char rflag = 0;							// send NMP reset command

BASEFILE bf;

#define BUFSIZE		512

extern "C" uint16_t crc_xmodem(const unsigned char* input_str, size_t num_bytes);

char qflag = 0;  						// quiet mode off (output to window)

unsigned char bytes_sha[32] = {
	0x6c,0x5a,0x2b,0x11,0x0d,0xdc,0xc0,0xa2, 0x91,0xf0,0xd0,0x6c,0xa0,0x0d,0x2f,0xb0,
	0xe9,0x4c,0x63,0x10,0x0a,0x00,0x72,0x14, 0x12,0xe3,0xff,0xc0,0x35,0xd0,0xbe,0x2f };

void TraceChar(int c)
{
	if (isprint(c))
	{
		TRACE("%c", c);
	}
	else if (c == '\n')
	{
		TRACE("<LF>\n");
	}
	else if (c == '\r')
	{
		TRACE("<CR>");
	}
	else
	{
		TRACE("[%02x]", c);
	}
}

/*********************************************/
/* Serial communications interface functions */
/*********************************************/
/* Receive a buffer[] of serial data bytes. */
int recv_buf_start(unsigned char* buf, int size, int count, unsigned char* pat)
{
	int len = 0;
	int delay = 50;

	TRACE("recv_buf_start(@%08x, %d, %d, [", buf, size, count);
	for (int i = 0; i < count; i++)
	{
		TRACE("%02x ", pat[i]);
	}
	TRACE("]){\n");
	while (len < count)
	{
		if (COM_recv_count() > 0)
		{
			int c;
			c = COM_recv_char();
			TraceChar(c);
			buf[len] = c;
			int ch = pat[len];
			len++;
			if (c != ch)
				len = 0;
			delay = 10;
		}
		else
		{
			if (--delay >= 0)
			{
				COM_Sleep(1);
			}
			else
			{
				printf("rx: Timeout!");
				return ERR_COM_TIMEOUT;
			}
		}
	}
	TRACE("} len=%d\n", len);
	return len;
}

int recv_buf(unsigned char* buf, int size, int count, int ch)
{
	int len = 0;
	int delay = 50;

	int m = count;
	int i = 0;
	bool done = false;
	TRACE("recv_buf(@%08x, %d, %d, %d){", buf, size, count, ch);
	while (len < count)
	{
		if (COM_recv_count() > 0)
		{
			int c;
			c = COM_recv_char();
			TraceChar(c);
			buf[len] = c;
			len++;
			if (ch != -1 && c == ch)
			{
				break;
			}
			delay = 10;
		}
		else
		{
			if (--delay >= 0)
			{
				COM_Sleep(1);
			}
			else
			{
				if (ch == -1)
				{
					break;
				}
				printf("rx: Timeout!");
				return ERR_COM_TIMEOUT;
			}
		}
	}
	TRACE("} len=%d\n", len);
	return len;
}

/* Send a buffer[] of data bytes over serial. */
void send_buf(unsigned char* buf, int n)
{
	//MEM_Trace(buf, n, 0L);
	if (!COM_connected())
	{
		return;
	}
	if (!COM_send_buf((LPSTR)buf, n))
	{
		printf("send_buf: Write error!\n");
	}
	COM_Sleep(1);
}

/* Send a pre-formatted HCI command buffer[] of data bytes over serial. */
int send_hci_cmd(unsigned char* buf, int size, unsigned char* cmd, int txlen, int rxlen)
{
	TRACE("tx hci cmd:\n");
	memcpy(buf, cmd, txlen);
	MEM_Trace(cmd, txlen, 0L);
	send_buf(buf, txlen);
	int n = recv_buf(buf, sizeof(buf), rxlen, -1);
	TRACE("rx hci resp:");
	if (n == 0)
	{
		printf("HCI Timeout!\n");
	}
	else
	{
		TRACE(" n=%d\n", n);
		MEM_Trace(buf, n, 0L);
		TMR_Delay(1);
	}
	return n;
}

/*********************************************/
/* NLIP serial type definitions.             */
/*********************************************/

/* NLIP packets sent over serial are fragmented into frames of 127 bytes or
 * fewer. This 127-byte maximum applies to the entire frame, including header,
 * CRC, and terminating newline.
 */
#define MGMT_NLIP_MAX_FRAME     127

typedef struct nlip_hdr
{
	uint8_t type[2];
} nlip_hdr_t;

typedef struct nlip_pkt_t
{
	nlip_hdr hdr;
	unsigned char data[0];
} nlip_pkt_t;

/*********************************************/
/* NMP type definitions.                     */
/*********************************************/
// Mcu Manager operation codes
typedef enum
{
	OP_READ = 0,
	OP_READ_RSP = 1,
	OP_WRITE = 2,
	OP_WRITE_RSP = 3
} nmp_op_codes_t;

// Mcu Manager groups
typedef enum
{
	GROUP_DEFAULT = 0,
	GROUP_IMAGE = 1,
	//GROUP_STATS = 2,
	//GROUP_CONFIG = 3,
	//GROUP_LOGS = 4,
	//GROUP_CRASH = 5,
	//GROUP_SPLIT = 6,
	//GROUP_RUN = 7,
	GROUP_FS = 8
	//GROUP_PERUSER = 64,
} nmp_groups_t;

// Default manager command IDs
typedef enum
{
	//DEFAULT_ID_ECHO = 0,
	//DEFAULT_ID_CONS_ECHO_CTRL = 1,
	//DEFAULT_ID_TASKSTATS = 2,
	//DEFAULT_ID_MPSTATS = 3,
	//DEFAULT_ID_DATETIME_STR = 4,
	DEFAULT_ID_RESET = 5
} nmp_default_ids_t;

// Image manager command IDs
typedef enum
{
	IMAGE_ID_STATE = 0,
	IMAGE_ID_UPLOAD = 1,
	//IMAGE_ID_FILE = 2
	//IMAGE_ID_CORELIST = 3,
	//IMAGE_ID_CORELOAD = 4,
	//IMAGE_ID_ERASE = 5,
	//IMAGE_ID_ERASE_STATE = 6
} nmp_image_ids_t;

// Stats manager command IDs
//typedef enum
//{
//    STATS_ID_READ = 0,
//    STATS_ID_LIST = 1
//} nmp_stats_ids_t;

// Config manager command IDs
//typedef enum
//{
//	CONFIG_ID_CONFIG = 0
//} nmp_config_ids_t;

// Logs manager command IDs
//typedef enum
//{
//    LOGS_ID_READ = 0,
//	LOGS_ID_CLEAR = 1,
//	LOGS_ID_APPEND = 2,
//	LOGS_ID_MODULE_LIST = 3,
//	LOGS_ID_LEVEL_LIST = 4,
//	LOGS_ID_LOGS_LIST = 5
//} nmp_logs_ids_t;

// FS manager command IDs
typedef enum
{
	FS_ID_FILE = 0
} nmp_fs_ids_t;

typedef struct nmp_hdr
{
	unsigned char Op;
	unsigned char Flags;
	unsigned short Len;
	unsigned short Group;
	unsigned char Seq;
	unsigned char Id;
} nmp_hdr_t;

typedef struct nmp_pkt
{
	nmp_hdr_t hdr;
	unsigned char data[0];
} nmp_pkt_t;

#define swapbytes(n)	((n&0xFF)<<8)+(n>>8)

unsigned int total_len = 0;				// total length of image file
unsigned char seq = 0x01;		// next nmp sequence number to send

CBOR cbor(16);					// CBOR token parsing storage array

void TraceNmpHdr(nmp_hdr_t* hdr)
{
	MEM_Trace((unsigned char*)hdr, sizeof(nmp_hdr_t), 2L);
	TRACE(" Op:%d Flags:%d Len:%d Group:%d Seq:%d Id:%d\n",
		hdr->Op, hdr->Flags, swapbytes(hdr->Len), swapbytes(hdr->Group), hdr->Seq, hdr->Id);
}


int recv_nmp_rsp(unsigned char* dec, int size, uint8_t Op, uint16_t Group, uint8_t Id)
{
	if (!COM_connected())
	{
		return 0;
	}

	unsigned char enc[256];
	unsigned char pat[2] = { 0x06, 0x09 };

	// Find the start of the NLIP packet:
	int len = recv_buf_start(enc, sizeof(enc), sizeof(pat), pat);
	if (len < 0)
	{
		return len;
	}

	// Receive body of the NLIP packet (ie. ascii text that is terminated with a <LF>):
	len = recv_buf(enc, sizeof(enc), sizeof(enc) - 1, '\r');
	if (len < 1)
	{
		return -1;
	}
	enc[len - 1] = '\0';	// remove anything after the trailing <LF>
	TRACE("rx: '%s'\n", &enc[0]);
	int m;
	//m = base64_decode_len((char*)enc);
	m = base64_decode((char*)enc, dec);
	if (m <= 0)
	{
		printf("rx: Decode failure!\n");
		return ERR_NMP_DECODE;
	}
	// NMP header (8-bytes):
	int k = swapbytes(*(uint16_t*)&dec[0]);
	MEM_Trace(&dec[2], k, 0L);
	TRACE("nmp len=%04x ", k);
	struct nmp_pkt* pkt = (struct nmp_pkt*)&dec[2];
	nmp_hdr_t* hdr = &pkt->hdr;
	len = swapbytes(hdr->Len);
	TRACE("hdr len=%04x\n", len);
	TRACE("rx: ");
	TraceNmpHdr(hdr);
	if (hdr->Flags != 0x00 || hdr->Op != Op || swapbytes(hdr->Group) != Group || hdr->Id != Id)
	{
		printf("rx: Bad hdr! Op:%d Flags:%d Len:%d Group:%d Seq:%d Id:%d\n",
			hdr->Op, hdr->Flags, len, swapbytes(hdr->Group), hdr->Seq, hdr->Id);
		return ERR_NMP_HDR_BAD;
	}
	uint16_t crc = crc_xmodem(&dec[2], k - 2);
	if (swapbytes(*(uint16_t*)&dec[2 + k - 2]) != crc)
	{
		printf("rx: Bad crc!\n");
		return ERR_NMP_CRC_BAD;
	}
	cbor.Init(pkt->data, len);
	int remaining = len - cbor.parse();
	TRACE("remaining=%d\n", remaining);
	return remaining;
}

void InitNmpHdr(nmp_hdr_t* hdr, uint8_t Op, uint8_t Flags, uint16_t Len, uint16_t Group, uint8_t Seq, uint8_t Id)
{
	hdr->Op = Op;
	hdr->Flags = Flags;
	hdr->Len = swapbytes(Len);
	hdr->Group = swapbytes(Group);
	hdr->Seq = Seq;
	hdr->Id = Id;
}

unsigned char* load_file(char* filename, long* size)
{
	BASEFILE bf;

	printf("Loading bytes from file '%s'", filename);
	if (size != NULL)
	{
		*size = 0L;
	}
	bf.InitReadFile(filename);
	if (!bf.IsFile())
	{
		printf("\nFile Not Found!\n");
		return NULL;
	}
	long m = bf.Filesize();
	printf(" size=%d bytes\n", m);
	unsigned char* data = new unsigned char[m];
	if (data == NULL)
	{
		printf("\nOut of memory!\n");
		return NULL;
	}

	long n = m;
	long j = 0;
	while (n)
	{
		unsigned char buf[BUFSIZE];
		if (n > BUFSIZE)
		{
			bf.ReadfromFile(BUFSIZE, buf);
			memcpy(&data[j], buf, BUFSIZE);
			n -= BUFSIZE;
			j += BUFSIZE;
		}
		else
		{
			bf.ReadfromFile(n, buf);
			memcpy(&data[j], buf, n);
			n = 0;
		}
	}
	bf.CloseFile();

	if (size != NULL)
	{
		*size = m;
	}
	return data;
}

// Simulated receiving of the saved data stream that was uploaded previously.
/*
	offset 0:    0x06 0x09
	== = Begin base64 encoding == =
	offset 2 : <16 - bit packet - length>
	offset ? : <body>
	offset ? : <crc16> (if final frame)
	== = End base64 encoding == =
	offset ? : 0x0a (newline)

	All subsequent frames have the following format :

	offset 0:    0x04 0x14
	== = Begin base64 encoding == =
	offset 2 : <body>
	offset ? : <crc16> (if final frame)
	== = End base64 encoding == =
	offset ? : 0x0a (newline)
*/
int download(char* fndata)
{
	unsigned char dec[520];
	long count = 0;		// NMP packet counter
	long j = 0;			// file data[] offset
	unsigned int len = 0;
	char fnimage[80];

	TRACE("download(%s)\n", fndata);
	strcpy(fnimage, fndata);
	char* p = strchr(fnimage, '.');
	if (p)
	{
		p++;
		strcpy(p, "img");
	}
	printf("Output image to file '%s'\n", fnimage);
	BASEFILE bf;
	bf.InitWriteFile(fnimage);
	if (!bf.IsFile())
	{
		printf("\nFile Not Found!\n");
		return ERR_FILE_NOT_FOUND;
	}

	long size;
	unsigned char* data = load_file(fndata, &size);
	if (data == NULL)
	{
		printf("\nLoad data failed!\n");
		return ERR_LOAD_FAILURE;
	}
	printf("Download:");

	while (j <= size)
	{
		if ((j + 515) < size)
		{
			MEM_Trace(&data[j], 515, 0L);
		}
		else
		{
			MEM_Trace(&data[j], size - j, 0L);
		}
		printf(!(count++ % 32) ? "\n." : ".");
		int k = 0;		// accumulated decoded base64 data offset in buf[]
		do
		{
			bool flag;
			nlip_hdr_t* nlip_hdr = (nlip_hdr_t*)&data[j];
			if (nlip_hdr->type[0] == 0x06 && nlip_hdr->type[1] == 0x09)
			{
				flag = true;	// Initial frame
			}
			else if (nlip_hdr->type[0] == 0x04 && nlip_hdr->type[1] == 0x14)
			{
				flag = false;	// Continuation frame
			}
			else
			{
				printf("Bad NLIP header type bytes!\n");
				MEM_Dump((unsigned char*)nlip_hdr, sizeof(nlip_hdr_t), j);
				delete data;
				bf.CloseFile();
				return ERR_NLIP_HDR_BAD;
			}
			j += sizeof(nlip_hdr_t);
			char enc[520];
			int i = 0;
			while (i < (sizeof(enc) - 1) && data[j] != 0x0a)
			{
				enc[i++] = data[j++];
			}
			if (i >= (sizeof(enc) - 1))
			{
				printf("No <LF> found!\n");
				delete data;
				return ERR_NLIP_NO_LF;
			}
			enc[i] = '\0';
			TRACE("rx: %02x %02x '%s'<LF>\n", nlip_hdr->type[0], nlip_hdr->type[1], enc);
			j += 1;
			int m;
			//m = base64_decode_len(enc);
			m = base64_decode(enc, &dec[k]);
			MEM_Trace(&dec[k], m, 0L);
			if (flag)
			{
				// NMP total length of decoded packet data (in CBOR format) (2-bytes)
				len = swapbytes(*(uint16_t*)&dec[k + 0]);
				TRACE("nmp len=%04x\n", len);
				// NMP header (8-bytes)
				nmp_hdr_t* hdr = (nmp_hdr_t*)&dec[k + 2];
				TRACE("hdr len=%04x\n", swapbytes(hdr->Len));
				TraceNmpHdr(hdr);
			}
			// Accumulate the decoded base64 data in dec[].
			k += m;
		} while (k < len);

		// Parse NMP packet payload as CBOR data map.
		MEM_Trace(dec, len, 0L);
		cbor.Init(&dec[10], len - 10);
		int offset = cbor.parse();
		unsigned int remaining = len - 8 - offset;
		TRACE("remaining=%x ", remaining);
		uint16_t crc = swapbytes(*(uint16_t*)&dec[len]);
		TRACE("offset=%x crc=%04x\n", offset, crc);

		// Determine if this is the last packet based on cbor map key pairs.
		cbor_token_t* token = cbor.get_key((char *)"data");
		unsigned int n = token->int_value;	// total number of bytes of data[] received
		TRACE("data[%d]:\n", n);
		MEM_Trace(token->bytes_value, n, 0L);
		bf.WritetoFile((DWORD)n, (BYTE*)token->bytes_value);
		if (count == 1)
		{
			// First packet has the expected total number of bytes in the image.
			token = cbor.get_key((char*)"len");
			total_len = token->int_value;
			TRACE("total_len=%d ", total_len);
		}
		token = cbor.get_key((char*)"off");
		unsigned int off = token->int_value;
		TRACE("off=%d\n", off);
		if ((off + n) == total_len)
		{
			//TRACE("Last packet\n");
			break;
		}
	}
	printf("EOF\n");
	delete data;
	return 0;
}

int nmp_format_buf(unsigned char* buf, int size, uint8_t Op, uint16_t Group, uint8_t Id, CBOR* cbor)
{
	int len;
	nmp_hdr_t* hdr;

	// Set NMP packet length (2-bytes):
	*(uint16_t*)&buf[0] = swapbytes(cbor->base + sizeof(nmp_hdr_t) + 2);
	MEM_Trace(&buf[0], sizeof(uint16_t), 0L);

	// Set NMP packet header (8-bytes):
	hdr = (nmp_hdr_t*)&buf[2];
	InitNmpHdr(hdr, Op, 0x00, cbor->base, Group, seq, Id);
	TRACE("tx: ");
	TraceNmpHdr(hdr);

	// Set NMP packet CRC16 (2-bytes):
	uint16_t crc = crc_xmodem(&buf[2], cbor->base + sizeof(nmp_hdr_t));
	TRACE("crc16: %04x\n", crc);
	*(uint16_t*)cbor->p = swapbytes(crc);
	len = 2 + sizeof(nmp_hdr_t) + cbor->base + 2;
	MEM_Trace(buf, len, 0L);

	// Encode NMP packet with base64.
	char enc[520];
	cbor->base = base64_encode(buf, len, enc, 1);
	TRACE("enc len=%d:\n", cbor->base);
	MEM_Trace((unsigned char*)enc, cbor->base, 0L);

	// Format packet for NLIP protocol by breaking into frames as needed.
	unsigned char* ptr = buf;
	int j = 0;
	for (int i = 0, k = MGMT_NLIP_MAX_FRAME - 3; i < cbor->base; i += k)
	{
		// Break up packet frames that are <=127 bytes:
		if ((i + k) >= cbor->base)
			k = cbor->base - i;
		if (i == 0)
		{
			*ptr++ = 0x06;
			*ptr++ = 0x09;
		}
		else
		{
			*ptr++ = 0x04;
			*ptr++ = 0x14;
		}
		strncpy((char*)ptr, &enc[i], k);
		ptr += k;
		*ptr++ = 0x0a;
		j += 2 + k + 1;
	}
	return j;
}

int send_nmp_req(unsigned char* buf, int size, uint8_t Op, uint16_t Group, uint8_t Id, CBOR* cbor)
{
	//TRACE("send_nmp_req Op=%x Group=%x Id=%x\n", Op, Group, Id);
	int j = nmp_format_buf(buf, sizeof(buf), Op, Group, Id, cbor);

	send_buf(buf, j);

	if (!tflag && oflag)
	{
		// Capture all serial output to a file to be used to verify correct operation.
		bf.WritetoFile((DWORD)j, (BYTE*)buf);
	}
	//MEM_Trace(buf, j, 0L);
	seq += 1;
	return j;
}

// Transmit a nmp imagelist request
static int send_imagelist(unsigned char* buf, int size)
{
	// Format the NMP Image List command buf[].
	cbor.Init(&buf[2 + sizeof(nmp_hdr_t)], sizeof(buf) - 2 - sizeof(nmp_hdr_t));
	cbor.def_map(0);
	send_nmp_req(buf, sizeof(buf), OP_READ, GROUP_IMAGE, IMAGE_ID_STATE, &cbor);
	int rc = recv_nmp_rsp(buf, sizeof(buf), OP_READ_RSP, GROUP_IMAGE, IMAGE_ID_STATE);
	if (rc < 0)
	{
		return rc;
	}
	return 0;
}

int imagelist(void)
{
	unsigned char buf[256];

	printf("Image List:\n");
	if (send_imagelist(buf, sizeof(buf)) != 0)
	{
		return -1;
	}
	// Find keys pairs describing the image list (ignoring array of maps). 
	cbor_token_t* images = cbor.get_key((char*)"images");
	if (images == NULL)
	{
		TRACE("rx: No images!\n");
		//return -2;
	}
	cbor_token_t* slot = cbor.get_key((char*)"slot");
	cbor_token_t* version = cbor.get_key((char*)"version");
	printf("images:[", images->int_value);
	if (slot != NULL)
		printf("slot:%d", slot->int_value);
	if (version != NULL)
		printf(",version:'%.*s'", version->int_value, version->text_value);
	printf("]\n");
	return 0;
}

// Transmit a nmp reset request
static int send_reset(unsigned char* buf, int size)
{
	// Format the NMP Reset command buf[].
	cbor.Init(&buf[2 + sizeof(nmp_hdr_t)], sizeof(buf) - 2 - sizeof(nmp_hdr_t));
	cbor.def_map(0);
	send_nmp_req(buf, size, OP_WRITE, GROUP_DEFAULT, DEFAULT_ID_RESET, &cbor);

	// Receive the response buf[].
	int rc = recv_nmp_rsp(buf, size, OP_WRITE_RSP, GROUP_DEFAULT, DEFAULT_ID_RESET);
	if (rc < 0)
	{
		return rc;
	}
	return 0;
}

int reset(void)
{
	unsigned char buf[256];
	int n;

	printf("Reset:\n");
	if (send_reset(buf, sizeof(buf)) != 0)
	{
		return -1;
	}
	char pat1[] = { "Boot detect" };
	n = recv_buf_start(buf, sizeof(buf), sizeof(pat1) - 1, (unsigned char*)pat1);
	if (n < 0)
	{
		printf("<nil>\n");
		return n;
	}
	else
	{
		buf[n] = '\0';
		printf("%s\n", (char*)buf);
	}

	// Wait >5 seconds after a software reset for the Bootloader to startup.
	TMR_Delay(55);

	// Check if the Bootloader signon has been received.
	char pat2[] = { "Boot valid" };
	n = recv_buf_start(buf, sizeof(buf), sizeof(pat2) - 1, (unsigned char*)pat2);
	if (n < 0)
	{
		printf("<nil>\n");
		return n;
	}
	else
	{
		buf[n] = '\0';
		printf("%s\n", (char*)buf);
	}
	return 0;
}

// Transmit a nmp upload request
static int send_upload(unsigned char* buf, int size, unsigned int offset, int nbytes, unsigned char* bytes_data)
{
	cbor.Init(&buf[2 + sizeof(nmp_hdr_t)], sizeof(buf) - 2 - sizeof(nmp_hdr_t));
	cbor.def_map(5);
	cbor.put((char*)"data");
	cbor.put(&bytes_data[offset], nbytes); // size of data (in bytes);
	cbor.put((char*)"image");
	cbor.put(0);
	if (offset == 0)
	{
		cbor.put((char*)"len");
		cbor.put(total_len);
	}
	cbor.put((char*)"off");
	cbor.put((int)offset);
	if (offset == 0)
	{
		cbor.put((char*)"sha");
		cbor.put(bytes_sha, sizeof(bytes_sha));
	}
	send_nmp_req(buf, size, OP_WRITE, GROUP_IMAGE, IMAGE_ID_UPLOAD, &cbor);

	// Receive the response buf[].
	int rc = recv_nmp_rsp(buf, sizeof(buf), OP_WRITE_RSP, GROUP_IMAGE, IMAGE_ID_UPLOAD);
	if (rc < 0)
	{
		return rc;
	}
	return 0;
}

typedef struct
{
	int rc;
	int off;
} upload_rsp_t;

static int recv_upload(upload_rsp_t* rsp)
{
	// Find keys pair describing the return code. 
	cbor_token_t* rc = cbor.get_key((char*)"rc");
	if (rc == NULL)
	{
		printf("rx: No return code!\n");
		return -2;
	}
	if (rc->int_value != 0)
	{
		printf("rx: Error rc=%d\n", rc->int_value);
		return -3;
	}
	cbor_token_t* off = cbor.get_key((char*)"off");
	if (rc == NULL)
	{
		printf("rx: No offset!\n");
		return -4;
	}
	rsp->rc = rc->int_value;
	rsp->off = off->int_value;
	TRACE("rc:%d off:%d\n", rsp->rc, rsp->off);
	return 0;
}

int send_upload_next(unsigned int offset, int* size, unsigned char* data)
{
	unsigned char buf[520];
	upload_rsp_t rsp;
	int rc;
	*size = (*size == 0) ? 0x0129 : 0x0154;
	//TRACE("offset=%d size=%d %d > %d\n", offset, *size, offset + *size, total_len);
	if ((offset + *size) > total_len)
	{
		*size = total_len - offset;
	}
	if (send_upload(buf, sizeof(buf), offset, *size, data) != 0)
	{
		return -1;
	}
	rc = recv_upload(&rsp);
	if (rc < 0)
	{
		return rc;
	}
	return 0;
}

int upload(char* fnimage)
{
	/* Dumb resource intensive way is to read the whole file into a large data buffer! */
	unsigned char* data = load_file(fnimage, (long *)&total_len);
	if (data == NULL)
	{
		return ERR_LOAD_FAILURE;
	}

	/* Send NMP packets broken up into several NLIP serial chunks that have the NMP packet
	** total length and a header in the first chunk, followed by a CBOR encoded map and a
	** crc16-ccitt value of the unencode packet in the last serial chunk.
	** Note that the first NMP packet is slighly shorter to accommodate some extra CBOR
	** encoded values that describe the total length of the image, etc. Subsequent packets
	** are longer and the final packet is variable based on the exact remainder needed for
	** the last fragment of the image.
	*/
	printf("Upload:");
	long count = 0;
	unsigned int offset = 0;
	int size = 0;
	do
	{
		printf(!(count++ % 32) ? "\n." : ".");
		send_upload_next(offset, &size, data);
		offset += size;
	} while (offset < total_len);
	printf("EOF\n");
	delete data;
	return 0;
}

#if 1
int _main(int argc, char* argv[]);

int main(int argc, char* argv[])
{
	argc = 0;
	argv[argc++] = (char *)"winlib";
	//argv[argc++] = (char *)"-d";
	argv[argc++] = (char*)"-p26";
	argv[argc++] = (char*)"blehci";			// ifile
	argv[argc++] = (char*)"-l";				//-"lwinlib.log";
	argv[argc++] = (char*)"-n";
	argv[argc++] = (char*)"-r";
	//argv[argc++] = (char *)"-t";
	argv[argc++] = (char*)"-ocapture";
	//argv[argc++] = (char *)"-q";
	//argv[argc++] = (char *)"-h";
	return _main(argc, argv);
}

int _main(int argc, char* argv[])
{
#else

int main(int argc, char* argv[])
{
#endif

	char* p;
	int i;
	int rc = 0;

	for (i = 1; --argc > 0; i++)          // parse command line options
	{
		p = argv[i];
		if (*p == '-')
		{
			while (*++p)
			{
				switch (*p)
				{
				case 'o':
					oflag++;
					if (strlen(p + 1))
					{
						ofile = p + 1;
					}
					p = (char*)" ";
					break;

				case 'l':
					lflag++;
					if (strlen(p + 1))
					{
						lfile = p + 1;
					}
					p = (char*)" ";
					break;

				case 'i':
					if (strlen(p + 1))
					{
						ifile = p + 1;
					}
					p = (char*)" ";
					break;

				case 'p':
					if (strlen(p + 1))
					{
						port = atoi(p + 1);
					}
					p = (char*)" ";
					break;

				case 't':
					tflag++;
					break;

				case 'n':
					nflag++;
					break;

				case 'r':
					rflag++;
					break;

				case 'd':
					dflag++;
					break;

				case 'q':
					qflag++;
					break;

				default:
					fprintf(stderr, "Usage: %s [-i][file] [-o][file] [-l][file] [-c] [-e] [-d]\n", argv[0]);
					fprintf(stderr, "[-i][file] image upload\n");
					fprintf(stderr, "-o[file]   capture output\n");
					fprintf(stderr, "-l[file]   log debug output\n");
					fprintf(stderr, "-pn        COM port number\n");
					fprintf(stderr, "-t         test capture\n");
					fprintf(stderr, "-d         dump data output\n");
					fprintf(stderr, "-n         send HCI commands to enable NMP mode\n");
					fprintf(stderr, "-r         send NMP reset command\n");
					fprintf(stderr, "-q         quiet mode\n");
					exit(1);
				}
			}
		}
		else
		{
			ifile = p;
		}
	}
	if (ifile)
	{
		strcpy(ifname, ifile);
		if (!strchr(ifname, '.'))
		{
			strcat(ifname, ".img");
		}
		ifile = ifname;
		fprintf(stdout, "ifile='%s'\n", ifile);
	}
	else
		fprintf(stdout, "ifile=stdin\n");

	if (oflag)
	{
		if (ofile)
		{
			strcpy(ofname, ofile);
			if (!strchr(ofname, '.'))
			{
				strcat(ofname, ".out");
			}
			ofile = ofname;
			fprintf(stdout, "ofile='%s'\n", ofile);
		}
		else
			fprintf(stdout, "ofile=stdout\n");
	}

	if (lflag)
	{
		if (!lfile)
		{
			lfile = argv[0];
		}
		strcpy(lfname, lfile);
		if (!strchr(lfile, '.'))
		{
			strcat(lfname, ".log");
		}
		lfile = lfname;
		fprintf(stdout, "lfile='%s'\n", lfile);
	}
	else
		fprintf(stdout, "lfile=NULL\n");

	// Open log file to capture output from putchar, puts and printf macros.
	LOG_Init(lfile);

	TMR_Init(100);	// 100ms timebase

	if (oflag)
	{
		if (!tflag)
		{
			printf("Capture upload to file '%s'\n", ofile);
			bf.InitWriteFile(ofile);
			if (!bf.IsFile())
			{
				printf("File Not Found!\n");
				goto err;
			}
		}
		else
		{
			printf("Read download from file '%s'\n", ofile);
			bf.InitReadFile(ofile);
			if (!bf.IsFile())
			{
				printf("File Not Found!\n");
				goto err;
			}
		}
	}

	if (port != 0)
	{
		COM_Init(port, 115200);
		TMR_Delay(5);

		if (COM_connected())
		{
			printf("Comport is connected!\n");

			if (nflag)
			{
				unsigned char HCI_SetUpload[] = {
					0x01,0x04,0xfc,0x01,0x01 };

				unsigned char HCI_Reset[] = {
					0x01,0x02,0xfc,0x00 };

				unsigned char buf[128];
				int n;
				if ((n = send_hci_cmd(buf, sizeof(buf), HCI_SetUpload, sizeof(HCI_SetUpload), 20)) == 0 ||
					(n = send_hci_cmd(buf, sizeof(buf), HCI_Reset, sizeof(HCI_Reset), 40)) == 0)
				{
					unsigned char buf[256];
					/* Ignore any spurious data sent from the bootloader. */
					recv_buf(buf, sizeof(buf), 100, -1);
					TRACE("Send <CR>\n");
					/* Sending a <CR> can help in resynchronizing the NMP serial link. */
					buf[0] = 0x0d;
					send_buf(buf, 1);
					TMR_Delay(1);

					COM_Term();
					rc = ERR_HCI_TIMEOUT;
					goto err;
				}
				// No specific response expected from the HCI_Reset, however the 'nmgr>' debug text 
				// is output, once the Bootloader is ready to accept NMP requests.
				if (!strncmp("nmgr>\n", (char*)&buf[n - 6], 6))
				{
					printf("nmgr>\n");
				}
			}
			rc = imagelist();
			if (rc < 0)
			{
				COM_Term();
				goto err;
			}
#if 0
			else
			{
				unsigned char buf[256];
				TMR_Delay(55);
				/* Ignore any spurious data sent from the bootloader. */
				recv_buf(buf, sizeof(buf), 100, -1);
				TRACE("Send <CR>\n");
				/* Sending a <CR> can help in resynchronizing the NMP serial link. */
				buf[0] = 0x0d;
				send_buf(buf, 1);
				TMR_Delay(1);
			}
#endif

			if (ifile)
			{
				rc = upload(ifile);
				if (rc < 0)
				{
					COM_Term();
					goto err;
				}
				rc = imagelist();
				if (rc < 0)
				{
					COM_Term();
					goto err;
				}
			}
			if (rflag)
			{
				rc = reset();
				if (rc < 0)
				{
					COM_Term();
					goto err;
				}
			}
		}
		COM_Term();
	}
	if (tflag && oflag)
	{
		rc = download(ofile);
		if (rc < 0)
		{
			goto err;
		}
	}

err:
	if (oflag)
	{
		bf.CloseFile();
	}
	TMR_Term();

	// Close capture log file.
	LOG_Term();

	return rc;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
