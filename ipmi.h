#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#define PAYLOAD_IPMI			0
#define PAYLOAD_SOL			1
#define PAYLOAD_RMCPPLUSOPEN_REQ	0x10
#define PAYLOAD_RMCPPLUSOPEN_REP	0x11
#define PAYLOAD_RAKP1			0x12
#define PAYLOAD_RAKP2			0x13
#define PAYLOAD_RAKP3			0x14
#define PAYLOAD_RAKP4			0x15

/*
RMCP_ERRORS = {
    1 => "Insufficient resources to create new session (wait for existing sessions to timeout)",
    2 => "Invalid Session ID", #this shouldn't occur...
    3 => "Invalid payload type",#shouldn't occur..
    4 => "Invalid authentication algorithm", #if this happens, we need to enhance our mechanism for detecting supported auth algorithms
    5 => "Invalid integrity algorithm", #same as above
    6 => "No matching authentication payload",
    7 => "No matching integrity payload",
    8 => "Inactive Session ID", #this suggests the session was timed out while trying to negotiate, shouldn't happen
    9 => "Invalid role",
    0xa => "Unauthorised role or privilege level requested",
    0xb => "Insufficient resources to create a session at the requested role",
    0xc => "Invalid username length",
    0xd => "Unauthorized name",
    0xe => "Unauthorized GUID",
    0xf => "Invalid integrity check value",
    0x10 => "Invalid confidentiality algorithm",
    0x11 => "No cipher suite match with proposed security algorithms",
    0x12 => "Illegal or unrecognized parameter", #have never observed this, would most likely mean a bug in xCAT or IPMI device
  }
*/

char* RMCP_ERRORS[] = {
	"ALL OK 8)",
	"Insufficient resources to create new session (wait for existing sessions to timeout)",
	"Invalid Session ID", //this shouldn't occur...
	"Invalid payload type", //shouldn't occur..
	"Invalid authentication algorithm", // if this happens, we need to enhance our mechanism for detecting supported auth algorithms
	"Invalid integrity algorithm",  // same as above
	"No matching authentication payload",
	"No matching integrity payload",
	"Inactive Session ID", // this suggests the session was timed out while trying to negotiate, shouldn't happen
	"Invalid role",
	"Unauthorised role or privilege level requested",
	"Insufficient resources to create a session at the requested role",
	"Invalid username length",
	"Unauthorized name",
	"Unauthorized GUID",
	"Invalid integrity check value",
	"Invalid confidentiality algorithm",
	"No cipher suite match with proposed security algorithms",
	"Illegal or unrecognized parameter", //have never observed this, would most likely mean a bug in xCAT or IPMI device
};

/*
class RAKP2 < BitStruct
  unsigned :rmcp_version,      8,     "RMCP Version"
  unsigned :rmcp_padding,      8,     "RMCP Padding"
  unsigned :rmcp_sequence,     8,     "RMCP Sequence"
  unsigned :rmcp_mtype,    1,     "RMCP Message Type"
  unsigned :rmcp_class,    7,     "RMCP Message Class"

  unsigned :session_auth_type,  8,     "Authentication Type"

  unsigned :session_payload_encrypted,  1,     "Session Payload Encrypted"
  unsigned :session_payload_authenticated,  1,     "Session Payload Authenticated"
  unsigned :session_payload_type,  6,     "Session Payload Type", :endian => 'little'

  unsigned :session_id,  32,     "Session ID"
  unsigned :session_sequence,  32,     "Session Sequence Number"
  unsigned :message_length,  16,     "Message Length", :endian => "little"

  unsigned :ignored1, 8, "Ignored"
  unsigned :error_code, 8, "RMCP Error Code"
  unsigned :ignored2, 16, "Ignored"
  char :console_session_id, 32, "Console Session ID"
  char :bmc_random_id,  128,     "BMC Random ID"
  char :bmc_guid,  128,     "RAKP2 Hash 2 (nulls)"
  char :hmac_sha1,  160,     "HMAC_SHA1 Output"
  rest :stuff, "The rest of the stuff"
end
*/

typedef struct  {
	uint8_t		rmcp_version;
	uint8_t		rmcp_padding;
	uint8_t		rmcp_sequence;
	uint8_t		rmcp_class:7;
	uint8_t		rmcp_mtype:1;

	uint8_t		session_auth_type;

	uint8_t		session_payload_type:6;
	uint8_t		session_payload_authenticated:1;
	uint8_t		session_payload_encrypted:1;

	uint32_t	session_id;
	uint32_t	session_sequence;
	uint16_t	message_length;

	uint8_t		ignored1;
	uint8_t		error_code;
	uint16_t	ignored2;

	char		console_session_id[4];
	char		bmc_random_id[16];
	char		bmc_guid[16];
	char		hmac_sha1[20];
} __attribute__((__packed__)) RAKP2;

/*
class Channel_Auth_Reply < BitStruct
  unsigned :rmcp_version,                    8,     "RMCP Version"
  unsigned :rmcp_padding,                    8,     "RMCP Padding"
  unsigned :rmcp_sequence,                   8,     "RMCP Sequence"
  unsigned :rmcp_mtype,                      1,     "RMCP Message Type"
  unsigned :rmcp_class,                      7,     "RMCP Message Class"

  unsigned :session_auth_type,               8,     "Session Auth Type"
  unsigned :session_sequence,               32,     "Session Sequence Number"
  unsigned :session_id,                     32,     "Session ID"
  unsigned :message_length,                  8,     "Message Length"

  unsigned :ipmi_tgt_address,                8,     "IPMI Target Address"
  unsigned :ipmi_tgt_lun,                    8,     "IPMI Target LUN"
  unsigned :ipmi_header_checksum,            8,     "IPMI Header Checksum"
  unsigned :ipmi_src_address,                8,     "IPMI Source Address"
  unsigned :ipmi_src_lun,                    8,     "IPMI Source LUN"
  unsigned :ipmi_command,                    8,     "IPMI Command"
  unsigned :ipmi_completion_code,            8,     "IPMI Completion Code"

  unsigned :ipmi_channel,                    8,     "IPMI Channel"

  unsigned :ipmi_compat_20,                  1,     "IPMI Version Compatibility: IPMI 2.0+"
  unsigned :ipmi_compat_reserved1,           1,     "IPMI Version Compatibility: Reserved 1"
  unsigned :ipmi_compat_oem_auth,            1,     "IPMI Version Compatibility: OEM Authentication"
  unsigned :ipmi_compat_password,            1,     "IPMI Version Compatibility: Straight Password"
  unsigned :ipmi_compat_reserved2,           1,     "IPMI Version Compatibility: Reserved 2"
  unsigned :ipmi_compat_md5,                 1,     "IPMI Version Compatibility: MD5"
  unsigned :ipmi_compat_md2,                 1,     "IPMI Version Compatibility: MD2"
  unsigned :ipmi_compat_none,                1,     "IPMI Version Compatibility: None"

  unsigned :ipmi_user_reserved1,             2,     "IPMI User Compatibility: Reserved 1"
  unsigned :ipmi_user_kg,                    1,     "IPMI User Compatibility: KG Set to Default"
  unsigned :ipmi_user_disable_message_auth,  1,     "IPMI User Compatibility: Disable Per-Message Authentication"
  unsigned :ipmi_user_disable_user_auth,     1,     "IPMI User Compatibility: Disable User-Level Authentication"
  unsigned :ipmi_user_non_null,              1,     "IPMI User Compatibility: Non-Null Usernames Enabled"
  unsigned :ipmi_user_null,                  1,     "IPMI User Compatibility: Null Usernames Enabled"
  unsigned :ipmi_user_anonymous,             1,     "IPMI User Compatibility: Anonymous Login Enabled"

  unsigned :ipmi_conn_reserved1,             6,     "IPMI Connection Compatibility: Reserved 1"
  unsigned :ipmi_conn_20,                    1,     "IPMI Connection Compatibility: 2.0"
  unsigned :ipmi_conn_15,                    1,     "IPMI Connection Compatibility: 1.5"

  unsigned :ipmi_oem_id,                    24,     "IPMI OEM ID", :endian => 'little'

  rest :ipm_oem_data, "IPMI OEM Data + Checksum Byte"
*/

typedef struct  {

	uint8_t		rmcp_version;
	uint8_t		rmcp_padding;
	uint8_t		rmcp_sequence;
	uint8_t		rmcp_class:7;
	uint8_t		rmcp_mtype:1;

	uint8_t		session_auth_type;
	uint32_t	session_sequence;
	uint32_t	session_id;
	uint8_t		message_length;

	uint8_t		ipmi_tgt_address;
	uint8_t		ipmi_tgt_lun;
	uint8_t		ipmi_header_checksum;
	uint8_t		ipmi_src_address;
	uint8_t		ipmi_src_lun;
	uint8_t		ipmi_command;
	uint8_t		ipmi_completion_code;

	uint8_t		ipmi_channel;

	uint8_t		ipmi_compat_none:1;
	uint8_t		ipmi_compat_md2:1;
	uint8_t		ipmi_compat_md5:1;
	uint8_t		ipmi_compat_reserved2:1;
	uint8_t		ipmi_compat_password:1;
	uint8_t		ipmi_compat_oem_auth:1;
	uint8_t		ipmi_compat_reserved1:1;
	uint8_t		ipmi_compat_20:1;

	uint8_t		ipmi_user_anonymous:1;
	uint8_t		ipmi_user_null:1;
	uint8_t		ipmi_user_non_null:1;
	uint8_t		ipmi_user_disable_user_auth:1;
	uint8_t		ipmi_user_disable_message_auth:1;
	uint8_t		ipmi_user_kg:1;
	uint8_t		ipmi_user_reserved1:2;

	uint8_t		ipmi_conn_15:1;
	uint8_t		ipmi_conn_20:1;
	uint8_t		ipmi_conn_reserved1:6;

	uint32_t	ipmi_oem_id:24;
}  __attribute__((__packed__)) ChannelAuthReply;

/*
class Open_Session_Reply < BitStruct
  unsigned :rmcp_version,  8,  "RMCP Version"
  unsigned :rmcp_padding,  8,  "RMCP Padding"
  unsigned :rmcp_sequence, 8,  "RMCP Sequence"
  unsigned :rmcp_mtype,    1,  "RMCP Message Type"
  unsigned :rmcp_class,    7,  "RMCP Message Class"

  unsigned :session_auth_type, 8,  "Authentication Type"

  unsigned :session_payload_encrypted,     1,  "Session Payload Encrypted"
  unsigned :session_payload_authenticated, 1,  "Session Payload Authenticated"
  unsigned :session_payload_type,          6,  "Session Payload Type", :endian => 'little'

  unsigned :session_id,       32,  "Session ID"
  unsigned :session_sequence, 32,  "Session Sequence Number"
  unsigned :message_length,   16,  "Message Length", :endian => "little"

  unsigned :ignored1,        8, "Ignored"
  unsigned :error_code,      8, "RMCP Error Code"
  unsigned :ignored2,       16, "Ignored"
  char :console_session_id, 32, "Console Session ID"
  char :bmc_session_id,     32, "BMC Session ID"

  rest :stuff, "The Rest of the Stuff"
end
*/

typedef struct {
	uint8_t		rmcp_version;
	uint8_t		rmcp_padding;
	uint8_t		rmcp_sequence;
	uint8_t		rmcp_class:7;
	uint8_t		rmcp_mtype:1;

	uint8_t		session_auth_type;

	uint8_t		session_payload_type:6;
	uint8_t		session_payload_authenticated:1;
	uint8_t		session_payload_encrypted:1;

	uint32_t	session_id;
	uint32_t	session_sequence;
	uint16_t	message_length;

	uint8_t		ignored1;
	uint8_t		error_code;
	uint16_t	ignored2;
	char		console_session_id[4];
	char		bmc_session_id[4];
} __attribute__((__packed__)) OpenSessionReplay;



