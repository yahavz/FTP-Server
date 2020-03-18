#ifndef PROTOCOL_H_
#define PROTOCOL_H_

#include <Windows.h>

#define TYPE_SYN 0x1
#define TYPE_ACK 0x2
#define TYPE_PSH 0x4
#define TYPE_EOP 0x8
#define TYPE_FIN 0x10

#define MAX_FRAGMENT_AT_ONCE (128)
#define MAX_PHASE_INDEX ((MAXDWORD / 128) - 1)
#define ACK_BITFIELD_SIZE (MAX_FRAGMENT_AT_ONCE / 8)

#define PACKET_HEADERS_SIZE (sizeof(packet_headers))
#define SYN_PACKET_SIZE (PACKET_HEADERS_SIZE + sizeof(syn_packet))
#define SYNACK_PACKET_SIZE (PACKET_HEADERS_SIZE)
#define PSH_PACKET_SIZE (PACKET_HEADERS_SIZE + sizeof(psh_packet))
#define EOPACK_PACKET_SIZE (PACKET_HEADERS_SIZE + sizeof(eopack_packet))
#define FIN_PACKET_SIZE (PACKET_HEADERS_SIZE)

#pragma pack(1)

typedef struct {
	USHORT crc;
	BYTE type;
}packet_headers, *p_packet_headers;

typedef struct {
	DWORD numberOfChunks;
} syn_packet, *p_syn_packet;

typedef struct {
	USHORT fragSize;
	DWORD fragPhase;
	BYTE fragIndex;

	/* Here comes the data of the fragment*/

} psh_packet, *p_psh_packet;

typedef struct {
	DWORD fragPhase;
} eop_packet, *p_eop_packet;

typedef struct {
	DWORD ackPhase;
	BYTE ackField[ACK_BITFIELD_SIZE];
} eopack_packet, *p_eopack_packet;

#pragma pack()

USHORT crc16(const BYTE *data, USHORT size);

#endif // !PROTOCOL_H_