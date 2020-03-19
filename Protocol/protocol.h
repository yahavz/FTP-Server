#ifndef PROTOCOL_H_
#define PROTOCOL_H_

#include <Windows.h>

#define TYPE_SYN 0x1
#define TYPE_ACK 0x2
#define TYPE_SYNACK (TYPE_SYN| TYPE_ACK)
#define TYPE_PSH 0x4
#define TYPE_EOP 0x8
#define TYPE_EOPACK (TYPE_EOP| TYPE_ACK)
#define TYPE_FIN 0x10

#define MAX_CHUNKS (128)
#define MAX_PHASE_INDEX ((MAXDWORD / 128) - 1)
#define ACK_BITFIELD_SIZE (MAX_CHUNKS / 8)
#define CRC_SIZE (sizeof(((p_packet_headers)0)->crc))

#define PACKET_HEADERS_SIZE (sizeof(packet_headers))
#define SYN_PACKET_SIZE (sizeof(syn_packet))
#define SYNACK_PACKET_SIZE (sizeof(synack_packet))
#define PSH_PACKET_SIZE (sizeof(psh_packet))
#define EOP_PACKET_SIZE (sizeof(eop_packet))
#define EOPACK_PACKET_SIZE (sizeof(eopack_packet))
#define FIN_PACKET_SIZE (sizeof(fin_packet))

#pragma pack(1)

typedef struct {
	USHORT crc;
	BYTE type;
}packet_headers, *p_packet_headers;

typedef struct {
	packet_headers headers;
	DWORD numberOfChunks;
} syn_packet, *p_syn_packet;

typedef struct {
	packet_headers headers;
} synack_packet, *p_synack_packet;

typedef struct {
	packet_headers headers;
	USHORT fragSize;
	DWORD fragPhase;
	BYTE fragIndex;

	/* Here comes the data of the fragment*/

} psh_packet, *p_psh_packet;

typedef struct {
	packet_headers headers;
	DWORD fragPhase;
} eop_packet, *p_eop_packet;

typedef struct {
	packet_headers headers;
	DWORD ackPhase;
	BYTE ackField[ACK_BITFIELD_SIZE];
} eopack_packet, *p_eopack_packet;

typedef struct {
	packet_headers headers;
} fin_packet, *p_fin_packet;

#pragma pack()

USHORT crc16(const BYTE *data, USHORT size);

#endif // !PROTOCOL_H_