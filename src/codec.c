// Copyright (C) github.com/ldeng7

#include <string.h>

// TODO: del these, ldeng?
#define PACKET_TYPE_CONNECT      1
#define PACKET_TYPE_CONNACK      2
#define PACKET_TYPE_PUBLISH      3
#define PACKET_TYPE_PUBACK       4
#define PACKET_TYPE_PUBREC       5
#define PACKET_TYPE_PUBREL       6
#define PACKET_TYPE_PUBCOMP      7
#define PACKET_TYPE_SUBSCRIBE    8
#define PACKET_TYPE_SUBACK       9
#define PACKET_TYPE_UNSUBSCRIBE  10
#define PACKET_TYPE_UNSUBACK     11
#define PACKET_TYPE_PINGREQ      12
#define PACKET_TYPE_PINGRESP     13
#define PACKET_TYPE_DISCONNECT   14

typedef uint8_t bool;
typedef uint8_t byte;
typedef uint16_t word;

word decode_word(const char *s) {
    return ((word)(*s) << 8) | (word)(*(s + 1));
}


typedef struct {
    byte packet_type;
    bool flag3;
    bool flag2;
    bool flag1;
    bool flag0;
    uint32_t remaining_length;
} fixed_header_t;

void decode_fixed_header(fixed_header_t *fh, byte b0, byte b1, byte b2, byte b3, byte b4)) {
    uint32_t l;

    fh->packet_type = b0 >> 4;
    fh->flag3 = (b0 >> 3) & 1;
    fh->flag2 = (b0 >> 2) & 1;
    fh->flag1 = (b0 >> 1) & 1;
    fh->flag0 = b0 & 1;

    l = (uint32_t)(b1 & 0x7f);
    if (b1 & 0x80) {
        l |= (uint32_t)(b2 & 0x7f) << 7;
        if (b2 & 0x80) {
            l |= (uint32_t)(b3 & 0x7f) << 14;
            if (b1 & 0x80) {
                l |= (uint32_t)(b4 & 0x7f) << 21;
            }
        }
    }
    fh->remaining_length = l;
}


typedef struct {
    char protocol_name[7];
    byte protocol_level;
    bool user_name_flag;
    bool password_flag;
    bool will_retain_flag;
    byte will_qos;
    bool will_flag;
    bool clean_session_flag;
    bool reserved_flag;
} var_header_connect_t;

void decode_var_header_connect(var_header_connect_t *vh, const char *s) {
    byte b;

    memcpy(vh->protocol_name, s, 6);
    s += 6;
    vh->protocol_level = *s++;

    b = *s++;
    vh->user_name_flag = b >> 7;
    vh->password_flag = (b >> 6) & 1;
    vh->will_retain_flag = (b >> 5) & 1;
    vh->will_qos = (b >> 3) & 0x03;
    vh->will_flag = (b >> 2) & 1;
    vh->clean_session_flag = (b >> 1) & 1;
    vh->reserved_flag = b & 1;

    vh->keep_alive = decode_word(s);
}