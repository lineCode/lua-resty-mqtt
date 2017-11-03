// Copyright (C) github.com/ldeng7

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

typedef uint8_t byte;
typedef uint16_t word;

word read_word(const char *s) {
    return ((word)(*s) << 8) | (word)(*(s + 1));
}

word read_word_offset(const char *s, word offset) {
    s += offset;
    return ((word)(*s) << 8) | (word)(*(s + 1));
}

void write_word(byte *buf, word w) {
    *buf++ = (byte)(w >> 8);
    *buf = (byte)(w & 0xff);
}


typedef struct {
    byte packet_type;
    bool flag3;
    bool flag2;
    bool flag1;
    bool flag0;
    uint32_t remaining_length;
} fixed_header_t;

void decode_fixed_header(fixed_header_t *fh, byte b0, byte b1, byte b2, byte b3, byte b4) {
    uint32_t l;

    fh->packet_type = b0 >> 4;
    fh->flag3 = (b0 >> 3) & 0x01;
    fh->flag2 = (b0 >> 2) & 0x01;
    fh->flag1 = (b0 >> 1) & 0x01;
    fh->flag0 = b0 & 0x01;

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

word encode_fixed_header(byte *buf, fixed_header_t *fh) {
    byte *begin = buf;
    uint32_t l = fh->remaining_length;
    *buf++ = (fh->packet_type << 4) |
        ((fh->flag3 & 0x01) << 3) | ((fh->flag2 & 0x01) << 2) | ((fh->flag1 & 0x01) << 1) | (fh->flag0 & 0x01);
    *buf = l & 0x7f;
    l >>= 7;
    if (l) {
        *buf++ |= 0x80;
        *buf = l & 0x7f;
        l >>= 7;
        if (l) {
            *buf++ |= 0x80;
            *buf = l & 0x7f;
            l >>= 7;
            if (l) {
                *buf++ |= 0x80;
                *buf = l & 0x7f;
            }
        }
    }
    return buf - begin;
}

typedef struct {
    char protocol_name[6];
    byte protocol_level;
    bool user_name_flag;
    bool password_flag;
    bool will_retain_flag;
    byte will_qos;
    bool will_flag;
    bool clean_session_flag;
    bool reserved_flag;
    word keep_alive;
} var_header_connect_t;

void decode_var_header_connect(var_header_connect_t *vh, const char *s) {
    byte b;
    memcpy(vh->protocol_name, s, 6);
    s += 6;
    vh->protocol_level = *s++;

    b = *s++;
    vh->user_name_flag = b >> 7;
    vh->password_flag = (b >> 6) & 0x01;
    vh->will_retain_flag = (b >> 5) & 0x01;
    vh->will_qos = (b >> 3) & 0x03;
    vh->will_flag = (b >> 2) & 0x01;
    vh->clean_session_flag = (b >> 1) & 0x01;
    vh->reserved_flag = b & 0x01;

    vh->keep_alive = read_word(s);
}

void encode_var_header_connect(byte *buf, var_header_connect_t *vh) {
    memcpy(buf, vh->protocol_name, 6);
    buf += 6;
    *buf++ = vh->protocol_level;
    
    *buf++ = ((vh->user_name_flag & 0x01) << 7) | ((vh->password_flag & 0x01) << 6) |
        ((vh->will_retain_flag & 0x01) << 5) | ((vh->will_qos & 0x03) << 3) |
        ((vh->will_flag & 0x01) << 2) | ((vh->clean_session_flag & 0x01) << 1) | (vh->reserved_flag & 0x01);
    write_word(buf, vh->keep_alive);
}


typedef struct {
    bool session_present_flag;
    byte return_code;
} var_header_connack_t;

void decode_var_header_connack(var_header_connack_t *vh, const char *s) {
    vh->session_present_flag = (*s++) & 0x01;
    vh->return_code = *s;
}

void encode_var_header_connack(byte *buf, var_header_connack_t *vh) {
    *buf++ = vh->session_present_flag & 0x01;
    *buf++ = vh->return_code;
}
