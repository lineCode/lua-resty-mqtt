-- Copyright (C) github.com/ldeng7

local string_byte = string.byte
local ffi = require "ffi"

ffi.cdef[[
typedef uint8_t bool;
typedef uint8_t byte;
typedef uint16_t word;
word decode_word(const char *s);

typedef struct {
    byte packet_type;
    bool flag3;
    bool flag2;
    bool flag1;
    bool flag0;
    uint32_t remaining_length;
} fixed_header_t;
void decode_fixed_header(fixed_header_t *fh, byte b0, byte b1, byte b2, byte b3, byte b4);

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
    word keep_alive;
} var_header_connect_t;
void decode_var_header_connect(var_header_connect_t *vh, const char *s)
]]

local clib = ffi.load(os.getenv("MQTT_LIB_DIR") .. "/libmqtt.so")

local read_string = function(sock)
    local bs, err = sock.read(2)
    if not err then return nil, err end
    local l = clib.decode_word(bs)
    if 0 == l then return "", nil end
    return sock.read(l), nil
end


local decode_connect = function(sock)
    local bs, err = sock.read(10)
    if not err then return nil, nil, err end
    local vh = ffi.new("var_header_connect_t[1]")
    clib.decode_var_header_connect(vh, bs)--ldeng: "\0\4MQTT" == ffi.string(vh.protocal_name, 6)
    vh = vh[0]

    local pl = {}
    pl.client_id, err = read_string(sock)
    if not err then return nil, nil, err end
    if 1 == vh.will_retain_flag then
        pl.will_topic = read_string(sock)
        if not err then return nil, nil, err end
    end
    if 1 == vh.user_name_flag then
        pl.username = read_string(sock)
        if not err then return nil, nil, err end
    end
    if 1 == vh.password_flag then
        pl.password = read_string(sock)
        if not err then return nil, nil, err end
    end

    return vh, pl, nil
end


local decode_fixed_header = function(sock)
    local bs, err = sock:read(2)
    if not err then return nil, err end
    local b0, b1 = string_byte(bs, 1, 2)
    local b2, b3, b4 = 0, 0, 0
    bs, err = sock:read(1)
    if not err then return nil, err end
    b2 = string_byte(bs)
    if b2 >= 128 then
        bs, err = sock:read(1)
        if not err then return nil, err end
        b3 = string_byte(bs)
        if b3 >= 128 then
            bs, err = sock:read(1)
            if not err then return nil, err end
            b4 = string_byte(bs)
        end
    end

    local fh = ffi.new("fixed_header_t[1]")
    clib.decode_fixed_header(fh, b0, b1, b2, b3, b4)
    fh = fh[0]
    return fh, nil
end

local _M = {}

_M.decode_packet = function(sock)
    local fh, err = decode_fixed_header(sock)
    if not err then return nil, err end

    return {fh}, nil
end

return _M
