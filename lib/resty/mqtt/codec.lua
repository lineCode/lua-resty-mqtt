-- Copyright (C) github.com/ldeng7

local ipairs = ipairs
local type = type
local string_sub = string.sub
local string_byte = string.byte
local ffi = require "ffi"
local C = ffi.C

ffi.cdef[[
void *memcpy (void *dest, const void *src, size_t n);
typedef uint8_t byte;
typedef uint16_t word;
word read_word_offset(const char *s, word offset);
void write_word(byte *buf, word w);

typedef struct {
    byte packet_type;
    bool flag3;
    bool flag2;
    bool flag1;
    bool flag0;
    uint32_t remaining_length;
} fixed_header_t;
void decode_fixed_header(fixed_header_t *fh, byte b0, byte b1, byte b2, byte b3, byte b4);
word encode_fixed_header(byte *buf, fixed_header_t *fh);

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
void decode_var_header_connect(var_header_connect_t *vh, const char *s);
void encode_var_header_connect(byte *buf, var_header_connect_t *vh);

typedef struct {
    bool session_present_flag;
    byte return_code;
} var_header_connack_t;
void decode_var_header_connack(var_header_connack_t *vh, const char *s);
void encode_var_header_connack(byte *buf, var_header_connack_t *vh);
]]

local clib = ffi.load(os.getenv("MQTT_LIB_DIR") .. "/libmqtt.so")

---------
-- decode
---------

local read_string = function(bs, offset)
    local l = ((offset <= #bs - 2) and clib.read_word_offset(bs, offset)) or 0
    local offset_new = offset + 2 + l
    return string_sub(bs, offset + 3, offset_new), offset_new
end

local decode_fixed_header = function(reader)
    local bs, err = reader:read(2)
    if not bs then return nil, err end
    local b0, b1 = string_byte(bs, 1, 2)

    local b2, b3, b4 = 0, 0, 0
    bs, err = reader:read(1)
    if not bs then return nil, err end
    b2 = string_byte(bs)
    if b2 >= 128 then
        bs, err = reader:read(1)
        if not bs then return nil, err end
        b3 = string_byte(bs)
        if b3 >= 128 then
            bs, err = reader:read(1)
            if not bs then return nil, err end
            b4 = string_byte(bs)
        end
    end

    local fh = ffi.new("fixed_header_t[1]")
    clib.decode_fixed_header(fh, b0, b1, b2, b3, b4)
    return fh[0], nil
end

local decode_connect = function(bs, fh)
    local vh = ffi.new("var_header_connect_t[1]")
    --ldeng: "\0\4MQTT" == ffi.string(vh.protocal_name, 6)
    clib.decode_var_header_connect(vh, bs)
    vh = vh[0]
    local cur = 10

    local pl = {}
    pl.client_id, cur = read_string(bs, cur)
    if vh.will_retain_flag then
        pl.will_topic, cur = read_string(bs, cur)
    end
    if vh.user_name_flag then
        pl.username, cur = read_string(bs, cur)
    end
    if vh.password_flag then
        pl.password, cur = read_string(bs, cur)
    end

    return vh, pl, cur
end

local decode_connack = function(bs, fh)
    local vh = ffi.new("var_header_connack_t[1]")
    clib.decode_var_header_connack(vh, bs)
    return vh[0], nil, 2
end

local decode_publish = function(bs, fh)
    local vh, cur = {}, 0
    vh.topic_name, cur = read_string(bs, cur)
    vh.packet_id = clib.read_word_offset(bs, cur)
    cur = cur + 2
    local pl = string_sub(bs, cur + 1)
    return vh, pl, cur + #pl
end

local decode_packet_id = function(bs, fh)
    return clib.read_word_offset(bs, 0), nil, 2
end

local decode_subscribe = function(bs, fh)
    local vh = clib.read_word_offset(bs, 0)
    local cur = 2
    local cur_end = #bs

    local pl = {}
    while cur <= cur_end - 3 do
        local filter = {}
        filter.topic, cur = read_string(bs, cur)
        filter.qos = string_byte(bs, cur + 1)
        cur = cur + 1
        pl[#pl + 1] = filter
    end

    return vh, pl, cur
end

local decode_suback = function(bs, fh)
    local vh = clib.read_word_offset(bs, 0)
    local cur = 2
    local pl = {string_byte(bs, cur + 1, -1)}
    return vh, pl, cur + #pl
end

local decode_unsubscribe = function(bs, fh)
    local vh = clib.read_word_offset(bs, 0)
    local cur = 2
    local cur_end = #bs

    local pl = {}
    while cur <= cur_end - 2 do
        pl[#pl + 1], cur = read_string(bs, cur)
    end

    return vh, pl, cur
end

local decode_non = function(bs, fh)
    return nil, nil, 0
end

local types_decode = {
    decode_connect,
    decode_connack,
    decode_publish,
    decode_packet_id,
    decode_packet_id,
    decode_packet_id,
    decode_packet_id,
    decode_subscribe,
    decode_suback,
    decode_unsubscribe,
    decode_packet_id,
    decode_non,
    decode_non,
    decode_non,
}

---------
-- create
---------

local types_create = {
    function()
        local vh = ffi.new("var_header_connect_t[1]")[0]
        vh.protocol_name = "\0\4MQTT"
        vh.protocol_level = 4
        return vh, {} end,
    function() return ffi.new("var_header_connack_t[1]")[0], nil end,
    function() return {}, "" end,
    function() return 0, nil end,
    function() return 0, nil end,
    function() return 0, nil end,
    function() return 0, nil end,
    function() return 0, {} end,
    function() return 0, {} end,
    function() return 0, {} end,
    function() return 0, nil end,
    function() return nil, nil end,
    function() return nil, nil end,
    function() return nil, nil end,
}

---------
-- encode
---------

local types_cal = {
    function(vh, pl) return 16 + #pl.will_topic + #pl.username + #pl.password end,
    2,
    function(vh, pl) return 4 + #vh.topic_name + #pl end,
    2,
    2,
    2,
    2,
    function(vh, pl)
        local sum = 2
        for _, filter in ipairs(pl) do
            sum = sum + 3 + #filter.topic
        end
        return sum end,
    function(vh, pl) return 2 + #pl end,
    function(vh, pl)
        local sum = 2
        for _, filter in ipairs(pl) do
            sum = sum + 2 + #filter.topic
        end
        return sum end,
    2,
    0,
    0,
    0,
}

local write_string = function(buf, cur, s)
    local sz = #s
    if sz >= 65536 then return 0 end
    clib.write_word_offset(buf + cur, sz)
    cur = cur + 2
    C.memcpy(buf + cur, s, sz)
    return cur + sz
end

local encode_connect = function(buf, vh, pl)
    clib.encode_var_header_connect(buf, vh)
    local cur = 10
    if vh.will_retain_flag then
        cur = write_string(buf, cur, pl.will_topic)
    end
    if vh.user_name_flag then
        cur = write_string(buf, cur, pl.username)
    end
    if vh.password_flag then
        cur = write_string(buf, cur, pl.password)
    end
    return cur
end

local encode_connack = function(buf, vh, pl)
    clib.encode_var_header_connack(buf, vh)
    return 2
end

local encode_publish = function(buf, vh, pl)
    local cur = write_string(buf, 0, vh.topic_name)
    clib.write_word(buf + cur, vh.packet_id)
    cur = cur + 2
    C.memcpy(buf + cur, pl, #pl)
    return cur + #pl
end

local encode_packet_id = function(buf, vh, pl)
    clib.write_word(buf, vh)
    return 2
end

local encode_subscribe = function(buf, vh, pl)
    clib.write_word(buf, vh)
    local cur = 2
    for _, filter in ipairs(pl) do
        cur = write_string(buf, cur, filter.topic)
        buf[cur] = filter.qos
        cur = cur + 1
    end
    return cur
end

local encode_suback = function(buf, vh, pl)
    clib.write_word(buf, vh)
    local cur = 2
    for _, b in ipairs(pl) do
        buf[cur] = b
        cur = cur + 1
    end
    return cur
end

local encode_unsubscribe = function(buf, vh, pl)
    clib.write_word_offset(buf, vh)
    local cur = 2
    for _, topic in ipairs(pl) do
        cur = write_string(buf, cur, topic)
    end
    return cur
end

local encode_non = function(buf, vh, pl)
    return 0
end

local types_encode = {
    encode_connect,
    encode_connack,
    encode_publish,
    encode_packet_id,
    encode_packet_id,
    encode_packet_id,
    encode_packet_id,
    encode_subscribe,
    encode_suback,
    encode_unsubscribe,
    encode_packet_id,
    encode_non,
    encode_non,
    encode_non,
}

local _M = {}

_M.read = function(reader)
    local fh, err = decode_fixed_header(reader)
    if not fh then return nil, err end

    local func = types_decode[fh.packet_type]
    if not func then return nil, "invalid type" end
    local bs, err = reader:read(fh.remaining_length)
    if not bs then return nil, err end
    local vh, pl, cur = func(bs, fh)
    if cur > #bs then return nil, "invalid packet" end

    return {fh, vh, pl}, nil
end

_M.create = function(typ)
    local fh = ffi.new("var_header_connect_t[1]")[0]
    fh.packet_type = typ
    local func = types_create[typ]
    if not func then return nil, "invalid type" end
    local vh, pl = func()
    return {fh, vh, pl}, nil
end

_M.encode = function(obj)
    local fh, vh, pl = obj[1], obj[2], obj[3]
    local typ = fh.packet_type

    local cal = types_cal[typ]
    if not cal then return nil, "invalid type" end
    if "function" == type(cal) then
        cal = cal(vh, pl)
    end
    local buf_rem = ffi.new("byte[?]", cal)
    local len_rem = types_encode[typ](buf_rem, vh, pl)

    fh.remaining_length = len_rem
    local buf = ffi.new("byte[?]", 5 + len_rem)
    local len_fh = clib.encode_fixed_header(buf, fh)
    if len_rem > 0 then
        C.memcpy(buf + len_fh, buf_rem, len_rem)
    end
    return ffi.string(buf, len_fh + len_rem)
end

return _M
