#include "decode.h"
#include <string.h>

typedef struct {
    const uint8_t *data;
    size_t len;
    size_t pos;
} Reader;

static bool r_u8(Reader *r, uint8_t *out) {
    if (r->pos + 1 > r->len) return false;
    *out = r->data[r->pos++];
    return true;
}

static bool r_u16(Reader *r, uint16_t *out) {
    if (r->pos + 2 > r->len) return false;
    *out = (uint16_t)r->data[r->pos] | ((uint16_t)r->data[r->pos + 1] << 8);
    r->pos += 2;
    return true;
}

static bool r_u32(Reader *r, uint32_t *out) {
    if (r->pos + 4 > r->len) return false;
    *out = (uint32_t)r->data[r->pos] |
           ((uint32_t)r->data[r->pos + 1] << 8) |
           ((uint32_t)r->data[r->pos + 2] << 16) |
           ((uint32_t)r->data[r->pos + 3] << 24);
    r->pos += 4;
    return true;
}

static bool r_i32(Reader *r, int32_t *out) {
    uint32_t v;
    if (!r_u32(r, &v)) return false;
    *out = (int32_t)v;
    return true;
}

static bool r_f32(Reader *r, float *out) {
    uint32_t v;
    if (!r_u32(r, &v)) return false;
    memcpy(out, &v, 4);
    return true;
}

static bool r_fixed_str(Reader *r, char *out, size_t out_size, size_t str_len) {
    if (r->pos + str_len > r->len) return false;
    size_t copy = str_len < out_size - 1 ? str_len : out_size - 1;
    memcpy(out, r->data + r->pos, copy);
    out[copy] = '\0';
    r->pos += str_len;
    return true;
}

static bool r_u8_len_str(Reader *r, char *out, size_t out_size) {
    uint8_t len;
    if (!r_u8(r, &len)) return false;
    return r_fixed_str(r, out, out_size, len);
}

static bool r_u32_len_str(Reader *r, char *out, size_t out_size) {
    uint32_t len;
    if (!r_u32(r, &len)) return false;
    if (len > 4096) return false;
    return r_fixed_str(r, out, out_size, len);
}

static void esc_json(const char *in, char *out, size_t out_size) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 2 < out_size; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') {
            if (j + 2 >= out_size) break;
            out[j++] = '\\';
            out[j++] = (char)c;
        } else if (c < 0x20) {
            if (j + 6 >= out_size) break;
            j += snprintf(out + j, out_size - j, "\\u%04x", c);
        } else {
            out[j++] = (char)c;
        }
    }
    out[j] = '\0';
}

bool decode_rpc_fields(const IdentifiedMessage *msg, PacketDirection dir,
                       char *out, size_t out_size) {
    if (msg->type != MSG_RPC) return false;
    if (msg->payload_len == 0) return false;

    Reader r = { msg->payload, msg->payload_len, 0 };
    out[0] = '\0';

    if (dir == DIR_CLIENT_TO_SERVER) {
        switch (msg->rpc_id) {
            case 25: {
                uint32_t version;
                uint8_t mod;
                char name[64] = {0};
                uint32_t challenge;
                if (!r_u32(&r, &version)) return false;
                if (!r_u8(&r, &mod)) return false;
                if (!r_u8_len_str(&r, name, sizeof(name))) return false;
                if (!r_u32(&r, &challenge)) return false;
                snprintf(out, out_size,
                         "name=\"%s\" version=%u mod=%u challenge=0x%08X",
                         name, version, mod, challenge);
                return true;
            }
            case 100: {
                uint16_t dlg;
                uint8_t response, listitem;
                char text[256] = {0};
                if (!r_u16(&r, &dlg)) return false;
                if (!r_u8(&r, &response)) return false;
                if (!r_u8(&r, &listitem)) return false;
                r_u8_len_str(&r, text, sizeof(text));
                snprintf(out, out_size,
                         "dialog=%u response=%u item=%u text=\"%s\"",
                         dlg, response, listitem, text);
                return true;
            }
            case 118: {
                char text[256] = {0};
                if (!r_u8_len_str(&r, text, sizeof(text))) return false;
                snprintf(out, out_size, "text=\"%s\"", text);
                return true;
            }
            case 117: {
                char cmd[256] = {0};
                if (!r_u32_len_str(&r, cmd, sizeof(cmd))) return false;
                snprintf(out, out_size, "cmd=\"%s\"", cmd);
                return true;
            }
            case 128: {
                uint16_t classid;
                if (!r_u16(&r, &classid)) return false;
                snprintf(out, out_size, "class=%u", classid);
                return true;
            }
            case 53: {
                uint16_t vehicle;
                uint8_t passenger;
                if (!r_u16(&r, &vehicle)) return false;
                if (!r_u8(&r, &passenger)) return false;
                snprintf(out, out_size, "vehicle=%u passenger=%u",
                         vehicle, passenger);
                return true;
            }
            case 170: {
                uint8_t give;
                uint16_t player;
                float amount;
                uint32_t weapon;
                uint32_t bodypart;
                if (!r_u8(&r, &give)) return false;
                if (!r_u16(&r, &player)) return false;
                if (!r_f32(&r, &amount)) return false;
                if (!r_u32(&r, &weapon)) return false;
                if (!r_u32(&r, &bodypart)) return false;
                snprintf(out, out_size,
                         "%s player=%u amount=%.1f weapon=%u part=%u",
                         give ? "give" : "take", player, amount, weapon, bodypart);
                return true;
            }
        }
    } else {
        switch (msg->rpc_id) {
            case 11: {
                uint16_t player;
                char name[64] = {0};
                uint8_t success;
                if (!r_u16(&r, &player)) return false;
                if (!r_u8_len_str(&r, name, sizeof(name))) return false;
                if (!r_u8(&r, &success)) return false;
                snprintf(out, out_size, "player=%u name=\"%s\" ok=%u",
                         player, name, success);
                return true;
            }
            case 12: {
                float x, y, z;
                if (!r_f32(&r, &x)) return false;
                if (!r_f32(&r, &y)) return false;
                if (!r_f32(&r, &z)) return false;
                snprintf(out, out_size, "pos=(%.2f, %.2f, %.2f)", x, y, z);
                return true;
            }
            case 14: {
                float hp;
                if (!r_f32(&r, &hp)) return false;
                snprintf(out, out_size, "health=%.1f", hp);
                return true;
            }
            case 24: {
                int32_t money;
                if (!r_i32(&r, &money)) return false;
                snprintf(out, out_size, "money=%+d", money);
                return true;
            }
            case 32: {
                float angle;
                if (!r_f32(&r, &angle)) return false;
                snprintf(out, out_size, "angle=%.1f", angle);
                return true;
            }
            case 35: {
                uint32_t weapon, ammo;
                if (!r_u32(&r, &weapon)) return false;
                if (!r_u32(&r, &ammo)) return false;
                snprintf(out, out_size, "weapon=%u ammo=%u", weapon, ammo);
                return true;
            }
            case 44: {
                uint8_t h, m;
                if (!r_u8(&r, &h)) return false;
                if (!r_u8(&r, &m)) return false;
                snprintf(out, out_size, "time=%02u:%02u", h, m);
                return true;
            }
            case 50: {
                float armour;
                if (!r_f32(&r, &armour)) return false;
                snprintf(out, out_size, "armour=%.1f", armour);
                return true;
            }
            case 60: {
                uint16_t vehicle;
                uint8_t seat;
                if (!r_u16(&r, &vehicle)) return false;
                if (!r_u8(&r, &seat)) return false;
                snprintf(out, out_size, "vehicle=%u seat=%u", vehicle, seat);
                return true;
            }
            case 62: {
                uint32_t player, skin;
                if (!r_u32(&r, &player)) return false;
                if (!r_u32(&r, &skin)) return false;
                snprintf(out, out_size, "player=%u skin=%u", player, skin);
                return true;
            }
            case 63: {
                uint8_t interior;
                if (!r_u8(&r, &interior)) return false;
                snprintf(out, out_size, "interior=%u", interior);
                return true;
            }
            case 86: {
                uint16_t dlg;
                uint8_t style;
                char caption[128] = {0};
                char btn1[64] = {0};
                char btn2[64] = {0};
                char info[256] = {0};
                if (!r_u16(&r, &dlg)) return false;
                if (!r_u8(&r, &style)) return false;
                if (!r_u8_len_str(&r, caption, sizeof(caption))) return false;
                if (!r_u8_len_str(&r, btn1, sizeof(btn1))) return false;
                if (!r_u8_len_str(&r, btn2, sizeof(btn2))) return false;
                r_u32_len_str(&r, info, sizeof(info));
                snprintf(out, out_size,
                         "dialog=%u style=%u caption=\"%s\" btn1=\"%s\" btn2=\"%s\"",
                         dlg, style, caption, btn1, btn2);
                return true;
            }
            case 104: {
                uint8_t weather;
                if (!r_u8(&r, &weather)) return false;
                snprintf(out, out_size, "weather=%u", weather);
                return true;
            }
            case 145: {
                uint32_t style, time;
                char text[256] = {0};
                if (!r_u32(&r, &style)) return false;
                if (!r_u32(&r, &time)) return false;
                if (!r_u32_len_str(&r, text, sizeof(text))) return false;
                snprintf(out, out_size, "style=%u time=%u text=\"%s\"",
                         style, time, text);
                return true;
            }
            case 153: {
                float gravity;
                if (!r_f32(&r, &gravity)) return false;
                snprintf(out, out_size, "gravity=%.4f", gravity);
                return true;
            }
            case 83: {
                uint16_t player;
                uint32_t colour;
                float draw_dist;
                uint32_t expire;
                char text[256] = {0};
                if (!r_u16(&r, &player)) return false;
                if (!r_u32(&r, &colour)) return false;
                if (!r_f32(&r, &draw_dist)) return false;
                if (!r_u32(&r, &expire)) return false;
                r_u8_len_str(&r, text, sizeof(text));
                snprintf(out, out_size,
                         "player=%u colour=0x%08X dist=%.1f expire=%u text=\"%s\"",
                         player, colour, draw_dist, expire, text);
                return true;
            }
        }
    }

    return false;
}

bool decode_rpc_fields_json(const IdentifiedMessage *msg, PacketDirection dir,
                            char *out, size_t out_size) {
    if (msg->type != MSG_RPC) return false;
    if (msg->payload_len == 0) return false;

    Reader r = { msg->payload, msg->payload_len, 0 };
    out[0] = '\0';
    char esc[512];

    if (dir == DIR_CLIENT_TO_SERVER) {
        switch (msg->rpc_id) {
            case 25: {
                uint32_t version;
                uint8_t mod;
                char name[64] = {0};
                uint32_t challenge;
                if (!r_u32(&r, &version)) return false;
                if (!r_u8(&r, &mod)) return false;
                if (!r_u8_len_str(&r, name, sizeof(name))) return false;
                if (!r_u32(&r, &challenge)) return false;
                esc_json(name, esc, sizeof(esc));
                snprintf(out, out_size,
                         "\"name\":\"%s\",\"version\":%u,\"mod\":%u,\"challenge\":%u",
                         esc, version, mod, challenge);
                return true;
            }
            case 100: {
                uint16_t dlg;
                uint8_t response, listitem;
                char text[256] = {0};
                if (!r_u16(&r, &dlg)) return false;
                if (!r_u8(&r, &response)) return false;
                if (!r_u8(&r, &listitem)) return false;
                r_u8_len_str(&r, text, sizeof(text));
                esc_json(text, esc, sizeof(esc));
                snprintf(out, out_size,
                         "\"dialog\":%u,\"response\":%u,\"item\":%u,\"text\":\"%s\"",
                         dlg, response, listitem, esc);
                return true;
            }
            case 118: {
                char text[256] = {0};
                if (!r_u8_len_str(&r, text, sizeof(text))) return false;
                esc_json(text, esc, sizeof(esc));
                snprintf(out, out_size, "\"text\":\"%s\"", esc);
                return true;
            }
            case 117: {
                char cmd[256] = {0};
                if (!r_u32_len_str(&r, cmd, sizeof(cmd))) return false;
                esc_json(cmd, esc, sizeof(esc));
                snprintf(out, out_size, "\"cmd\":\"%s\"", esc);
                return true;
            }
            case 128: {
                uint16_t classid;
                if (!r_u16(&r, &classid)) return false;
                snprintf(out, out_size, "\"class\":%u", classid);
                return true;
            }
        }
    } else {
        switch (msg->rpc_id) {
            case 11: {
                uint16_t player;
                char name[64] = {0};
                uint8_t success;
                if (!r_u16(&r, &player)) return false;
                if (!r_u8_len_str(&r, name, sizeof(name))) return false;
                if (!r_u8(&r, &success)) return false;
                esc_json(name, esc, sizeof(esc));
                snprintf(out, out_size,
                         "\"player\":%u,\"name\":\"%s\",\"ok\":%u",
                         player, esc, success);
                return true;
            }
            case 12: {
                float x, y, z;
                if (!r_f32(&r, &x)) return false;
                if (!r_f32(&r, &y)) return false;
                if (!r_f32(&r, &z)) return false;
                snprintf(out, out_size, "\"x\":%.2f,\"y\":%.2f,\"z\":%.2f", x, y, z);
                return true;
            }
            case 14: {
                float hp;
                if (!r_f32(&r, &hp)) return false;
                snprintf(out, out_size, "\"health\":%.1f", hp);
                return true;
            }
            case 24: {
                int32_t money;
                if (!r_i32(&r, &money)) return false;
                snprintf(out, out_size, "\"money\":%d", money);
                return true;
            }
            case 50: {
                float armour;
                if (!r_f32(&r, &armour)) return false;
                snprintf(out, out_size, "\"armour\":%.1f", armour);
                return true;
            }
            case 86: {
                uint16_t dlg;
                uint8_t style;
                char caption[128] = {0};
                char btn1[64] = {0};
                char btn2[64] = {0};
                if (!r_u16(&r, &dlg)) return false;
                if (!r_u8(&r, &style)) return false;
                if (!r_u8_len_str(&r, caption, sizeof(caption))) return false;
                if (!r_u8_len_str(&r, btn1, sizeof(btn1))) return false;
                if (!r_u8_len_str(&r, btn2, sizeof(btn2))) return false;
                char ec[256], eb1[128], eb2[128];
                esc_json(caption, ec, sizeof(ec));
                esc_json(btn1, eb1, sizeof(eb1));
                esc_json(btn2, eb2, sizeof(eb2));
                snprintf(out, out_size,
                         "\"dialog\":%u,\"style\":%u,\"caption\":\"%s\",\"btn1\":\"%s\",\"btn2\":\"%s\"",
                         dlg, style, ec, eb1, eb2);
                return true;
            }
        }
    }

    return false;
}
