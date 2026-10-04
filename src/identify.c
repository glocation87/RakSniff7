#include "identify.h"
#include "bitstream.h"

typedef struct {
    uint32_t id;
    PacketDirection dir;
    const char *name;
} RpcEntry;

// RPC name table derived from open.mp Shared/NetCode/ NetworkPacketBase<> structs
static const RpcEntry rpc_table[] = {
    // Client → Server RPCs
    { 25,  DIR_CLIENT_TO_SERVER, "PlayerConnect" },
    { 26,  DIR_CLIENT_TO_SERVER, "NPCConnect" },
    { 52,  DIR_CLIENT_TO_SERVER, "ClientJoin" },
    { 53,  DIR_CLIENT_TO_SERVER, "PlayerEnterVehicle" },
    { 54,  DIR_CLIENT_TO_SERVER, "PlayerExitVehicle" },
    { 55,  DIR_CLIENT_TO_SERVER, "PlayerSpawn" },
    { 56,  DIR_CLIENT_TO_SERVER, "PlayerDeath" },
    { 100, DIR_CLIENT_TO_SERVER, "DialogResponse" },
    { 101, DIR_CLIENT_TO_SERVER, "PlayerClickPlayer" },
    { 102, DIR_CLIENT_TO_SERVER, "PlayerClickTextdraw" },
    { 103, DIR_CLIENT_TO_SERVER, "PlayerClickMap" },
    { 106, DIR_CLIENT_TO_SERVER, "SetInteriorId" },
    { 115, DIR_CLIENT_TO_SERVER, "MapMarkerSync" },
    { 116, DIR_CLIENT_TO_SERVER, "PlayerUpdate" },
    { 117, DIR_CLIENT_TO_SERVER, "PlayerCommandText" },
    { 118, DIR_CLIENT_TO_SERVER, "PlayerChatMessage" },
    { 119, DIR_CLIENT_TO_SERVER, "SCMEvent" },
    { 128, DIR_CLIENT_TO_SERVER, "RequestClass" },
    { 129, DIR_CLIENT_TO_SERVER, "RequestSpawn" },
    { 132, DIR_CLIENT_TO_SERVER, "PickedUpPickup" },
    { 133, DIR_CLIENT_TO_SERVER, "MenuSelect" },
    { 134, DIR_CLIENT_TO_SERVER, "VehiclePaintjob" },
    { 136, DIR_CLIENT_TO_SERVER, "MenuExit" },
    { 154, DIR_CLIENT_TO_SERVER, "EditAttachedObject" },
    { 155, DIR_CLIENT_TO_SERVER, "EditObject" },
    { 156, DIR_CLIENT_TO_SERVER, "SetPlayerObjectMaterial" },
    { 170, DIR_CLIENT_TO_SERVER, "GiveTakeDamage" },

    // Server → Client RPCs
    { 11,  DIR_SERVER_TO_CLIENT, "SetPlayerName" },
    { 12,  DIR_SERVER_TO_CLIENT, "SetPlayerPos" },
    { 13,  DIR_SERVER_TO_CLIENT, "SetPlayerPosFindZ" },
    { 14,  DIR_SERVER_TO_CLIENT, "SetPlayerHealth" },
    { 16,  DIR_SERVER_TO_CLIENT, "TogglePlayerControllable" },
    { 17,  DIR_SERVER_TO_CLIENT, "PlaySound" },
    { 22,  DIR_SERVER_TO_CLIENT, "SetPlayerWorldBounds" },
    { 24,  DIR_SERVER_TO_CLIENT, "GivePlayerMoney" },
    { 32,  DIR_SERVER_TO_CLIENT, "SetPlayerFacingAngle" },
    { 33,  DIR_SERVER_TO_CLIENT, "ResetPlayerMoney" },
    { 34,  DIR_SERVER_TO_CLIENT, "ResetPlayerWeapons" },
    { 35,  DIR_SERVER_TO_CLIENT, "GivePlayerWeapon" },
    { 36,  DIR_SERVER_TO_CLIENT, "SetVehicleParamsEx" },
    { 41,  DIR_SERVER_TO_CLIENT, "CancelEdit" },
    { 44,  DIR_SERVER_TO_CLIENT, "SetPlayerTime" },
    { 45,  DIR_SERVER_TO_CLIENT, "ToggleClock" },
    { 47,  DIR_SERVER_TO_CLIENT, "WorldPlayerAdd" },
    { 50,  DIR_SERVER_TO_CLIENT, "SetPlayerArmour" },
    { 57,  DIR_SERVER_TO_CLIENT, "SetPlayerTeam" },
    { 60,  DIR_SERVER_TO_CLIENT, "PutPlayerInVehicle" },
    { 61,  DIR_SERVER_TO_CLIENT, "RemoveBuilding" },
    { 62,  DIR_SERVER_TO_CLIENT, "SetPlayerSkin" },
    { 63,  DIR_SERVER_TO_CLIENT, "SetPlayerInterior" },
    { 65,  DIR_SERVER_TO_CLIENT, "SetCameraBehindPlayer" },
    { 66,  DIR_SERVER_TO_CLIENT, "WorldPlayerRemove" },
    { 67,  DIR_SERVER_TO_CLIENT, "WorldVehicleAdd" },
    { 68,  DIR_SERVER_TO_CLIENT, "WorldVehicleRemove" },
    { 69,  DIR_SERVER_TO_CLIENT, "CreateObject" },
    { 70,  DIR_SERVER_TO_CLIENT, "SetObjectPos" },
    { 71,  DIR_SERVER_TO_CLIENT, "SetObjectRot" },
    { 72,  DIR_SERVER_TO_CLIENT, "DestroyObject" },
    { 75,  DIR_SERVER_TO_CLIENT, "PlayerDeath_Notify" },
    { 80,  DIR_SERVER_TO_CLIENT, "SetMapIcon" },
    { 81,  DIR_SERVER_TO_CLIENT, "RemoveVehicleComponent" },
    { 83,  DIR_SERVER_TO_CLIENT, "PlayerChatBubble" },
    { 85,  DIR_SERVER_TO_CLIENT, "UpdateGlobalTimer" },
    { 86,  DIR_SERVER_TO_CLIENT, "ShowDialog" },
    { 87,  DIR_SERVER_TO_CLIENT, "DestroyPickup" },
    { 89,  DIR_SERVER_TO_CLIENT, "LinkVehicleToInterior" },
    { 90,  DIR_SERVER_TO_CLIENT, "SetPlayerObjectMaterial_S" },
    { 91,  DIR_SERVER_TO_CLIENT, "SetVehicleHealth" },
    { 93,  DIR_SERVER_TO_CLIENT, "PlayerInit" },
    { 94,  DIR_SERVER_TO_CLIENT, "GameModeRestart" },
    { 95,  DIR_SERVER_TO_CLIENT, "PlayAudioStream" },
    { 97,  DIR_SERVER_TO_CLIENT, "SetPlayerDrunkLevel" },
    { 104, DIR_SERVER_TO_CLIENT, "SetPlayerWeather" },
    { 105, DIR_SERVER_TO_CLIENT, "SetPlayerSkin_S2C" },
    { 107, DIR_SERVER_TO_CLIENT, "SetPlayerSpecialAction" },
    { 108, DIR_SERVER_TO_CLIENT, "ShowPlayerNameTag" },
    { 112, DIR_SERVER_TO_CLIENT, "AttachObjectToPlayer" },
    { 113, DIR_SERVER_TO_CLIENT, "SetVehicleNumberPlate" },
    { 114, DIR_SERVER_TO_CLIENT, "TogglePlayerSpectating" },
    { 120, DIR_SERVER_TO_CLIENT, "PlayerSpectatePlayer" },
    { 121, DIR_SERVER_TO_CLIENT, "PlayerSpectateVehicle" },
    { 126, DIR_SERVER_TO_CLIENT, "ApplyAnimation" },
    { 127, DIR_SERVER_TO_CLIENT, "ClearAnimations" },
    { 128, DIR_SERVER_TO_CLIENT, "RequestClassResponse" },
    { 129, DIR_SERVER_TO_CLIENT, "RequestSpawnResponse" },
    { 130, DIR_SERVER_TO_CLIENT, "CreateExplosion" },
    { 131, DIR_SERVER_TO_CLIENT, "CreatePickup" },
    { 135, DIR_SERVER_TO_CLIENT, "SetPlayerVelocity" },
    { 137, DIR_SERVER_TO_CLIENT, "ShowMenu" },
    { 138, DIR_SERVER_TO_CLIENT, "HideMenu" },
    { 139, DIR_SERVER_TO_CLIENT, "CreateMenu" },
    { 140, DIR_SERVER_TO_CLIENT, "DestroyMenu" },
    { 145, DIR_SERVER_TO_CLIENT, "ShowGameText" },
    { 148, DIR_SERVER_TO_CLIENT, "ForceClassSelection" },
    { 150, DIR_SERVER_TO_CLIENT, "FlashGangZone" },
    { 151, DIR_SERVER_TO_CLIENT, "StopFlashGangZone" },
    { 152, DIR_SERVER_TO_CLIENT, "RemoveMapIcon" },
    { 153, DIR_SERVER_TO_CLIENT, "SetGravity" },
    { 155, DIR_SERVER_TO_CLIENT, "SetVehicleVelocity" },
    { 156, DIR_SERVER_TO_CLIENT, "CreateGangZone" },
    { 157, DIR_SERVER_TO_CLIENT, "PlayCrimeReport" },
    { 158, DIR_SERVER_TO_CLIENT, "SetPlayerAttachedObject" },
    { 159, DIR_SERVER_TO_CLIENT, "ShowGangZone" },
    { 160, DIR_SERVER_TO_CLIENT, "HideGangZone" },
    { 161, DIR_SERVER_TO_CLIENT, "DestroyGangZone" },
    { 162, DIR_SERVER_TO_CLIENT, "TextDrawSetString" },
    { 163, DIR_SERVER_TO_CLIENT, "SetPlayerChatColour" },
    { 164, DIR_SERVER_TO_CLIENT, "CreateTextDraw" },
    { 165, DIR_SERVER_TO_CLIENT, "DestroyTextDraw" },
    { 166, DIR_SERVER_TO_CLIENT, "ShowTextDraw" },
    { 167, DIR_SERVER_TO_CLIENT, "HideTextDraw" },
    { 171, DIR_SERVER_TO_CLIENT, "ClientCheck" },
    { 172, DIR_SERVER_TO_CLIENT, "DestroyPlayerObject" },
    { 174, DIR_SERVER_TO_CLIENT, "SetPlayerObjectPos" },
    { 175, DIR_SERVER_TO_CLIENT, "SetPlayerObjectRot" },
    { 176, DIR_SERVER_TO_CLIENT, "CreatePlayerObject" },
    { 0, 0, NULL }
};

const char *rpc_name(uint32_t rpc_id, PacketDirection dir) {
    for (const RpcEntry *e = rpc_table; e->name; e++) {
        if (e->id == rpc_id && e->dir == dir) return e->name;
    }
    return NULL;
}

const char *packet_id_name(uint8_t id) {
    switch (id) {
        case ID_INTERNAL_PING:         return "InternalPing";
        case ID_PING_OPEN_CONNECTIONS: return "PingOpenConnections";
        case ID_CONNECTED_PONG:        return "ConnectedPong";
        case ID_CONNECTION_REQUEST:    return "ConnectionRequest";
        case ID_AUTH_KEY:              return "AuthKey";
        case ID_RPC:                   return "RPC";
        case ID_TIMESTAMP:             return "Timestamp";
        case ID_USER_PACKET_ENUM:      return "UserPacketEnum";
        case ID_PLAYER_SYNC:           return "PlayerSync";
        case ID_VEHICLE_SYNC:          return "VehicleSync";
        case ID_PASSENGER_SYNC:        return "PassengerSync";
        case ID_AIM_SYNC:              return "AimSync";
        case ID_UNOCCUPIED_SYNC:       return "UnoccupiedSync";
        case ID_TRAILER_SYNC:          return "TrailerSync";
        case ID_BULLET_SYNC:           return "BulletSync";
        case ID_SPECTATING_SYNC:       return "SpectatingSync";
        default:                       return NULL;
    }
}

bool identify_message(const uint8_t *data, size_t len, PacketDirection dir,
                      IdentifiedMessage *out) {
    if (len == 0) return false;

    memset(out, 0, sizeof(*out));
    out->packet_id = data[0];

    if (data[0] == ID_RPC) {
        // RPC header: optional timestamp, then RPC ID, then bit length, then payload
        BitStream bs;
        bs_init(&bs, data + 1, len - 1);

        // Check for timestamp prefix
        // In RAKNET_LEGACY builds, the RPC format is:
        // [ID_TIMESTAMP (1 byte) + timestamp (4 bytes)] + ID_RPC (1 byte) already consumed
        // Then: rpc_id (uint8), bit_length (uint32_compressed), payload

        uint8_t rpc_id;
        if (!bs_read_u8(&bs, &rpc_id)) return false;

        uint32_t bit_len;
        if (!bs_read_compressed_u32(&bs, &bit_len)) return false;

        bs_align(&bs);

        out->type = MSG_RPC;
        out->rpc_id = rpc_id;
        out->payload = data + 1 + (bs.bit_pos / 8);
        out->payload_len = len - 1 - (bs.bit_pos / 8);
        out->payload_bit_len = bit_len;

        const char *name = rpc_name(rpc_id, dir);
        out->name = name ? name : "UnknownRPC";
        return true;
    }

    // Check sync packets
    if (data[0] >= ID_PLAYER_SYNC && data[0] <= ID_SPECTATING_SYNC) {
        out->type = MSG_PACKET;
        out->name = packet_id_name(data[0]);
        out->payload = data + 1;
        out->payload_len = len - 1;
        return true;
    }

    // Internal RakNet message
    const char *name = packet_id_name(data[0]);
    if (name) {
        out->type = MSG_INTERNAL;
        out->name = name;
        out->payload = data + 1;
        out->payload_len = len - 1;
        return true;
    }

    out->type = MSG_UNKNOWN;
    out->name = "Unknown";
    out->payload = data;
    out->payload_len = len;
    return true;
}
