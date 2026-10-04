#ifndef OMP_DECODE_H
#define OMP_DECODE_H

#include "common.h"
#include "identify.h"

bool decode_rpc_fields(const IdentifiedMessage *msg, PacketDirection dir,
                       char *out, size_t out_size);

bool decode_rpc_fields_json(const IdentifiedMessage *msg, PacketDirection dir,
                            char *out, size_t out_size);

#endif
