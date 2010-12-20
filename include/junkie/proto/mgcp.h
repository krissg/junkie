// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef MGCP_H_100609
#define MGCP_H_100609
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <junkie/proto/proto.h>

/** @file
 * @brief MGCP informations
 */

extern struct proto *proto_mgcp;

typedef uint_least32_t mgcp_txid;
#define PRI_MGCP_TXID PRIuLEAST32

/// MGCP message
struct mgcp_proto_info {
    struct proto_info info;
    bool response;
    union {
        struct mgcp_resp {
            unsigned code;
            mgcp_txid txid;
        } resp;
        struct mgcp_query {
            enum mgcp_command {
                MGCP_EndpointConfiguration, MGCP_CreateConnection,
                MGCP_ModifyConnection,      MGCP_DeleteConnection,
                MGCP_NotificationRequest,   MGCP_Notify,
                MGCP_AuditEndpoint,         MGCP_AuditConnection,
                MGCP_RestartInProgress,
            } command;
            mgcp_txid txid;
#           define MGCP_ENDPOINT_LEN 128
            char endpoint[MGCP_ENDPOINT_LEN+1];
        } query;
    } u;
    // Parameters
#   define MGCP_HD 0x01U    // hang down
#   define MGCP_HU 0x02U    // hang up
#   define MGCP_FHD 0x04U   // forced hang down
#   define MGCP_FHU 0x08U   // forced hang up
#   define MGCP_BZ 0x10U    // buzy
#   define MGCP_RG 0x20U    // ring
    unsigned observed, signaled;
    char dialed[32+1];
#   define MGCP_CNXID_LEN 32
    char cnx_id[MGCP_CNXID_LEN+1];
#   define MGCP_CALLID_LEN 32
    char call_id[MGCP_CALLID_LEN+1];
};

void mgcp_init(void);
void mgcp_fini(void);

#endif
