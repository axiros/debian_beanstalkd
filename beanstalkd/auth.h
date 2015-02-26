/*
 * auth.h
 *
 *  Created on: Feb 25, 2015
 *      Author: mihai.haras
 */

#ifndef AUTH_H_
#define AUTH_H_
#include <stdint.h>
#include "auth_types.h"
#include "conn.h"

/* consts */
#define GROUP_ADMIN "admin"
#define GROUP_PRODUCER "producer"
#define GROUP_CONSUMER "consumer"
#define GROUP_MONITOR "monitor"

#define CMD_AUTH1 "auth1 "
#define CMD_AUTH2 "auth2 "
#define OP_AUTH1 TOTAL_OPS + 1
#define OP_AUTH2 TOTAL_OPS + 2
#define CMD_AUTH1_LEN CONSTSTRLEN(CMD_AUTH1)
#define CMD_AUTH2_LEN CONSTSTRLEN(CMD_AUTH2)

#define MSG_AUTH_ENABLED "AUTH_REQUIRED\r\n"

static const uint8_t AES_KEY[16] = {
    0x41,
    0x73,
    0x68,
    0x61,
    0x72,
    0x4C,
    0x6F,
    0x68,
    0x6D,
    0x61,
    0x72,
    0x47,
    0x6D,
    0x61,
    0x69,
    0x6C };

/* exposed methods */
#define CONSTSTRLEN(m) (sizeof(m) - 1)
void*
zalloc(int n);
#define new(T) zalloc(sizeof(T))
void
SET_AUTH();
int
IS_AUTH();
int
loadAuthStorage(char*);
//int
//buildNonce(Auth*, char*);
//void
//checkAuth(Auth*, char*);
void
authConn(conn, int);
/* temp */
//void
//bytes2String(char**, uint8_t*, int);
//void
//encodeAES(char**, uint8_t**, char*, int);
//void
//decodeAES(char**, uint8_t*, char*, int);
//void
//doMd5(char**, char*);
#endif /* AUTH_H_ */
