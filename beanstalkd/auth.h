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

#define CONSTSTRLEN(m) (sizeof(m) - 1)

#define CMD_AUTH1_LEN CONSTSTRLEN(CMD_AUTH1)
#define CMD_AUTH2_LEN CONSTSTRLEN(CMD_AUTH2)

#define MSG_AUTH_ENABLED "AUTH_REQUIRED\r\n"

/* exposed methods */
void SET_AUTH();
int IS_AUTH();
int loadAuthStorage(char*);
void authConn(conn, int);
#endif /* AUTH_H_ */
