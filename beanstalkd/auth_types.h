/*
 * auth_data.h
 *
 *  Created on: Feb 25, 2015
 *      Author: mihai.haras
 */

#ifndef AUTH_TYPES_H_
#define AUTH_TYPES_H_

/* auth data types */
typedef enum ACCES_LEVEL
{
    ALL,
    PRODUCER,
    CONSUMER,
    MONITOR,
    DENIED
} ACCES_LEVEL;

typedef struct AUTH_RECORD_LIST AUTH_RECORD_LIST;

struct AUTH_RECORD_LIST
{
char *user;
ACCES_LEVEL level;
char *hash;
AUTH_RECORD_LIST *next;
};

typedef struct Auth
{
int auth_ok;
AUTH_RECORD_LIST *record;
uint8_t *nonce;
} Auth;

#endif /* AUTH_TYPES_H_ */
