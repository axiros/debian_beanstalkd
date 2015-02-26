/*
 * auth_data.h
 *
 *  Created on: Feb 25, 2015
 *      Author: mihai.haras
 */

#ifndef AUTH_TYPES_H_
#define AUTH_TYPES_H_

/* auth data types */
typedef struct AUTH_RECORD_LIST AUTH_RECORD_LIST;

struct AUTH_RECORD_LIST {
    char *user;
    char *hash;
    AUTH_RECORD_LIST *next;
};

typedef struct {
    int auth_ok;
    AUTH_RECORD_LIST *record;
    char *nonce;
} Auth;

#endif /* AUTH_TYPES_H_ */
