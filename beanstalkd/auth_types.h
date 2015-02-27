/*
 * auth_data.h
 *
 *  Created on: Feb 25, 2015
 *      Author: mihai.haras
 */

#ifndef AUTH_TYPES_H_
#define AUTH_TYPES_H_

#define NONCE_SIZE 16

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

    /* The +1 for the null byte. Nonce handled as a hex-string. */
    char nonce[NONCE_SIZE + 1];
} Auth;

#endif /* AUTH_TYPES_H_ */
