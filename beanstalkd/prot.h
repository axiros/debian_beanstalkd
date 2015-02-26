/* prot.h - protocol implementation header */

/* Copyright (C) 2007 Keith Rarick and Philotic Inc.

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef prot_h
#define prot_h

#include "conn.h"

#define URGENT_THRESHOLD 1024
#define JOB_DATA_SIZE_LIMIT_DEFAULT ((1 << 16) - 1)

#define STATE_WANTCOMMAND 0
#define STATE_WANTDATA 1
#define STATE_SENDJOB 2
#define STATE_SENDWORD 3
#define STATE_WAIT 4
#define STATE_BITBUCKET 5

#define MSG_FOUND "FOUND"
#define MSG_NOTFOUND "NOT_FOUND\r\n"
#define MSG_RESERVED "RESERVED"
#define MSG_DEADLINE_SOON "DEADLINE_SOON\r\n"
#define MSG_TIMED_OUT "TIMED_OUT\r\n"
#define MSG_DELETED "DELETED\r\n"
#define MSG_RELEASED "RELEASED\r\n"
#define MSG_BURIED "BURIED\r\n"
#define MSG_TOUCHED "TOUCHED\r\n"
#define MSG_BURIED_FMT "BURIED %llu\r\n"
#define MSG_INSERTED_FMT "INSERTED %llu\r\n"
#define MSG_NOT_IGNORED "NOT_IGNORED\r\n"

#define MSG_OUT_OF_MEMORY "OUT_OF_MEMORY\r\n"
#define MSG_INTERNAL_ERROR "INTERNAL_ERROR\r\n"
#define MSG_DRAINING "DRAINING\r\n"
#define MSG_BAD_FORMAT "BAD_FORMAT\r\n"
#define MSG_UNKNOWN_COMMAND "UNKNOWN_COMMAND\r\n"
#define MSG_EXPECTED_CRLF "EXPECTED_CRLF\r\n"
#define MSG_JOB_TOO_BIG "JOB_TOO_BIG\r\n"

#define OP_UNKNOWN 0
#define OP_PUT 1
#define OP_PEEKJOB 2
#define OP_RESERVE 3
#define OP_DELETE 4
#define OP_RELEASE 5
#define OP_BURY 6
#define OP_KICK 7
#define OP_STATS 8
#define OP_JOBSTATS 9
#define OP_PEEK_BURIED 10
#define OP_USE 11
#define OP_WATCH 12
#define OP_IGNORE 13
#define OP_LIST_TUBES 14
#define OP_LIST_TUBE_USED 15
#define OP_LIST_TUBES_WATCHED 16
#define OP_STATS_TUBE 17
#define OP_PEEK_READY 18
#define OP_PEEK_DELAYED 19
#define OP_RESERVE_TIMEOUT 20
#define OP_TOUCH 21
#define OP_QUIT 22
#define OP_PAUSE_TUBE 23
#define TOTAL_OPS 24
extern size_t job_data_size_limit;

void prot_init();

conn remove_waiting_conn(conn c);

void enqueue_reserved_jobs(conn c);

void enter_drain_mode(int sig);
void h_accept(const int fd, const short which, struct event *ev);
void prot_remove_tube(tube t);
void prot_replay_binlog(job binlog_jobs);

void reply(conn, const char*, int, int);
void reply_line(conn, int, const char*, ...);
#define reply_msg(c,m) reply((c),(m),CONSTSTRLEN(m),STATE_SENDWORD)
#define reply_serr(c,e) (twarnx("server error: %s",(e)),\
                         reply_msg((c),(e)))

#endif /*prot_h*/
