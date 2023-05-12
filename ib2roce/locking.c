/*
 * RDMA Infiniband to ROCE Bridge or Gateway
 *
 * (C) 2021-2022 Christoph Lameter <cl@linux.com>
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * $Author: Christoph Lameter [cl@linux.com]$
 *
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <fcntl.h>
#include <ctype.h>
#include <pthread.h>
#include <numa.h>
#include <stdatomic.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <rdma/rdma_cma.h>
#include <infiniband/ib.h>
#include <infiniband/verbs.h>
#include <poll.h>
#include <sys/mman.h>
#include "errno.h"
#include "logging.h"
#include "locking.h"

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;		/* Generic serialization mutex */

/* Is the lock taken */
static bool locked = false;

/* Are we running concurrent threads ? */
bool multithreaded = false;

void lock(void)
{
	if (multithreaded) {
 		if (pthread_mutex_lock(&mutex))
 			logg(LOG_CRIT, "Mutex lock failed: %s\n", errname());
	}

	if (locked)
	       	panic("lock() called when already locked\n");

	locked = true;
}

void unlock(void)
{
	if (!locked)
		panic("unlock() called when not locked\n");

	locked = false;
	if (multithreaded) {
 		if (pthread_mutex_unlock(&mutex))
 			panic("Mutex unlock failed: %s\n", errname());

	}
}

#if 0
bool trylock(void)
{
	if (multithreaded) {
 		if (pthread_mutex_trylock(&mutex)) {
 			if (errno != EBUSY)
 				logg(LOG_ERR, "Mutex trylock failed: %s\n", errname());
 			return false;
 		}
	} else {
		if (locked)
			abort();
	}

	locked = true;

out:
 	return true;
}
#endif

