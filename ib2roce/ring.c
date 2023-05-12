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
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "ring.h"

void ring_init(struct ring *r)
{
	r->head = 0;
	r->tail = 0;
	r->full = false;
	r->size = RING_SIZE;
}

static bool ring_empty(struct ring *r)
{
	return !r->full && r->head == r->tail;
}

bool ring_put(struct ring *r, const char *msg, unsigned len)
{
	unsigned tail;

	if (len > 250 || r->full)
		return false;

	tail = r->tail + 1 + len;

	/* trail < head then write in the middle up to head */
	if (r->tail < r->head && tail < r->head)
       		goto copy_object;

	/* head before trail and objects fits in before end of buffer ? */
	if (r->head <= r->tail && tail <= r->size)
		goto copy_object;

	/* Object straddles the end of the buffer */
	if (tail > r->size && tail - r->size <= r->head) {

		r->buf[r->tail] = len;
		memcpy(r->buf + r->tail + 1, msg, r->size - r->tail);
		memcpy(r->buf, msg + r->size - r->tail, tail - r->size);

		tail -= r->size;
		goto out;	
	}
	
	return false;

copy_object:
	r->buf[r->tail] = len;
	memcpy(r->buf + r->tail + 1, msg, len);

out:
	if (tail == r->size)
		tail = 0;

	if (tail == r->head)
		r->full = true;

	r->tail = tail;
	return true;
}

int ring_get(struct ring *r, char *msg, unsigned max_len)
{
	uint8_t len;
	unsigned head;

	if (!r->full && r->head == r->tail)
		/* Nothing here */
		return 0;

	r->full = false;	/* We take something out so it cannot be full after this */

	len = r->buf[r->head];
	head = r->head + 1 + len;

	if (len < 2 || len > max_len) {
		printf("Ring_get len = %d\n", len);
		abort();
	}

	if (head <= r->tail || (r->tail < r->head && head <= r->size)) {
		memcpy(msg, r->buf + r->head + 1, len);
		goto done;
	}

	if (head > r->size && head - r->size <= r->tail) {
		memcpy(msg, r->buf + r->head + 1, r->size - r->head - 1);
		memcpy(msg + r->size - r->head, r->buf, head - r->size);
		head -= r->size;
		goto done;;
	}

	/* Data integrity issue */
	abort();

done:
	if (head == r->size)
		head = 0;

	r->head = head;
	return len;

}

void ring_test(void)
{
	/* Fill up till the end */
	struct ring r;
	int n = 0;
	int x;
	char inmsg[50];
	const char *msg = "This is a test";
	unsigned len = strlen(msg);
	ring_init(&r);

	printf("Ring test\n");
	printf("---------\n");
	do {
		n++;

	} while (ring_put(&r, msg, len));

	printf("Wrote %d messages via ring_put into ring. Full=%d\n", n, r.full);

	while ((x = ring_get(&r, inmsg, 50))) {
		if (x != len)
			printf("%d %s\n", n, inmsg);
		n--;
	}
	printf("Leftover after ring_get =%d ring_empty=%d\n",n, ring_empty(&r));

	srand(55);
	/* Randomized test */
	n = 0;
	printf("Randomized put/get ....\n");
	for(int i = 0; i < 1000000000; i++) {
		x = rand() % 2;

		if (x == 0) {
			if (ring_put(&r, msg, len))
				n++;
		} else if (x == 1) {
			int y;

			if ((y = ring_get(&r, inmsg, 50))) {
				n--;
				if (y != len && strcmp(inmsg, msg)) {
					printf("ring_get: Expected [%d]\"%s\" got [%d]\"%s\" \n", len, msg, y, inmsg);
					abort();
				}
			}
		}
	}
	printf("N=%d\n", n);
	printf("Ring test End.\n");
}

