#ifndef IB2ROCE_HASH
#define IB2ROCE_HASH

/*
 * unsigned long values in the hash tables are usually used to represent
 * the address of the object hashed. However, if there is a collision then
 * the 3 lower bits are also used to indicate how the collision was resolved.
 * The lower 3 bits are usually not used since objects are aligned to
 * 8 byte boundaries in a 64 bit environment.
 *
 * The lower 3 bits encode the number of collision entries. The rest of the
 * 64 bit value then points to the overflow table where the addresses of the:w
 * objects with the same hash can be found.
 *
 * So we can encode 0-7 in the lower 3 bits
 *
 * They mean:
 * 0	The long can be used as a pointer to the object directly.
 * 1    The number of collisions can be found at the address followed by the collision entries
 * 2..7 Number of collision entries that can be found at the address
 */
#define HASH_COLL_INIT_BITS 4
#define HASH_INIT_BITS 4

#define HASH_FLAG_LOCAL (1 << 1)		/* Local array is being used. No Malloc */
#define HASH_FLAG_REORG_RUNNING (1 << 2)	/* A Reorg of the hash is in progress */
#define HASH_FLAG_REORG_FAIL (1 << 3 )		/* Abort the unsuccessful reorg */
#define HASH_FLAG_CORRUPTED (1 << 4)		/* Unrecoverable Metadata consistency issue */
#define HASH_FLAG_VERBOSE (1 << 5)		/* Show statistics during reorg */

struct hash {
	unsigned short key_offset;
	unsigned short key_length;
	unsigned char hash_bits;		/* Bits of the 32 bit hash to use */
	unsigned char coll_bits;		/* 1 << N size of collision area */
	unsigned char coll_ubits;		/* 2^ubits allocations size in words */
	unsigned char flags;			/* Flags */
	unsigned coll_next;			/* Next free unit in coll area */
	void **table;				/* Colltable follows hash table */
	union {
		void *local[(1 << HASH_INIT_BITS) + (1 << HASH_COLL_INIT_BITS)];
		struct {
			unsigned collisions;
			unsigned hash_free;	/* Unused entries */
			unsigned items;		/* How many items in the table */
			unsigned coll_free;	/* How many unit blocks are still available */
			unsigned coll_max;	/* Maximum Collisions per hash entry */
			unsigned coll_reloc;	/* Relocation of free list */
			unsigned coll[8];	/* Statistics for collision sizes. 0 = larger collisions */
		};
	};
};

struct hash *hash_create(unsigned offset, unsigned length);
void hash_add(struct hash *h, void *object);
void hash_del(struct hash *h, void *object);
void *hash_find(struct hash *h, void *key);

unsigned int hash_check(struct hash *h, bool fast);

/* Read N objects starting at the mths one */
unsigned int hash_get_objects(struct hash *h, unsigned first, unsigned number, void **objects);
void hash_test(void);

#endif

