/*
 * Copyright (c) 2025 Eric Radman <ericshane@eradman.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/mman.h>

#include <err.h>
#include <stdlib.h>
#include <string.h>

#include "rsecret.h"

void
secure_zero(void *ptr, size_t len) {
	volatile unsigned char *p = ptr;
	while (len--)
		*p++ = 0;
}

void *
secure_malloc(size_t size) {
	void *ptr;

	ptr = malloc(size);
	if (!ptr)
		return NULL;

#ifdef MAP_NOCORE
	/* prevent memory from being included in core dumps */
	if (mlock(ptr, size) != 0) {
		warn("mlock");
	}
#endif

	return ptr;
}

void
secure_free(void *ptr, size_t size) {
	if (ptr) {
		secure_zero(ptr, size);
#ifdef MAP_NOCORE
		munlock(ptr, size);
#endif
		free(ptr);
	}
}

SecretList *
secret_list_new(void) {
	SecretList *list;

	list = malloc(sizeof(SecretList));
	if (!list)
		return NULL;

	list->capacity = 16;
	list->count = 0;
	list->keys = malloc(list->capacity * MAX_SECRET_KEY_SIZE);
	if (!list->keys) {
		free(list);
		return NULL;
	}

	return list;
}

void
secret_list_add(SecretList *list, const char *key) {
	char *new_keys;

	if (!list || !key)
		return;

	/* expand capacity if needed */
	if (list->count >= list->capacity) {
		list->capacity *= 2;
		new_keys = realloc(list->keys, list->capacity * MAX_SECRET_KEY_SIZE);
		if (!new_keys)
			return;
		list->keys = new_keys;
	}

	/* add key to list */
	strlcpy(&list->keys[list->count * MAX_SECRET_KEY_SIZE], key, MAX_SECRET_KEY_SIZE);
	list->count++;
}

void
secret_list_free(SecretList *list) {
	if (list) {
		if (list->keys) {
			secure_zero(list->keys, list->capacity * MAX_SECRET_KEY_SIZE);
			free(list->keys);
		}
		free(list);
	}
}