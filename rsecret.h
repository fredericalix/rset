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

#ifndef _RSECRET_H_
#define _RSECRET_H_

#include <limits.h>

#define RSECRET_CONFIG_FILE "rsecret.conf"
#define REDIS_KEY_PREFIX "secret:"
#define MAX_SECRET_KEY_SIZE 128
#define MAX_SECRET_VALUE_SIZE 4096
#define MAX_CONFIG_LINE 256

typedef struct {
	char redis_host[256];
	int redis_port;
	int redis_db;
	char redis_password[256];
	int redis_tls;
	int timeout_ms;
} RSConfig;

typedef struct {
	char *keys;
	int count;
	int capacity;
} SecretList;

/* Configuration */
RSConfig *load_config(const char *config_path);
void free_config(RSConfig *config);

/* Redis operations */
int redis_connect(RSConfig *config);
void redis_disconnect(void);
int redis_get_secret(const char *key, char *value, size_t value_size);
int redis_set_secret(const char *key, const char *value);
int redis_list_secrets(SecretList *list);
int redis_validate_secrets(char **keys, int count);

/* GPG operations */
int gpg_encrypt(const char *plaintext, char **ciphertext);
int gpg_decrypt(const char *ciphertext, char **plaintext);
void gpg_cleanup(void);

/* Secret list operations */
SecretList *secret_list_new(void);
void secret_list_add(SecretList *list, const char *key);
void secret_list_free(SecretList *list);

/* Memory security */
void secure_zero(void *ptr, size_t len);
void *secure_malloc(size_t size);
void secure_free(void *ptr, size_t size);

/* Utility functions */
int validate_secret_key(const char *key);

#endif /* _RSECRET_H_ */