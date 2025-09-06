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

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rsecret_scanner.h"

SecretContext *
secret_context_new(int enabled) {
	SecretContext *ctx;

	ctx = malloc(sizeof(SecretContext));
	if (!ctx)
		return NULL;

	ctx->secrets_enabled = enabled;
	ctx->required_secrets = enabled ? secret_list_new() : NULL;

	return ctx;
}

void
secret_context_free(SecretContext *ctx) {
	if (ctx) {
		if (ctx->required_secrets)
			secret_list_free(ctx->required_secrets);
		free(ctx);
	}
}

int
scan_content_for_secrets(SecretContext *ctx, const char *content) {
	const char *p, *key_start, *key_end;
	char *secret_key;

	if (!ctx || !ctx->secrets_enabled || !content)
		return 0;

	p = content;
	while (*p) {
		if (is_secret_pattern(p, &key_start, &key_end)) {
			secret_key = extract_secret_key(key_start, key_end);
			if (secret_key) {
				secret_list_add(ctx->required_secrets, secret_key);
				free(secret_key);
			}
			p = key_end + strlen(SECRET_PATTERN_END);
		} else {
			p++;
		}
	}

	return 0;
}

int
scan_options_for_secrets(SecretContext *ctx, Options *options) {
	if (!ctx || !ctx->secrets_enabled || !options)
		return 0;

	/* Scan all option strings for secret patterns */
	scan_content_for_secrets(ctx, options->execute_with);
	scan_content_for_secrets(ctx, options->interpreter);
	scan_content_for_secrets(ctx, options->local_interpreter);
	scan_content_for_secrets(ctx, options->environment);
	scan_content_for_secrets(ctx, options->environment_file);
	
	if (options->begin)
		scan_content_for_secrets(ctx, options->begin);
	if (options->end)
		scan_content_for_secrets(ctx, options->end);

	return 0;
}

int
substitute_secrets_in_content(char **content, int *content_size) {
	char *new_content = NULL;
	char *old_content = *content;
	const char *p, *key_start, *key_end;
	char *secret_key = NULL;
	char secret_value[MAX_SECRET_VALUE_SIZE];
	int new_size = 0;
	int new_capacity = *content_size * 2; /* start with double capacity */
	int pattern_len, key_len, value_len;

	if (!content || !*content)
		return 0;

	new_content = secure_malloc(new_capacity);
	if (!new_content)
		return -1;

	p = old_content;
	while (*p) {
		if (is_secret_pattern(p, &key_start, &key_end)) {
			secret_key = extract_secret_key(key_start, key_end);
			if (!secret_key) {
				warnx("failed to extract secret key");
				goto error;
			}

			/* Get secret value */
			secure_zero(secret_value, sizeof(secret_value));
			if (redis_get_secret(secret_key, secret_value, sizeof(secret_value)) != 0) {
				warnx("failed to get secret: %s", secret_key);
				free(secret_key);
				goto error;
			}

			value_len = strlen(secret_value);
			pattern_len = (key_end + strlen(SECRET_PATTERN_END)) - p;

			/* Ensure we have enough space */
			while (new_size + value_len >= new_capacity) {
				new_capacity *= 2;
				new_content = realloc(new_content, new_capacity);
				if (!new_content) {
					free(secret_key);
					goto error;
				}
			}

			/* Copy secret value */
			memcpy(new_content + new_size, secret_value, value_len);
			new_size += value_len;

			/* Clear secret value from memory */
			secure_zero(secret_value, sizeof(secret_value));

			/* Move past the pattern */
			p += pattern_len;
			free(secret_key);
			secret_key = NULL;
		} else {
			/* Ensure we have space for one more character */
			if (new_size + 1 >= new_capacity) {
				new_capacity *= 2;
				new_content = realloc(new_content, new_capacity);
				if (!new_content)
					goto error;
			}

			/* Copy regular character */
			new_content[new_size++] = *p++;
		}
	}

	new_content[new_size] = '\0';

	/* Replace old content with new content */
	free(old_content);
	*content = new_content;
	*content_size = new_size;

	return 0;

error:
	if (new_content)
		secure_free(new_content, new_capacity);
	if (secret_key)
		free(secret_key);
	secure_zero(secret_value, sizeof(secret_value));
	return -1;
}

int
substitute_secrets_in_string(char *str, size_t str_size) {
	char *content = strdup(str);
	int content_size = strlen(content);
	int ret;

	if (!content)
		return -1;

	ret = substitute_secrets_in_content(&content, &content_size);
	if (ret == 0) {
		if (content_size < str_size) {
			strlcpy(str, content, str_size);
		} else {
			warnx("substituted string too long");
			ret = -1;
		}
	}

	if (content)
		secure_free(content, strlen(content));

	return ret;
}

int
validate_required_secrets(SecretContext *ctx) {
	char **keys;
	int count;
	int ret;

	if (!ctx || !ctx->secrets_enabled)
		return 0;

	keys = get_required_secret_keys(ctx, &count);
	if (!keys)
		return 0;

	ret = redis_validate_secrets(keys, count);

	/* keys array points into ctx->required_secrets, don't free individual keys */
	free(keys);

	return ret;
}

char **
get_required_secret_keys(SecretContext *ctx, int *count) {
	char **keys;
	int i;

	if (!ctx || !ctx->required_secrets) {
		*count = 0;
		return NULL;
	}

	*count = ctx->required_secrets->count;
	if (*count == 0)
		return NULL;

	keys = malloc(*count * sizeof(char *));
	if (!keys) {
		*count = 0;
		return NULL;
	}

	for (i = 0; i < *count; i++) {
		keys[i] = &ctx->required_secrets->keys[i * MAX_SECRET_KEY_SIZE];
	}

	return keys;
}

int
is_secret_pattern(const char *str, const char **key_start, const char **key_end) {
	const char *pattern_start, *pattern_prefix, *pattern_end;

	pattern_start = strstr(str, SECRET_PATTERN_START);
	if (!pattern_start || pattern_start != str)
		return 0;

	pattern_prefix = pattern_start + strlen(SECRET_PATTERN_START);
	if (strncmp(pattern_prefix, SECRET_PATTERN_PREFIX, strlen(SECRET_PATTERN_PREFIX)) != 0)
		return 0;

	*key_start = pattern_prefix + strlen(SECRET_PATTERN_PREFIX);
	pattern_end = strstr(*key_start, SECRET_PATTERN_END);
	if (!pattern_end)
		return 0;

	*key_end = pattern_end;
	return 1;
}

char *
extract_secret_key(const char *pattern_start, const char *pattern_end) {
	size_t key_len;
	char *key;

	key_len = pattern_end - pattern_start;
	if (key_len == 0 || key_len >= MAX_SECRET_KEY_SIZE)
		return NULL;

	key = malloc(key_len + 1);
	if (!key)
		return NULL;

	memcpy(key, pattern_start, key_len);
	key[key_len] = '\0';

	if (!validate_secret_key(key)) {
		free(key);
		return NULL;
	}

	return key;
}