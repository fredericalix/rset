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

#ifndef _RSECRET_SCANNER_H_
#define _RSECRET_SCANNER_H_

#include "input.h"
#include "rsecret.h"

#define SECRET_PATTERN_START "{{"
#define SECRET_PATTERN_PREFIX "secret:"
#define SECRET_PATTERN_END "}}"
#define SECRET_PATTERN_FULL "{{secret:"

/* Secret substitution context */
typedef struct {
	SecretList *required_secrets;
	int secrets_enabled;
} SecretContext;

/* Secret scanning and substitution */
SecretContext *secret_context_new(int enabled);
void secret_context_free(SecretContext *ctx);

/* Scan content for secret patterns and add to required list */
int scan_content_for_secrets(SecretContext *ctx, const char *content);
int scan_options_for_secrets(SecretContext *ctx, Options *options);

/* Substitute secrets in content (modifies content in-place) */
int substitute_secrets_in_content(char **content, int *content_size);
int substitute_secrets_in_string(char *str, size_t str_size);

/* Validate all required secrets are available */
int validate_required_secrets(SecretContext *ctx);

/* Get list of all required secrets */
char **get_required_secret_keys(SecretContext *ctx, int *count);

/* Utility functions */
int is_secret_pattern(const char *str, const char **key_start, const char **key_end);
char *extract_secret_key(const char *pattern_start, const char *pattern_end);

#endif /* _RSECRET_SCANNER_H_ */