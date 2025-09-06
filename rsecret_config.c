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

#include "rsecret.h"

static void parse_config_line(RSConfig *config, const char *line);
static void trim_whitespace(char *str);

RSConfig *
load_config(const char *config_path) {
	FILE *fp;
	char line[MAX_CONFIG_LINE];
	RSConfig *config;

	config = malloc(sizeof(RSConfig));
	if (!config)
		return NULL;

	/* set defaults */
	strlcpy(config->redis_host, "127.0.0.1", sizeof(config->redis_host));
	config->redis_port = 6379;
	config->redis_db = 0;
	config->redis_password[0] = '\0';
	config->redis_tls = 0;
	config->timeout_ms = 5000;

	fp = fopen(config_path, "r");
	if (!fp) {
		/* config file is optional, use defaults */
		return config;
	}

	while (fgets(line, sizeof(line), fp)) {
		trim_whitespace(line);
		
		/* skip empty lines and comments */
		if (line[0] == '\0' || line[0] == '#')
			continue;

		parse_config_line(config, line);
	}

	fclose(fp);
	return config;
}

void
free_config(RSConfig *config) {
	if (config) {
		/* zero sensitive data */
		secure_zero(config->redis_password, sizeof(config->redis_password));
		free(config);
	}
}

static void
parse_config_line(RSConfig *config, const char *line) {
	char *key, *value, *line_copy;
	
	line_copy = strdup(line);
	if (!line_copy)
		return;

	key = line_copy;
	value = strchr(line_copy, '=');
	if (!value) {
		free(line_copy);
		return;
	}

	*value = '\0';
	value++;

	trim_whitespace(key);
	trim_whitespace(value);

	if (strcmp(key, "redis_host") == 0) {
		strlcpy(config->redis_host, value, sizeof(config->redis_host));
	} else if (strcmp(key, "redis_port") == 0) {
		config->redis_port = atoi(value);
	} else if (strcmp(key, "redis_db") == 0) {
		config->redis_db = atoi(value);
	} else if (strcmp(key, "redis_password") == 0) {
		strlcpy(config->redis_password, value, sizeof(config->redis_password));
	} else if (strcmp(key, "redis_tls") == 0) {
		config->redis_tls = (strcmp(value, "1") == 0 || strcmp(value, "true") == 0);
	} else if (strcmp(key, "timeout_ms") == 0) {
		config->timeout_ms = atoi(value);
	}

	free(line_copy);
}

static void
trim_whitespace(char *str) {
	char *start = str;
	char *end;

	/* trim leading whitespace */
	while (*start == ' ' || *start == '\t')
		start++;

	/* trim trailing whitespace */
	end = str + strlen(str) - 1;
	while (end > str && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r'))
		end--;

	end[1] = '\0';

	/* move trimmed string to beginning if needed */
	if (start != str) {
		memmove(str, start, strlen(start) + 1);
	}
}