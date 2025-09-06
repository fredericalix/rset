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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "missing/compat.h"
#include "rsecret.h"
#include "rsecret_scanner.h"

/* forwards */
static void usage(void);

/* globals */
static RSConfig *config = NULL;

int
main(int argc, char *argv[]) {
	int ch;
	int ret = 0;
	char *config_path = RSECRET_CONFIG_FILE;
	char secret_value[MAX_SECRET_VALUE_SIZE];
	SecretList *secret_list = NULL;
	
	/* command modes */
	enum { MODE_NONE, MODE_GET, MODE_SET, MODE_LIST, MODE_VALIDATE } mode = MODE_NONE;
	char *secret_key = NULL;
	char *secret_data = NULL;
	char **validate_keys = NULL;
	int validate_count = 0;

#ifdef __OpenBSD__
	if (pledge("stdio rpath inet proc exec", NULL) == -1)
		err(1, "pledge");
#endif

	/* handle --help before getopt */
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--help") == 0) {
			usage();
		}
	}

	while ((ch = getopt(argc, argv, "c:g:s:lv")) != -1) {
		switch (ch) {
		case 'c':
			config_path = optarg;
			break;
		case 'g':
			if (mode != MODE_NONE) usage();
			mode = MODE_GET;
			secret_key = optarg;
			break;
		case 's':
			if (mode != MODE_NONE) usage();
			mode = MODE_SET;
			secret_key = optarg;
			break;
		case 'l':
			if (mode != MODE_NONE) usage();
			mode = MODE_LIST;
			break;
		case 'v':
			if (mode != MODE_NONE) usage();
			mode = MODE_VALIDATE;
			validate_keys = &argv[optind];
			validate_count = argc - optind;
			break;
		default:
			usage();
		}
	}

	if (mode == MODE_NONE)
		usage();

	/* validate secret key format */
	if (secret_key && !validate_secret_key(secret_key))
		errx(1, "invalid secret key format: %s", secret_key);

	/* load configuration */
	config = load_config(config_path);
	if (!config)
		errx(1, "failed to load config from %s", config_path);

	/* connect to Redis */
	if (redis_connect(config) != 0)
		errx(1, "failed to connect to Redis");

#ifdef __OpenBSD__
	if (pledge("stdio inet proc exec", NULL) == -1)
		err(1, "pledge");
#endif

	switch (mode) {
	case MODE_GET:
		secure_zero(secret_value, sizeof(secret_value));
		ret = redis_get_secret(secret_key, secret_value, sizeof(secret_value));
		if (ret == 0) {
			printf("%s", secret_value);
			secure_zero(secret_value, sizeof(secret_value));
		}
		break;

	case MODE_SET:
		if (optind >= argc)
			errx(1, "secret value required for set mode");
		secret_data = argv[optind];
		ret = redis_set_secret(secret_key, secret_data);
		if (ret == 0)
			printf("Secret '%s' stored successfully\n", secret_key);
		break;

	case MODE_LIST:
		secret_list = secret_list_new();
		ret = redis_list_secrets(secret_list);
		if (ret == 0) {
			for (int i = 0; i < secret_list->count; i++)
				printf("%s\n", &secret_list->keys[i * MAX_SECRET_KEY_SIZE]);
		}
		break;

	case MODE_VALIDATE:
		ret = redis_validate_secrets(validate_keys, validate_count);
		break;

	default:
		usage();
	}

#ifdef __OpenBSD__
	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");
#endif

	/* cleanup */
	gpg_cleanup();
	redis_disconnect();
	free_config(config);
	if (secret_list)
		secret_list_free(secret_list);

	return ret;
}

static void
usage() {
	fprintf(stderr, "usage: rsecret [-c config] -g key\n");
	fprintf(stderr, "       rsecret [-c config] -s key value\n");
	fprintf(stderr, "       rsecret [-c config] -l\n");
	fprintf(stderr, "       rsecret [-c config] -v key1 key2 ...\n");
	exit(1);
}
