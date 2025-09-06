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

#include "input.h"
#include "rsecret_scanner.h"

int
validate_all_secrets(Label **route_labels) {
	SecretContext *ctx;
	int i, j;
	int ret = 0;
	Label **host_labels;

	ctx = secret_context_new(1);
	if (!ctx)
		return -1;

	/* scan all route labels and their host labels for secrets */
	for (i = 0; route_labels[i]; i++) {
		/* scan route label options */
		scan_options_for_secrets(ctx, &route_labels[i]->options);
		
		/* scan route label content */
		if (route_labels[i]->content)
			scan_content_for_secrets(ctx, route_labels[i]->content);

		/* scan host labels */
		host_labels = route_labels[i]->labels;
		if (host_labels) {
			for (j = 0; host_labels[j]; j++) {
				/* scan host label options */
				scan_options_for_secrets(ctx, &host_labels[j]->options);
				
				/* scan host label content */
				if (host_labels[j]->content)
					scan_content_for_secrets(ctx, host_labels[j]->content);
			}
		}
	}

	/* validate all required secrets */
	ret = validate_required_secrets(ctx);
	if (ret != 0)
		warnx("Secret validation failed");

	secret_context_free(ctx);
	return ret;
}