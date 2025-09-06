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
#include <unistd.h>

#include "rsecret.h"

/* GPG context - will be replaced with actual GPGME integration */
static void *gpg_context = NULL;

static int gpg_init(void);
static int run_gpg_command(char *const argv[], const char *input, char **output);

int
gpg_encrypt(const char *plaintext, char **ciphertext) {
	char *argv[16];
	int argc = 0;
	int ret;

	if (gpg_init() != 0)
		return -1;

	/* Build GPG command for encryption */
	argc = 0;
	argv[argc++] = "gpg";
	argv[argc++] = "--quiet";
	argv[argc++] = "--batch";
	argv[argc++] = "--armor";
	argv[argc++] = "--encrypt";
	argv[argc++] = "--trust-model";
	argv[argc++] = "always";
	argv[argc++] = "--default-recipient-self";
	argv[argc] = NULL;

	ret = run_gpg_command(argv, plaintext, ciphertext);
	if (ret != 0) {
		warnx("GPG encryption failed");
		return -1;
	}

	return 0;
}

int
gpg_decrypt(const char *ciphertext, char **plaintext) {
	char *argv[16];
	int argc = 0;
	int ret;

	if (gpg_init() != 0)
		return -1;

	/* Build GPG command for decryption */
	argc = 0;
	argv[argc++] = "gpg";
	argv[argc++] = "--quiet";
	argv[argc++] = "--batch";
	argv[argc++] = "--decrypt";
	argv[argc] = NULL;

	ret = run_gpg_command(argv, ciphertext, plaintext);
	if (ret != 0) {
		warnx("GPG decryption failed");
		return -1;
	}

	return 0;
}

void
gpg_cleanup(void) {
	if (gpg_context) {
		/* TODO: Implement actual GPGME cleanup */
		gpg_context = NULL;
	}
}

static int
gpg_init(void) {
	if (gpg_context)
		return 0;

	/* TODO: Implement actual GPGME initialization */
	/* For now, just check if gpg binary is available */
	if (access("/usr/bin/gpg", X_OK) != 0 && 
	    access("/usr/local/bin/gpg", X_OK) != 0) {
		warnx("gpg binary not found in PATH");
		return -1;
	}

	gpg_context = (void *)1; /* simulate successful init */
	return 0;
}

static int
run_gpg_command(char *const argv[], const char *input, char **output) {
	FILE *pipe_read, *pipe_write;
	int stdin_pipe[2], stdout_pipe[2];
	pid_t pid;
	int status;
	char buffer[4096];
	size_t total_size = 0;
	size_t buffer_size = 4096;
	char *result = NULL;
	ssize_t bytes_read;

	if (pipe(stdin_pipe) == -1 || pipe(stdout_pipe) == -1) {
		warn("pipe");
		return -1;
	}

	pid = fork();
	if (pid == -1) {
		warn("fork");
		close(stdin_pipe[0]);
		close(stdin_pipe[1]);
		close(stdout_pipe[0]);
		close(stdout_pipe[1]);
		return -1;
	}

	if (pid == 0) {
		/* child process */
		close(stdin_pipe[1]);
		close(stdout_pipe[0]);

		dup2(stdin_pipe[0], STDIN_FILENO);
		dup2(stdout_pipe[1], STDOUT_FILENO);

		close(stdin_pipe[0]);
		close(stdout_pipe[1]);

		execvp(argv[0], argv);
		err(1, "execvp %s", argv[0]);
	}

	/* parent process */
	close(stdin_pipe[0]);
	close(stdout_pipe[1]);

	/* write input to gpg */
	pipe_write = fdopen(stdin_pipe[1], "w");
	if (pipe_write) {
		fprintf(pipe_write, "%s", input);
		fclose(pipe_write);
	}

	/* read output from gpg */
	result = secure_malloc(buffer_size);
	if (!result) {
		close(stdout_pipe[0]);
		waitpid(pid, &status, 0);
		return -1;
	}

	pipe_read = fdopen(stdout_pipe[0], "r");
	if (pipe_read) {
		while ((bytes_read = fread(buffer, 1, sizeof(buffer), pipe_read)) > 0) {
			if (total_size + bytes_read >= buffer_size) {
				buffer_size *= 2;
				result = realloc(result, buffer_size);
				if (!result) {
					fclose(pipe_read);
					waitpid(pid, &status, 0);
					return -1;
				}
			}
			memcpy(result + total_size, buffer, bytes_read);
			total_size += bytes_read;
		}
		fclose(pipe_read);
	}

	waitpid(pid, &status, 0);

	if (WEXITSTATUS(status) != 0) {
		secure_free(result, buffer_size);
		return -1;
	}

	result[total_size] = '\0';
	*output = result;
	return 0;
}