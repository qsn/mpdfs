#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <mpd/client.h>

#include "lib.h"

void replace_chr(char *buf, char from, char to)
{
	char *c = buf;
	while (*c) {
		if (*c == from)
			*c = to;
		c++;
	}
}

bool check_error(struct mpd_connection *con, FILE *logfile, bool exit_on_failure)
{
	if (mpd_connection_get_error(con) != MPD_ERROR_SUCCESS) {
		if (logfile)
			fprintf(logfile, "MPD error: %s\n", mpd_connection_get_error_message(con));
		if (exit_on_failure || !mpd_connection_clear_error(con)) {
			mpd_connection_free(con);
			exit(EXIT_FAILURE);
		}

		return true;
	}

	return false;
}

unsigned int n_digits(unsigned int n)
{
	if (n < 10)
		return 1;
	if (n < 100)
		return 2;
	if (n < 1000)
		return 3;
	return 4;
}

void free_item(struct playlist_item *item)
{
	if (item) {
		free(item->str);
		free(item);
	}
}

void free_playlist(struct playlist_item *first)
{
	struct playlist_item *item, *next;

	for (item = first; item; item = next) {
		next = item->next;
		free_item(item);
	}
}

void do_status(struct mpd_connection *con, int *current, unsigned int *current_elapsed, unsigned int *current_total, unsigned int *length, unsigned int *version)
{
	struct mpd_status *st = mpd_run_status(con);

	if (!st)
		return;
	if (check_error(con, NULL, false))
		goto out;

	switch (mpd_status_get_state(st)) {
	case MPD_STATE_UNKNOWN:
	case MPD_STATE_STOP:
		if (current)
			*current = -1;
		if (current_elapsed)
			*current_elapsed = 0;
		if (current_total)
			*current_total = 0;
		break;
	case MPD_STATE_PLAY:
	case MPD_STATE_PAUSE:
		if (current)
			*current = mpd_status_get_song_pos(st);
		if (current_elapsed)
			*current_elapsed = mpd_status_get_elapsed_time(st);
		if (current_total)
			*current_total = mpd_status_get_total_time(st);
		break;
	}
	if (length)
		*length = mpd_status_get_queue_length(st);
	if (version)
		*version = mpd_status_get_queue_version(st);

out:
	mpd_status_free(st);
}
