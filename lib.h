#ifndef LIB_H
#define LIB_H

struct playlist_item {
	struct playlist_item *next;
	char *str;
	unsigned int pos;
};

struct playlist {
	struct playlist_item *next;
	unsigned int length;
	unsigned int version;
	int current_pos;
	unsigned int current_elapsed;
	unsigned int current_length;
};

#define for_each_playlist_item(playlist, item) for (item = (playlist)->next; item; item = item->next)

void replace_chr(char *buf, char from, char to);
bool check_error(struct mpd_connection *con, FILE *logfile, bool exit_on_failure);
unsigned int n_digits(unsigned int n);

void free_item(struct playlist_item *item);
void free_playlist(struct playlist_item *first);

void do_status(struct mpd_connection *con, int *current, unsigned int *current_elapsed, unsigned int *current_total, unsigned int *length, unsigned int *version);

#endif /* LIB_H */
