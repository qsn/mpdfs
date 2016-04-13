#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bsd/string.h>
#include <mpd/client.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/mman.h>
#include <limits.h>
#include <fcntl.h>

#define FUSE_USE_VERSION 26
#include <fuse.h>

#include "lib.h"

#define FMODE_EXEC 0x20

static bool exit_on_failure = false;

struct mpdfs_priv {
	struct mpd_connection *con;
	struct playlist playlist;
	pthread_mutex_t mutex;
	char *root;
	FILE *logfile;
	pid_t pping;
};

static void ping_fct(struct mpdfs_priv *priv)
{
	struct mpd_stats *stats;

	while (1) {
		sleep(10);
		pthread_mutex_lock(&priv->mutex);
		stats = mpd_run_stats(priv->con);
		if (!check_error(priv->con, NULL, false))
			mpd_stats_free(stats);
		pthread_mutex_unlock(&priv->mutex);
	}
}

#define SEPARATOR " - "
#define SEPARATOR_LEN 3
static char *format_song(struct mpd_song *song, unsigned int align, unsigned int pos)
{
	char *buf;
	unsigned long buflen;
	const char *artist, *album, *album_artist, *title;
	artist = mpd_song_get_tag(song, MPD_TAG_ARTIST, 0);
	album_artist = mpd_song_get_tag(song, MPD_TAG_ALBUM_ARTIST, 0);
	album = mpd_song_get_tag(song, MPD_TAG_ALBUM, 0);
	title = mpd_song_get_tag(song, MPD_TAG_TITLE, 0);

	if (album_artist)
		artist = album_artist;

	if (artist && title && album) {
		buflen = align + SEPARATOR_LEN + strlen(artist) + SEPARATOR_LEN + strlen(album) + SEPARATOR_LEN + strlen(title) + 1;
		buf = malloc(buflen);
		memset(buf, 0, buflen);
		sprintf(buf, "%0*u" SEPARATOR "%s" SEPARATOR "%s" SEPARATOR "%s", align, pos, artist, album, title);
	} else if (artist && title) {
		buflen = align + SEPARATOR_LEN + strlen(artist) + SEPARATOR_LEN + strlen(title) + 1;
		buf = malloc(buflen);
		memset(buf, 0, buflen);
		sprintf(buf, "%0*u" SEPARATOR "%s" SEPARATOR "%s", align, pos, artist, title);
	} else {
		const char *uri = mpd_song_get_uri(song);
		buflen = align + SEPARATOR_LEN + strlen(uri) + 1;
		buf = malloc(buflen);
		memset(buf, 0, buflen);
		sprintf(buf, "%0*u" SEPARATOR "%s", align, pos, uri);
	}

	replace_chr(buf, '/', ':');
	return buf;
}

static bool update(struct mpdfs_priv *priv)
{
	unsigned int length, version, i;
	int current;
	struct playlist_item *first = priv->playlist.next;

	pthread_mutex_lock(&priv->mutex);
	do_status(priv->con, &current, &priv->playlist.current_elapsed, &priv->playlist.current_length, &length, &version);
	if (version != priv->playlist.version) {
		unsigned int align = n_digits(length);
		struct mpd_song *song;
		struct playlist_item *prev;
		priv->playlist.next = NULL;

		if (!mpd_send_list_queue_meta(priv->con)) {
			check_error(priv->con, priv->logfile, exit_on_failure);
			goto unlock;
		}

		prev = (struct playlist_item *) &priv->playlist;
		for (i = 0; (song = mpd_recv_song(priv->con)); i++) {
			prev->next = malloc(sizeof(struct playlist_item));
			if (!prev->next)
				goto err;
			prev->next->next = NULL;
			prev->next->pos = mpd_song_get_pos(song);
			prev->next->str = format_song(song, align, prev->next->pos);
			mpd_song_free(song);
			prev = prev->next;
		}

		free_playlist(first);

		if (!mpd_response_finish(priv->con))
			check_error(priv->con, priv->logfile, exit_on_failure);

		priv->playlist.version = version;
	}
	priv->playlist.current_pos = current;
	priv->playlist.length = length;

	pthread_mutex_unlock(&priv->mutex);

	return true;

err:
	// restore previous playlist, it will be updated on the next occasion
	free_playlist(priv->playlist.next);
	priv->playlist.current_pos = -1;
	priv->playlist.next = first;
unlock:
	pthread_mutex_unlock(&priv->mutex);
	return false;
}

static struct playlist_item *find_in_playlist(const char *path, struct playlist *playlist)
{
	struct playlist_item *item;

	if (!path || strlen(path) == 0 || path[0] != '/')
		return NULL;
	for_each_playlist_item(playlist, item) {
		if (strcmp(path + 1, item->str) == 0)
			return item;
	}

	return NULL;
}

static struct playlist_item *find_current(struct playlist *playlist)
{
	struct playlist_item *item;

	if (playlist->current_pos < 0)
		return NULL;

	for_each_playlist_item(playlist, item) {
		if ((unsigned int)playlist->current_pos == item->pos)
			return item;
	}

	return NULL;
}


#define STATUS_LEN 512
#define SCRIPT_HEADER "#!/bin/sh\n"
#define SCRIPT_LEN strlen(SCRIPT_HEADER)
static char status_buf[STATUS_LEN];

static void format_time(char *buf, unsigned int secs)
{
	sprintf(buf, "%u:%02u", secs / 60, secs % 60);
}

static void regen_status_buf(struct mpdfs_priv *priv)
{
	struct playlist_item *item;
	char buf1[12], buf2[12];
	unsigned long offset = 0;
	int ret;

	update(priv);

	memset(status_buf, 0, sizeof(status_buf));

	item = find_current(&priv->playlist);
	if (!item)
		return;
	ret = snprintf(status_buf + offset, STATUS_LEN - 1 - offset, "%s\n", item->str);
	if (ret < 0)
		return;
	offset += (unsigned long) ret;
	format_time(buf1, priv->playlist.current_elapsed);
	format_time(buf2, priv->playlist.current_length);
	ret = snprintf(status_buf + offset, STATUS_LEN - 1 - offset, "%s/%s\n", buf1, buf2);
}


enum mpdfs_builtin_id {
	MPDFS_NONE = 0,
	MPDFS_STATUS,
	MPDFS_CLEAR,
	MPDFS_NEXT,
	MPDFS_PREV,
	MPDFS_PLAY,
	MPDFS_STOP,
	MPDFS_PAUSE,
	MPDFS_SAVE,
	MPDFS_LOAD,
};

struct mpdfs_command {
	char *path;
	enum mpdfs_builtin_id id;
	bool (*mpd_action)(struct mpd_connection *);
};

static bool mpdfs_toggle_pause(struct mpd_connection *con)
{
	int current;
	do_status(con, &current, NULL, NULL, NULL, NULL);

	return current == -1 ? mpd_run_play(con) : mpd_run_toggle_pause(con);
}

static const struct mpdfs_command commands[] = {
	{
		.path = "status",
		.id   = MPDFS_STATUS,
		.mpd_action = NULL,
	},
	{
		.path = "clear",
		.id   = MPDFS_CLEAR,
		.mpd_action = mpd_run_clear,
	},
	{
		.path = "next",
		.id = MPDFS_NEXT,
		.mpd_action = mpd_run_next,
	},
	{
		.path = "prev",
		.id   = MPDFS_PREV,
		.mpd_action = mpd_run_previous,
	},
	{
		.path = "play",
		.id   = MPDFS_PLAY,
		.mpd_action = mpd_run_play,
	},
	{
		.path = "pause",
		.id   = MPDFS_PAUSE,
		.mpd_action = mpdfs_toggle_pause,
	},
	{
		.path = "stop",
		.id   = MPDFS_STOP,
		.mpd_action = mpd_run_stop,
	},
	{
		.path = "save",
		.id   = MPDFS_SAVE,
		.mpd_action = NULL,
	},
	{
		.path  = "load",
		.id    = MPDFS_LOAD,
		.mpd_action = NULL,
	},
	{
		.id = MPDFS_NONE,
	}
};

static bool builtin_writable(const struct mpdfs_command *command)
{
	return command->id == MPDFS_SAVE || command->id == MPDFS_LOAD;
}

static const struct mpdfs_command *check_builtin_path(const char *path)
{
	unsigned int i;

	if (!path || *path != '/')
		return NULL;

	for (i = 0; commands[i].id != MPDFS_NONE; i++) {
		if (strcmp(path + 1, commands[i].path) == 0)
			return &commands[i];
	}

	return NULL;
}


static int mpdfs_getattr(const char *path, struct stat *stbuf)
{
	struct mpdfs_priv *priv = fuse_get_context()->private_data;
	const struct mpdfs_command *command;

	if (priv->logfile)
		fprintf(priv->logfile, "getattr %s\n", path);

	memset(stbuf, 0, sizeof(*stbuf));
	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} else if (strcmp(path, "/current") == 0) {
		if (priv->playlist.current_pos >= 0) {
			stbuf->st_mode = S_IFLNK | 0444;
			stbuf->st_nlink = 1;
		} else {
			return -ENOENT;
		}
	} else if ((command = check_builtin_path(path))) {
		stbuf->st_nlink = 1;
		if (command->id == MPDFS_STATUS) {
			stbuf->st_mode = S_IFREG | 0444;
			stbuf->st_size = priv->playlist.current_pos >= 0 ? STATUS_LEN : 0;
		} else if (command->id == MPDFS_SAVE || command->id == MPDFS_LOAD) {
			stbuf->st_mode = S_IFREG | 0222;
			stbuf->st_size = 0;
		} else {
			stbuf->st_mode = S_IFREG | 0555;
			stbuf->st_size = SCRIPT_LEN;
		}
	} else if (find_in_playlist(path, &priv->playlist)) {
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = 0;
	} else {
		return -ENOENT;
	}

	return 0;
}

static int mpdfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
	struct mpdfs_priv *priv = fuse_get_context()->private_data;
	struct playlist_item *item;
	unsigned int i;

	if (priv->logfile)
		fprintf(priv->logfile, "readdir %s\n", path);
	if (strcmp(path, "/") != 0)
		return -ENOENT;

	if (!update(priv))
		return -EAGAIN;

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);

	for (i = 0; commands[i].id != MPDFS_NONE; i++)
		filler(buf, commands[i].path, NULL, 0);
	if (priv->playlist.current_pos >= 0)
		filler(buf, "current", NULL, 0);
	for_each_playlist_item(&priv->playlist, item)
		filler(buf, item->str, NULL, 0);

	return 0;
}


static int mpdfs_open(const char *path, struct fuse_file_info *fi)
{
	struct mpdfs_priv *priv = fuse_get_context()->private_data;
	struct playlist_item *item;
	const struct mpdfs_command *command;
	int err = -ENOENT;

	if (!update(priv))
		return -EAGAIN;

	if (priv->logfile)
		fprintf(priv->logfile, "open %s\n", path);

	command = check_builtin_path(path);
	pthread_mutex_lock(&priv->mutex);
	if (command) {
		if (!builtin_writable(command) && fi->flags & O_ACCMODE != O_RDONLY) {
			err = -EPERM;
			goto unlock;
		}

		/* execve = open(NORMAL | FMODE_EXEC) + open(NORMAL)
		 * filter out the first call that has FMODE_EXEC, and only
		 * tickle mpd on the second, or on a standard read
		 */
		if (command->mpd_action && !(fi->flags & FMODE_EXEC)) {
			if (!command->mpd_action(priv->con))
				check_error(priv->con, priv->logfile, exit_on_failure);
		}
		err = 0;
	} else if ((item = find_in_playlist(path, &priv->playlist))) {
		if (fi->flags & O_ACCMODE != O_RDONLY) {
			err = -EPERM;
			goto unlock;
		}

		if (!mpd_run_play_pos(priv->con, item->pos)) {
			check_error(priv->con, priv->logfile, exit_on_failure);
			err = -EIO;
		} else {
			err = 0;
		}
	}

unlock:
	pthread_mutex_unlock(&priv->mutex);

	return err;
}

static int mpdfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	struct mpdfs_priv *priv = fuse_get_context()->private_data;
	const struct mpdfs_command *command;

	if (!update(priv))
		return -EAGAIN;

	if (priv->logfile)
		fprintf(priv->logfile, "read %s\n", path);

	command = check_builtin_path(path);
	if (command && command->id == MPDFS_STATUS) {
		if (offset > STATUS_LEN)
			return 0;
		if (offset <= 0) {
			regen_status_buf(priv);
			offset = 0;
		}
		if ((unsigned long)offset + size >= STATUS_LEN)
			size = (unsigned long) (STATUS_LEN - offset);
		memcpy(buf, status_buf + offset, size);
		return (int)size;
	} else if (command) {
		strlcpy(buf, SCRIPT_HEADER, size);
		return SCRIPT_LEN;
	}

	return find_in_playlist(path, &priv->playlist) ? 0 : -ENOENT;
}

static int mpdfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	struct mpdfs_priv *priv = fuse_get_context()->private_data;
	const struct mpdfs_command *command;

	if (priv->logfile)
		fprintf(priv->logfile, "write %s\n", path);

	command = check_builtin_path(path);
	if (!command || !builtin_writable(command))
		return -EPERM;

	return size;
}

static int mpdfs_readlink(const char *path, char *buf, size_t size)
{
	struct mpdfs_priv *priv = fuse_get_context()->private_data;
	if (strcmp(path, "/current") == 0) {
		struct playlist_item *item;
		if (!update(priv))
			return -EIO;

		if (priv->playlist.current_pos < 0)
			return -ENOENT;

		item = find_current(&priv->playlist);
		if (!item)
			return -EIO;
		snprintf(buf, size, "%s/%s", priv->root, item->str);
		return 0;
	}

	return -ENOENT;
}

static void remove_from_playlist(struct playlist *playlist, unsigned int pos)
{
	struct playlist_item *item = playlist->next;

	if (pos == 0) {
		playlist->next = item->next;
	} else {
		while (item->pos < pos-1)
			item = item->next;
		item->next = item->next->next;
	}

	while ((item = item->next))
		item->pos--;
}

static int mpdfs_unlink(const char *path)
{
	struct mpdfs_priv *priv = fuse_get_context()->private_data;
	struct playlist_item *item;

	if (priv->logfile)
		fprintf(priv->logfile, "unlink %s\n", path);

	if (!path || *path != '/')
		return -ENOENT;

	if (strcmp(path, "/") == 0 || strcmp(path, "/current") == 0 || check_builtin_path(path))
		return -EPERM;

	pthread_mutex_lock(&priv->mutex);
	item = find_in_playlist(path, &priv->playlist);
	if (!item) {
		pthread_mutex_unlock(&priv->mutex);
		return -ENOENT;
	}

	if (!mpd_run_delete(priv->con, item->pos)) {
		check_error(priv->con, priv->logfile, exit_on_failure);
		pthread_mutex_unlock(&priv->mutex);
		return -EIO;
	}
	remove_from_playlist(&priv->playlist, item->pos);
	free(item);
	pthread_mutex_unlock(&priv->mutex);

	return 0;
}

static int mpdfs_rename(const char *path, const char *newpath)
{
	struct mpdfs_priv *priv = fuse_get_context()->private_data;
	struct playlist_item *item;
	long int newpos;
	char *endptr;

	if (priv->logfile)
		fprintf(priv->logfile, "rename %s to %s\n", path, newpath);

	if (!path || *path != '/' || !newpath || *newpath != '/')
		return -ENOENT;

	if (strcmp(path, "/") == 0 || strcmp(path, "/current") == 0 || check_builtin_path(path))
		return -EPERM;

	pthread_mutex_lock(&priv->mutex);
	item = find_in_playlist(path, &priv->playlist);
	if (!item) {
		pthread_mutex_unlock(&priv->mutex);
		return -ENOENT;
	}

	newpos = strtol(newpath + 1, &endptr, 0);
	if (*endptr != 0) {
		pthread_mutex_unlock(&priv->mutex);
		return -EINVAL;
	}

	if (!mpd_run_move(priv->con, item->pos, newpos)) {
		check_error(priv->con, priv->logfile, exit_on_failure);
		pthread_mutex_unlock(&priv->mutex);
		return -EIO;
	}
	pthread_mutex_unlock(&priv->mutex);

	update(priv);

	return 0;
}

static void mpdfs_destroy(void *arg)
{
	struct mpdfs_priv *priv = arg;

	kill(priv->pping, SIGKILL);
	mpd_connection_free(priv->con);
	if (priv->logfile)
		fclose(priv->logfile);
}

static struct mpdfs_priv *priv;


static void *mpdfs_init(struct fuse_conn_info *arg)
{
	return priv;
}

static int mpdfs_truncate(const char *path, off_t off)
{
	struct mpdfs_priv *priv = fuse_get_context()->private_data;
	const struct mpdfs_command *command;

	if (priv->logfile)
		fprintf(priv->logfile, "truncate %s\n", path);

	command = check_builtin_path(path);
	if (!command || !builtin_writable(command))
		return -EPERM;

	if (off != 0)
		return -EOPNOTSUPP;

	return 0;
}

static struct fuse_operations fops = {
	.getattr  = mpdfs_getattr,
	.readdir  = mpdfs_readdir,
	.readlink = mpdfs_readlink,
	.open     = mpdfs_open,
	.read     = mpdfs_read,
	.write    = mpdfs_write,
	.truncate = mpdfs_truncate,
	.unlink   = mpdfs_unlink,
	.rename   = mpdfs_rename,
	.init     = mpdfs_init,
	.destroy  = mpdfs_destroy,
};

#define DEFAULT_LOGFILE "/tmp/log"
#define DEFAULT_SERVER "127.0.0.1"
#define DEFAULT_PORT 6600

static void usage(void)
{
	printf("usage: mpdfs [-c server] [-p port] [-d | -D logfile] mountpoint\n");
	exit(1);
}

int main(int argc, char **argv)
{
	int err;
	pthread_mutexattr_t attr;

	char opt;
	unsigned short port = DEFAULT_PORT;
	char *server = DEFAULT_SERVER;
	bool debug = false;
	char *logfile = NULL;

	while ((opt = getopt(argc, argv, "hdD:c:p:")) != -1) {
		switch (opt) {
		case 'd':
			debug = true;
			if (!logfile)
				logfile = DEFAULT_LOGFILE;
			break;
		case 'D':
			debug = true;
			logfile = optarg;
			break;
		case 'c':
			server = optarg;
			break;
		case 'p': {
			unsigned long p = strtoul(optarg, NULL, 10);
			if (p != ULONG_MAX && p <= USHRT_MAX) {
				port = (unsigned short) p;
			} else {
				printf("bad port number: %s\n", optarg);
				usage();
				return 1;
			}
			break;
		}
		default:
			printf("unknown: %c\n", opt);
			usage();
		}
	}

	optind--;
	argv[optind] = argv[0];
	argv += optind;
	argc -= optind;

	priv = mmap(NULL, sizeof(*priv), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	if (priv == MAP_FAILED) {
		perror("mmap");
		goto err_init;
	}

	if (pthread_mutexattr_init(&attr) ||
	    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) ||
	    pthread_mutex_init(&priv->mutex, &attr))
		goto err_init;

	priv->root = argv[1];

	if (logfile) {
		priv->logfile = fopen(logfile, "a");
		if (!priv->logfile) {
			perror("open log file");
			goto err_init;
		}
		setvbuf(priv->logfile, NULL, _IOLBF, BUFSIZ);
	}

	priv->con = mpd_connection_new(server, port, 0);
	if (!priv->con)
		goto err_init;

	check_error(priv->con, stdout, true);

	pid_t pid = fork();
	if (pid < 0) {
		perror("fork");
		goto err_fork;
	}
	if (pid == 0) {
		ping_fct(priv);
		return 0;
	}

	priv->pping = pid;

	err = fuse_main(argc, argv, &fops, &priv);
	if (err)
		goto err_fuse;

	return 0;

err_fuse:
	kill(pid, SIGKILL);
err_fork:
	mpd_connection_free(priv->con);
err_init:
	if (priv->logfile)
		fclose(priv->logfile);
	exit(EXIT_FAILURE);
}
