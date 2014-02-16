/*
	Copyright (C) 2013 - 2014 CurlyMo

	This file is part of zfsguru.

    zfsguru is free software: you can redistribute it and/or modify it under the
	terms of the GNU General Public License as published by the Free Software
	Foundation, either version 3 of the License, or (at your option) any later
	version.

    zfsguru is distributed in the hope that it will be useful, but WITHOUT ANY
	WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
	A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with zfsguru. If not, see	<http://www.gnu.org/licenses/>
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#define __USE_GNU
#include <pthread.h>
#include <ctype.h>

#include "zfsguru.h"
#include "common.h"
#include "settings.h"
#include "gc.h"
#include "log.h"
#include "options.h"
#include "threads.h"
#include "webserver.h"

/* The pid_file and pid of this daemon */
char *pid_file;
pid_t pid;
/* Daemonize or not */
int nodaemon = 0;
/* Are we already running */
int running = 1;
/* Which mode are we running in: 1 = server, 2 = client */
unsigned short runmode = 1;
/* Thread pointers */
pthread_t pth;
/* While loop conditions */
unsigned short main_loop = 1;
/* Are we running standalone */
int standalone = 0;

int webserver_enable = 1;

void save_pid(pid_t npid) {
	int f = 0;
	char buffer[BUFFER_SIZE];
	if((f = open(pid_file, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR)) != -1) {
		lseek(f, 0, SEEK_SET);
		sprintf(buffer, "%d", npid);
		ssize_t i = write(f, buffer, strlen(buffer));
		if(i != strlen(buffer)) {
			logprintf(LOG_ERR, "could not store pid in %s", pid_file);
		}
	}
	close(f);
}

void daemonize(void) {
	log_file_enable();
	log_shell_disable();
	/* Get the pid of the fork */
	pid_t npid = fork();
	switch(npid) {
		case 0:
		break;
		case -1:
			logprintf(LOG_ERR, "could not daemonize program");
			exit(1);
		break;
		default:
			save_pid(npid);
			logprintf(LOG_INFO, "daemon started with pid: %d", npid);
			exit(0);
		break;
	}
}

/* Garbage collector of main program */
int main_gc(void) {

	main_loop = 0;

	if(running == 0) {
		/* Remove the stale pid file */
		if(access(pid_file, F_OK) != -1) {
			if(remove(pid_file) != -1) {
				logprintf(LOG_DEBUG, "removed stale pid_file %s", pid_file);
			} else {
				logprintf(LOG_ERR, "could not remove stale pid file %s", pid_file);
			}
		}
	}

	if(webserver_enable == 1) {
		webserver_gc();
	}

	if(pth) {
		pthread_cancel(pth);
		pthread_join(pth, NULL);
	}

	threads_gc();
	settings_gc();
	options_gc();

	log_gc();
	sfree((void *)&progname);
	return 0;
}

int main(int argc, char **argv) {

	progname = malloc(16);
	if(!progname) {
		logprintf(LOG_ERR, "out of memory");
		exit(EXIT_FAILURE);
	}
	strcpy(progname, "zfsguru-daemon");

	if(geteuid() != 0) {
		printf("%s requires root priveliges in order to run\n", progname);
		sfree((void *)&progname);
		exit(EXIT_FAILURE);
	}

	/* Run main garbage collector when quiting the daemon */
	gc_attach(main_gc);

	/* Catch all exit signals for gc */
	gc_catch();
	
	loglevel = LOG_INFO;

	log_file_enable();
	log_shell_disable();

	settingsfile = malloc(strlen(SETTINGS_FILE)+1);
	if(!settingsfile) {
		logprintf(LOG_ERR, "out of memory");
		exit(EXIT_FAILURE);
	}
	strcpy(settingsfile, SETTINGS_FILE);

	struct options_t *options = NULL;

	char buffer[BUFFER_SIZE];
	int f, itmp, show_help = 0, show_version = 0, show_default = 0;
	char *stmp = NULL;
	char *args = NULL;

	memset(buffer, '\0', BUFFER_SIZE);

	options_add(&options, 'H', "help", no_value, 0, NULL);
	options_add(&options, 'V', "version", no_value, 0, NULL);
	options_add(&options, 'D', "nodaemon", no_value, 0, NULL);
	options_add(&options, 'S', "settings", has_value, 0, NULL);

	while(1) {
		int c;
		c = options_parse(&options, argc, argv, 1, &args);
		if(c == -1)
			break;
		if(c == -2) {
			show_help = 1;
			break;
		}
		switch(c) {
			case 'H':
				show_help = 1;
			break;
			case 'V':
				show_version = 1;
			break;
			case 'S':
				if(access(args, F_OK) != -1) {
					settingsfile = realloc(settingsfile, strlen(args)+1);
					if(!settingsfile) {
						logprintf(LOG_ERR, "out of memory");
						exit(EXIT_FAILURE);
					}
					strcpy(settingsfile, args);
					settings_set_file(args);
				} else {
					fprintf(stderr, "%s: the settings file %s does not exists\n", progname, args);
					exit(EXIT_FAILURE);
				}
			break;
			case 'D':
				nodaemon=1;
			break;
			default:
				show_default = 1;
			break;
		}
	}
	options_delete(options);

	if(show_help) {
		printf("Usage: %s [options]\n", progname);
		printf("\t -H --help\t\tdisplay usage summary\n");
		printf("\t -V --version\t\tdisplay version\n");
		printf("\t -S --settings\t\tsettings file\n");
		printf("\t -D --nodaemon\t\tdo not daemonize and\n");
		printf("\t\t\t\tshow debug information\n");
		goto clear;
	}
	if(show_version) {
		printf("%s version %s, commit %s\n", progname, VERSION, HASH);
		goto clear;
	}
	if(show_default) {
		printf("Usage: %s [options]\n", progname);
		goto clear;
	}

	if(access(settingsfile, F_OK) != -1) {
		if(settings_read() != 0) {
			goto clear;
		}
	}

	settings_find_number("webserver-enable", &webserver_enable);

	if(settings_find_string("pid-file", &pid_file) != 0) {
		pid_file = realloc(pid_file, strlen(PID_FILE)+1);
		if(!pid_file) {
			logprintf(LOG_ERR, "out of memory");
			exit(EXIT_FAILURE);
		}
		strcpy(pid_file, PID_FILE);
	}

	if((f = open(pid_file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR)) != -1) {
		if(read(f, buffer, BUFFER_SIZE) != -1) {
			//If the file is empty, create a new process
			strcat(buffer, "\0");
			if(!atoi(buffer)) {
				running = 0;
			} else {
				//Check if the process is running
				kill(atoi(buffer), 0);
				//If not, create a new process
				if(errno == ESRCH) {
					running = 0;
				}
			}
		}
	} else {
		logprintf(LOG_ERR, "could not open / create pid_file %s", pid_file);
		goto clear;
	}
	close(f);

	if(settings_find_number("log-level", &itmp) == 0) {
		itmp += 2;
		log_level_set(itmp);
	}

	if(settings_find_string("log-file", &stmp) == 0) {
		log_file_set(stmp);
	}

	logprintf(LOG_INFO, "version %s, commit %s", VERSION, HASH);

	if(nodaemon == 1 || running == 1) {
		log_file_disable();
		log_shell_enable();
		log_level_set(LOG_DEBUG);
	}

	if(running == 1) {
		nodaemon=1;
		logprintf(LOG_NOTICE, "already active (pid %d)", atoi(buffer));
		log_level_set(LOG_NOTICE);
		log_shell_disable();
		goto clear;
	}

	if(nodaemon == 0) {
		daemonize();
	} else {
		save_pid(getpid());
	}

	/* Start threads library that keeps track of all threads used */
	pthread_create(&pth, NULL, &threads_start, (void *)NULL);

	/* Register a seperate thread for the webserver */
	if(webserver_enable == 1 && runmode == 1) {
		threads_register("webserver daemon", &webserver_start, (void *)NULL);
	}
	
	while(1) {
		sleep(1);
	}

clear:
	if(nodaemon == 0) {
		log_level_set(LOG_NOTICE);
		log_shell_disable();
	}
	main_gc();
	gc_clear();
	return EXIT_FAILURE;
}
