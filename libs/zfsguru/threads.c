/*
	Copyright (C) 2013 CurlyMo

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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "threads.h"
#include "common.h"
#include "log.h"

unsigned short thread_loop = 1;
unsigned short thread_count = 0;
unsigned short thread_running = 0;

void threads_register(const char *id, void *(*function)(void *param), void *param) {
	struct threads_t *tnode = malloc(sizeof(struct threads_t));
	if(!tnode) {
		logprintf(LOG_ERR, "out of memory");
		exit(EXIT_FAILURE);
	}
	tnode->function = function;
	tnode->running = 0;
	tnode->id = malloc(strlen(id)+1);
	if(!tnode->id) {
		logprintf(LOG_ERR, "out of memory");
		exit(EXIT_FAILURE);
	}
	strcpy(tnode->id, id);
	tnode->param = param;
	tnode->next = threads;
	threads = tnode;
	
	thread_count++;
}

void *threads_start(void *param) {
	struct threads_t *tmp_threads = NULL;
	while(thread_loop) {
		if(thread_count > thread_running) {
			tmp_threads = threads;
			while(tmp_threads) {
				if(tmp_threads->running == 0) {
					pthread_create(&tmp_threads->pth, NULL, tmp_threads->function, (void *)tmp_threads->param);
					tmp_threads->running = 1;		
					thread_running++;
					if(thread_running == 1) {
						logprintf(LOG_DEBUG, "new thread %s, %d thread running", tmp_threads->id, thread_running);
					} else {
						logprintf(LOG_DEBUG, "new thread %s, %d threads running", tmp_threads->id, thread_running);
					}
				}
				tmp_threads = tmp_threads->next;
			}
		}
		usleep(5000);
	}
	return (void *)NULL;
}

int threads_gc(void) {
	thread_loop = 0;

	struct threads_t *tmp_threads = threads;
	while(tmp_threads) {
		if(tmp_threads->running == 1) {
			tmp_threads->running = 0;
			thread_running--;
			pthread_cancel(tmp_threads->pth);
			pthread_join(tmp_threads->pth, NULL);
			if(thread_running == 1) {
				logprintf(LOG_DEBUG, "stopped thread %s, %d thread running", tmp_threads->id, thread_running);
			} else {
				logprintf(LOG_DEBUG, "stopped thread %s, %d threads running", tmp_threads->id, thread_running);
			}
		}
		tmp_threads = tmp_threads->next;
	}

	struct threads_t *ttmp;
	while(threads) {
		ttmp = threads;
		sfree((void *)&ttmp->id);
		thread_count--;
		threads = threads->next;
		sfree((void *)&ttmp);
	}
	sfree((void *)&threads);

	logprintf(LOG_DEBUG, "garbage collected threads library");
	return EXIT_SUCCESS;
}
