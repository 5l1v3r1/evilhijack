/*
 * Copyright (c) 2018, Shawn Webb
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials
 *      provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <fcntl.h>

#include <hijack.h>
#include <infect.h>

#include "evilhijack.h"

void
usage(char *name, int err)
{

	fprintf(stderr, "USAGE: %s -p pid -i inject -s so -f func\n",
	    name);
	exit(err);
}

int
main(int argc, char *argv[])
{
	unsigned long addr, mapping, pltgot_addr;
	char *inject, *so, *targetfunc;
	int capsicum, ch, fd;
	FUNC *func, *funcs;
	RTLD_SYM *sym;
	struct stat sb;
	void *map, *p1;
	HIJACK *ctx;
	pid_t pid;

	pid = -1;
	capsicum = 0;
	while ((ch = getopt(argc, argv, "ci:f:p:s:")) != -1) {
		switch (ch) {
		case 'c':
			capsicum++;
			break;
		case 'i':
			inject = optarg;
			break;
		case 'f':
			targetfunc = optarg;
			break;
		case 'p':
			if (sscanf(optarg, "%d", &pid) != 1)
				usage(argv[0], 1);
			break;
		case 's':
			so = optarg;
			break;
		default:
			usage(argv[0], 0);
		}
	}

	if (inject == NULL)
		usage(argv[0], 1);
	if (targetfunc == NULL)
		usage(argv[0], 1);
	if (pid == -1)
		usage(argv[0], 1);
	if (so == NULL)
		usage(argv[0], 1);

	do_infect(pid, capsicum, inject, so, targetfunc);

	return (0);
}
