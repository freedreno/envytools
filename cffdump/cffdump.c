/*
 * Copyright (c) 2012 Rob Clark <robdclark@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>

#include "redump.h"
#include "disasm.h"
#include "script.h"
#include "io.h"
#include "rnnutil.h"
#include "pager.h"
#include "buffers.h"
#include "cffdec.h"

static struct cffdec_options options = {
	.gpu_id = 220,
};

static bool needs_wfi = false;
static bool is_blob = false;
static bool show_comp = false;
static int vertices;

static int handle_file(const char *filename, int start, int end, int draw);

static void print_usage(const char *name)
{
	printf("Usage: %s [OPTIONS]... FILE...\n", name);
	printf("    --verbose         - more verbose disassembly\n");
	printf("    --dump-shaders    - dump each shader to raw file\n");
	printf("    --no-color        - disable colorized output (default for non-console\n");
	printf("                        output)\n");
	printf("    --color           - enable colorized output (default for tty output)\n");
	printf("    --summary         - don't show individual register writes, but just show\n");
	printf("                        register values on draws\n");
	printf("    --allregs         - show all registers (including ones not written since\n");
	printf("                        previous draw) at each draw\n");
	printf("    --start N         - decode start frame number\n");
	printf("    --end N           - decode end frame number\n");
	printf("    --frame N         - decode specified frame number\n");
	printf("    --draw N          - decode specified draw number\n");
	printf("    --textures        - dump texture contents (if possible)\n");
	printf("    --script FILE     - run specified lua script to analyze state at draws\n");
	printf("    --query/-q REG    - query mode, dump only specified query registers on\n");
	printf("                        each draw; multiple --query/-q args can be given to\n");
	printf("                        dump multiple registers; register can be specified\n");
	printf("                        either by name or numeric offset\n");
	printf("    --disasm/-d       - combine with query mode, disassembles shader referenced\n");
	printf("                        by queried register\n");
	printf("    --help            - show this message\n");
}

int main(int argc, char **argv)
{
	int ret = -1, n = 1;
	int start = 0, end = 0x7ffffff, draw = -1;
	int interactive = isatty(STDOUT_FILENO);

	options.color = interactive;

	while (n < argc) {
		if (!strcmp(argv[n], "--verbose")) {
			disasm_set_debug(PRINT_RAW | EXPAND_REPEAT | PRINT_VERBOSE);
			n++;
			continue;
		}

		if (!strcmp(argv[n], "--show-compositor")) {
			show_comp = true;
			n++;
			continue;
		}

		if (!strcmp(argv[n], "--dump-shaders")) {
			options.dump_shaders = true;
			n++;
			continue;
		}

		if (!strcmp(argv[n], "--no-color")) {
			options.color = false;
			n++;
			continue;
		}

		if (!strcmp(argv[n], "--color")) {
			options.color = true;
			n++;
			continue;
		}

		if (!strcmp(argv[n], "--summary")) {
			options.summary = true;
			n++;
			continue;
		}

		if (!strcmp(argv[n], "--allregs")) {
			options.allregs = true;
			n++;
			continue;
		}

		if (!strcmp(argv[n], "--start")) {
			n++;
			start = atoi(argv[n]);
			n++;
			continue;
		}

		if (!strcmp(argv[n], "--end")) {
			n++;
			end = atoi(argv[n]);
			n++;
			continue;
		}

		if (!strcmp(argv[n], "--frame")) {
			n++;
			end = start = atoi(argv[n]);
			n++;
			continue;
		}

		if (!strcmp(argv[n], "--draw")) {
			n++;
			draw = atoi(argv[n]);
			n++;
			continue;
		}

		if (!strcmp(argv[n], "--textures")) {
			n++;
			options.dump_textures = true;
			continue;
		}

		if (!strcmp(argv[n], "--script")) {
			n++;
			options.script = argv[n];
			if (script_load(options.script)) {
				fprintf(stderr, "error loading %s\n", argv[n]);
				return 1;
			}
			n++;
			continue;
		}

		if (!strcmp(argv[n], "--query") ||
				!strcmp(argv[n], "-q")) {
			n++;
			options.querystrs = realloc(options.querystrs,
					(options.nquery + 1) * sizeof(*options.querystrs));
			options.querystrs[options.nquery] = argv[n];
			options.nquery++;
			n++;
			interactive = 0;
			continue;
		}

		if (!strcmp(argv[n], "--help")) {
			n++;
			print_usage(argv[0]);
			return 0;
		}

		break;
	}

	if (interactive) {
		pager_open();
	}

	while (n < argc) {
		ret = handle_file(argv[n], start, end, draw);
		if (ret) {
			fprintf(stderr, "error reading: %s\n", argv[n]);
			fprintf(stderr, "continuing..\n");
		}
		n++;
	}

	if (ret) {
		print_usage(argv[0]);
		return ret;
	}

	script_finish();

	if (interactive) {
		pager_close();
	}

	return 0;
}

static void parse_addr(uint32_t *buf, int sz, unsigned int *len, uint64_t *gpuaddr)
{
	*gpuaddr = buf[0];
	*len = buf[1];
	if (sz > 8)
		*gpuaddr |= ((uint64_t)(buf[2])) << 32;
}

static int handle_file(const char *filename, int start, int end, int draw)
{
	enum rd_sect_type type = RD_NONE;
	void *buf = NULL;
	struct io *io;
	int submit = 0, got_gpu_id = 0;
	int sz, ret = 0;
	bool needs_reset = false;
	bool skip = false;

	options.draw_filter = draw;

	cffdec_init(&options);

	printf("Reading %s...\n", filename);

	script_start_cmdstream(filename);

	if (!strcmp(filename, "-"))
		io = io_openfd(0);
	else
		io = io_open(filename);

	if (!io) {
		fprintf(stderr, "could not open: %s\n", filename);
		return -1;
	}

	struct {
		unsigned int len;
		uint64_t gpuaddr;
	} gpuaddr = {0};

	while (true) {
		uint32_t arr[2];

		ret = io_readn(io, arr, 8);
		if (ret <= 0)
			goto end;

		while ((arr[0] == 0xffffffff) && (arr[1] == 0xffffffff)) {
			ret = io_readn(io, arr, 8);
			if (ret <= 0)
				goto end;
		}

		type = arr[0];
		sz = arr[1];

		if (sz < 0) {
			ret = -1;
			goto end;
		}

		free(buf);

		needs_wfi = false;

		buf = malloc(sz + 1);
		((char *)buf)[sz] = '\0';
		ret = io_readn(io, buf, sz);
		if (ret < 0)
			goto end;

		switch(type) {
		case RD_TEST:
			printl(1, "test: %s\n", (char *)buf);
			break;
		case RD_CMD:
			is_blob = true;
			printl(2, "cmd: %s\n", (char *)buf);
			skip = false;
			if (!show_comp) {
				skip |= (strstr(buf, "fdperf") == buf);
				skip |= (strstr(buf, "chrome") == buf);
				skip |= (strstr(buf, "surfaceflinger") == buf);
				skip |= ((char *)buf)[0] == 'X';
			}
			break;
		case RD_VERT_SHADER:
			printl(2, "vertex shader:\n%s\n", (char *)buf);
			break;
		case RD_FRAG_SHADER:
			printl(2, "fragment shader:\n%s\n", (char *)buf);
			break;
		case RD_GPUADDR:
			if (needs_reset) {
				reset_buffers();
				needs_reset = false;
			}
			parse_addr(buf, sz, &gpuaddr.len, &gpuaddr.gpuaddr);
			break;
		case RD_BUFFER_CONTENTS:
			add_buffer(gpuaddr.gpuaddr, gpuaddr.len, buf);
			buf = NULL;
			break;
		case RD_CMDSTREAM_ADDR:
			if ((start <= submit) && (submit <= end)) {
				unsigned int sizedwords;
				uint64_t gpuaddr;
				parse_addr(buf, sz, &sizedwords, &gpuaddr);
				printl(2, "############################################################\n");
				printl(2, "cmdstream: %d dwords\n", sizedwords);
				if (!skip) {
					script_start_submit();
					dump_commands(hostptr(gpuaddr), sizedwords, 0);
					script_end_submit();
				}
				printl(2, "############################################################\n");
				printl(2, "vertices: %d\n", vertices);
			}
			needs_reset = true;
			submit++;
			break;
		case RD_GPU_ID:
			if (!got_gpu_id) {
				options.gpu_id = *((unsigned int *)buf);
				printl(2, "gpu_id: %d\n", options.gpu_id);
				cffdec_init(&options);
				got_gpu_id = 1;
			}
			break;
		default:
			break;
		}
	}

end:
	script_end_cmdstream();

	io_close(io);
	fflush(stdout);

	if (ret < 0) {
		printf("corrupt file\n");
	}
	return 0;
}
