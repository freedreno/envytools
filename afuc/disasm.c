/*
 * Copyright (c) 2017 Rob Clark <robdclark@gmail.com>
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

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>

#include "afuc.h"
#include "rnn.h"
#include "rnndec.h"

static int gpuver;


static struct rnndeccontext *ctx;
static struct rnndb *db;
struct rnndomain *dom[2];

/* non-verbose mode should output something suitable to feed back into
 * assembler.. verbose mode has additional output useful for debugging
 * (like unexpected bits that are set)
 */
static bool verbose = false;

static void print_gpu_reg(uint32_t regbase)
{
	struct rnndomain *d = NULL;

	if (regbase < 0x100)
		return;

	if (rnndec_checkaddr(ctx, dom[0], regbase, 0))
		d = dom[0];
	else if (rnndec_checkaddr(ctx, dom[1], regbase, 0))
		d = dom[1];

	if (d) {
		struct rnndecaddrinfo *info = rnndec_decodeaddr(ctx, d, regbase, 0);
		if (info) {
			printf("\t; %s", info->name);
			free(info->name);
			free(info);
			return;
		}
	}
}

static void printc(const char *c, const char *fmt, ...)
{
	va_list args;
	printf("%s", c);
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	printf("%s", ctx->colors->reset);
}

#define printerr(fmt, ...) printc(ctx->colors->err, fmt, ##__VA_ARGS__)
#define printlbl(fmt, ...) printc(ctx->colors->btarg, fmt, ##__VA_ARGS__)

static void print_reg(unsigned reg)
{
// XXX seems like *reading* $00 --> literal zero??
// seems like read from $1c gives packet remaining len??
// $01 current packet header, writing to $01 triggers
// parsing header and jumping to appropriate handler.
	if (reg == 0x1c)
		printf("$rem");      /* remainding dwords in packet */
	else if (reg == 0x1d)
		printf("$addr");
	else if (reg == 0x1e)
		printf("$addr2");   // XXX
	else if (reg == 0x1f)
		printf("$data");
	else
		printf("$%02x", reg);
}

static void print_src(unsigned reg)
{
	print_reg(reg);
}

static void print_dst(unsigned reg)
{
	print_reg(reg);
}

static void print_alu_name(afuc_opc opc, uint32_t instr)
{
	if (opc == OPC_ADD) {
		printf("add ");
	} else if (opc == OPC_ADDHI) {
		printf("addhi ");
	} else if (opc == OPC_SUB) {
		printf("sub ");
	} else if (opc == OPC_SUBHI) {
		printf("subhi ");
	} else if (opc == OPC_AND) {
		printf("and ");
	} else if (opc == OPC_OR) {
		printf("or ");
	} else if (opc == OPC_XOR) {
		printf("xor ");
	} else if (opc == OPC_NOT) {
		printf("not ");
	} else if (opc == OPC_SHL) {
		printf("shl ");
	} else if (opc == OPC_USHR) {
		printf("ushr ");
	} else if (opc == OPC_ISHR) {
		printf("ishr ");
	} else if (opc == OPC_ROT) {
		printf("rot ");
	} else if (opc == OPC_MUL8) {
		printf("mul8 ");
	} else if (opc == OPC_MIN) {
		printf("min ");
	} else if (opc == OPC_MAX) {
		printf("max ");
	} else if (opc == OPC_CMP) {
		printf("cmp ");
	} else {
		printerr("[%08x]", instr);
		printf("  ; alu%02x ", opc);
	}
}

static char *getpm4(uint32_t id)
{
	return rnndec_decode_enum(ctx, "adreno_pm4_type3_packets", id);
}


static uint32_t label_offsets[0x512];
static int num_label_offsets;

static int label_idx(uint32_t offset, bool create)
{
	int i;
	for (i = 0; i < num_label_offsets; i++)
		if (offset == label_offsets[i])
			return i;
	if (!create)
		return -1;
	label_offsets[i] = offset;
	num_label_offsets = i+1;
	return i;
}


static uint32_t fxn_offsets[0x512];
static int num_fxn_offsets;

static int fxn_idx(uint32_t offset, bool create)
{
	int i;
	for (i = 0; i < num_fxn_offsets; i++)
		if (offset == fxn_offsets[i])
			return i;
	if (!create)
		return -1;
	fxn_offsets[i] = offset;
	num_fxn_offsets = i+1;
	return i;
}

static struct {
	uint32_t offset;
	uint32_t num_jump_labels;
	uint32_t jump_labels[256];
} jump_labels[1024];
int num_jump_labels;

static void add_jump_table_entry(uint32_t n, uint32_t offset)
{
	int i;

	if (n > 128) /* can't possibly be a PM4 PKT3.. */
		return;

	for (i = 0; i < num_jump_labels; i++)
		if (jump_labels[i].offset == offset)
			goto add_label;

	num_jump_labels = i + 1;
	jump_labels[i].offset = offset;
	jump_labels[i].num_jump_labels = 0;

add_label:
	jump_labels[i].jump_labels[jump_labels[i].num_jump_labels++] = n;
	assert(jump_labels[i].num_jump_labels < 256);
}

static int get_jump_table_entry(uint32_t offset)
{
	int i;

	for (i = 0; i < num_jump_labels; i++)
		if (jump_labels[i].offset == offset)
			return i;

	return -1;
}

static void disasm(uint32_t *buf, int sizedwords)
{
	uint32_t *instrs = buf;
	const int jmptbl_start = instrs[1];
	uint32_t *jmptbl = &buf[jmptbl_start];
	afuc_opc opc;
	bool flush;
	int i;


	/* parse jumptable: */
	for (i = 0; i < 0x7f; i++) {
		unsigned offset = jmptbl[i];
		unsigned n = i;// + CP_NOP;
		add_jump_table_entry(n, offset);
	}

	/* do a pre-pass to find instructions that are potential branch targets,
	 * and add labels for them:
	 */
	for (i = 0; i < jmptbl_start; i++) {
		afuc_instr *instr = (void *)&instrs[i];

		afuc_get_opc(instr, &opc, &flush);

		switch (opc) {
		case OPC_BRNEI:
		case OPC_BREQI:
		case OPC_BRNEB:
		case OPC_BREQB:
			label_idx(i + instr->br.ioff, true);
			break;
		case OPC_CALL:
			fxn_idx(instr->call.uoff, true);
			break;
		default:
			break;
		}
	}

	/* print instructions: */
	for (i = 0; i < jmptbl_start; i++) {
		int lidx, fidx, jump_label_idx;
		afuc_instr *instr = (void *)&instrs[i];
		afuc_opc opc;
		bool flush;

		afuc_get_opc(instr, &opc, &flush);

		lidx = label_idx(i, false);
		fidx = fxn_idx(i, false);
		jump_label_idx = get_jump_table_entry(i);

		if (jump_label_idx >= 0) {
			int j;
			printf("\n");
			for (j = 0; j < jump_labels[jump_label_idx].num_jump_labels; j++) {
				uint32_t jump_label = jump_labels[jump_label_idx].jump_labels[j];
				char *name = getpm4(jump_label);
				if (name) {
					printlbl("%s", name);
				} else {
					printlbl("UNKN%d", jump_label);
				}
				printf(":\n");
			}
		}

		if (fidx >= 0) {
			printlbl("f%02d", fidx);
			printf(":\n");
		}

		if (lidx >= 0) {
			printlbl(" l%02d", lidx);
			printf(": ");
		} else {
			printf("      ");
		}


		if (verbose) {
			printf("\t%04x: %08x  ", i, instrs[i]);
		} else {
			printf("  ");
		}

		if (flush)
			printf("(f)");

		switch (opc) {
		case OPC_NOP:

			if (instrs[i] != 0x0) {
				printerr("[%08x]", instrs[i]);
				printf("  ; ");
			}
			printf("nop");

			break;
		case OPC_ADD:
		case OPC_ADDHI:
		case OPC_SUB:
		case OPC_SUBHI:
		case OPC_AND:
		case OPC_OR:
		case OPC_XOR:
		case OPC_NOT:
		case OPC_SHL:
		case OPC_USHR:
		case OPC_ISHR:
		case OPC_ROT:
		case OPC_MUL8:
		case OPC_MIN:
		case OPC_MAX:
		case OPC_CMP: {
			bool src1 = true;

			if (opc == OPC_NOT)
				src1 = false;

			print_alu_name(opc, instrs[i]);
			print_dst(instr->alui.dst);
			printf(", ");
			if (src1) {
				print_src(instr->alui.src);
				printf(", ");
			}
			printf("0x%04x", instr->alui.uimm);
			print_gpu_reg(instr->alui.uimm);

			/* print out unexpected bits: */
			if (verbose) {
				if (instr->alui.src && !src1)
					printerr("  (src=%02x)", instr->alui.src);
			}

			break;
		}
		case OPC_MOVI:
			printf("mov ");
			print_dst(instr->movi.dst);
			printf(", 0x%04x", instr->movi.uimm);
			if (instr->movi.shift)
				printf(" << %u", instr->movi.shift);
			print_gpu_reg(instr->movi.uimm << instr->movi.shift);
			break;
		case OPC_ALU: {
			bool src1 = true;

			if (instr->alu.alu == OPC_NOT)
				src1 = false;

			/* special case mnemonics:
			 *   reading $00 seems to always yield zero, and so:
			 *      or $dst, $00, $src -> mov $dst, $src
			 *   Maybe add one for negate too, ie.
			 *      sub $dst, $00, $src ???
			 */
			if ((instr->alu.alu == OPC_OR) && !instr->alu.src1) {
				printf("mov ");
				src1 = false;
			} else {
				print_alu_name(instr->alu.alu, instrs[i]);
			}

			print_dst(instr->alu.dst);
			if (src1) {
				printf(", ");
				print_src(instr->alu.src1);
			}
			printf(", ");
			print_src(instr->alu.src2);

			/* print out unexpected bits: */
			if (verbose) {
				if (instr->alu.pad)
					printerr("  (pad=%03x)", instr->alu.pad);
				if (instr->alu.src1 && !src1)
					printerr("  (src1=%02x)", instr->alu.src1);
			}
			break;
		}
		case OPC_CWRITE:
		case OPC_CREAD: {

			if (opc == OPC_CWRITE) {
				printf("cwrite ");
			} else if (opc == OPC_CREAD) {
				printf("cread ");
			}

			print_src(instr->control.src1);
			printf(", ");
			print_src(instr->control.src2);
			printf(", 0x%x, 0x%03x", instr->control.flags, instr->control.uimm);
			break;
		}
		case OPC_BRNEI:
		case OPC_BREQI:
		case OPC_BRNEB:
		case OPC_BREQB: {
			unsigned off = i + instr->br.ioff;

			/* Since $00 reads back zero, it can be used as src for
			 * unconditional branches.  (This only really makes sense
			 * for the BREQB.. or possible BRNEI if imm==0.)
			 *
			 * If bit=0 then branch is taken if *all* bits are zero.
			 * Otherwise it is taken if bit (bit-1) is clear.
			 *
			 * Note the instruction after a jump/branch is executed
			 * regardless of whether branch is taken, so use nop or
			 * take that into account in code.
			 */
			if (instr->br.src || (opc != OPC_BRNEB)) {
				bool immed = false;

				if (opc == OPC_BRNEI) {
					printf("brne ");
					immed = true;
				} else if (opc == OPC_BREQI) {
					printf("breq ");
					immed = true;
				} else if (opc == OPC_BRNEB) {
					printf("brne ");
				} else if (opc == OPC_BREQB) {
					printf("breq ");
				}
				print_src(instr->br.src);
				if (immed) {
					printf(", 0x%x,", instr->br.bit_or_imm);
				} else {
					printf(", b%u,", instr->br.bit_or_imm);
				}
			} else {
				printf("jump");
				if (verbose && instr->br.bit_or_imm) {
					printerr("  (src=%03x, bit=%03x) ",
						instr->br.src, instr->br.bit_or_imm);
				}
			}

			printf(" #");
			printlbl("l%02d", label_idx(off, false));
			if (verbose)
				printf(" (#%d, %04x)", instr->br.ioff, off);
			break;
		}
		case OPC_CALL:
			printf("call #");
			printlbl("f%02d", fxn_idx(instr->call.uoff, false));
			if (verbose) {
				printf(" (%04x)", instr->call.uoff);
				if (instr->br.bit_or_imm || instr->br.src) {
					printerr("  (src=%03x, bit=%03x) ",
						instr->br.src, instr->br.bit_or_imm);
				}
			}
			break;
		case OPC_RET:
			printf("ret");
			break;
		case OPC_WIN:
			printf("waitin");
			if (verbose && instr->waitin.pad)
				printerr("  (pad=%x)", instr->waitin.pad);
			break;
		default:
			printerr("[%08x]", instrs[i]);
			printf("  ; op%02x ", opc);
			print_dst(instr->alui.dst);
			printf(", ");
			print_src(instr->alui.src);
			print_gpu_reg(instrs[i] & 0xffff);
			break;
		}
		printf("\n");
	}

	/* print jumptable: */
	if (verbose) {
		printf(";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;\n");
		printf("; JUMP TABLE\n");
		for (i = 0; i < 0x7f; i++) {
			int n = i;// + CP_NOP;
			uint32_t offset = jmptbl[i];
			char *name = getpm4(n);
			printf("%3d %02x: ", n, n);
			printf("%04x", offset);
			if (name) {
				printf("   ; %s", name);
			} else {
				printf("   ; UNKN%d", n);
			}
			printf("\n");
		}
	}
}

#define CHUNKSIZE 4096

static char * readfile(const char *path, int *sz)
{
	char *buf = NULL;
	int fd, ret, n = 0;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return NULL;

	while (1) {
		buf = realloc(buf, n + CHUNKSIZE);
		ret = read(fd, buf + n, CHUNKSIZE);
		if (ret < 0) {
			free(buf);
			*sz = 0;
			return NULL;
		} else if (ret < CHUNKSIZE) {
			n += ret;
			*sz = n;
			return buf;
		} else {
			n += CHUNKSIZE;
		}
	}
}

static void usage(void)
{
	fprintf(stderr, "Usage:\n"
			"\tdisasm [-g GPUVER] [-v] [-c] filename.asm\n"
			"\t\t-g - specify GPU version (5, etc)\n"
			"\t\t-c - use colors\n"
			"\t\t-v - verbose output\n"
		);
	exit(2);
}

int main(int argc, char **argv)
{
	uint32_t *buf;
	char *file, *name;
	bool colors = false;
	int sz, c;

	/* Argument parsing: */
	while ((c = getopt (argc, argv, "g:vc")) != -1) {
		switch (c) {
			case 'g':
				gpuver = atoi(optarg);
				break;
			case 'v':
				verbose = true;
				break;
			case 'c':
				colors = true;
				break;
			default:
				usage();
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "no file specified!\n");
		usage();
	}

	file = argv[optind];

	/* if gpu version not specified, infer from filename: */
	if (!gpuver) {
		if (strstr(file, "a5")) {
			gpuver = 5;
		}
	}

	switch (gpuver) {
	case 5:
		printf("; a5xx microcode\n");
		name = "A5XX";
		break;
	default:
		fprintf(stderr, "unknown GPU version!\n");
		usage();
	}

	rnn_init();
	db = rnn_newdb();

	ctx = rnndec_newcontext(db);
	ctx->colors = colors ? &envy_def_colors : &envy_null_colors;

	rnn_parsefile(db, "adreno.xml");
	dom[0] = rnn_finddomain(db, name);
	dom[1] = rnn_finddomain(db, "AXXX");

	buf = (uint32_t *)readfile(file, &sz);

	printf("; Disassembling microcode: %s\n", file);
	printf("; Version: %08x\n\n", buf[1]);
	disasm(&buf[1], sz/4 - 1);

	return 0;
}
