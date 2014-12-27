/*
 * Copyright (C) 2010-2011 Marcin Kościelnicki <koriakin@0x04.net>
 * Copyright (C) 2011 Martin Peres <martin.peres@ensi-bourges.fr>
 * All Rights Reserved.
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
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include "rnn.h"
#include "rnndec.h"
#include "var.h"
#include "dis.h"
#include "util.h"
#include "nvhw.h"
#include "seq.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <getopt.h>

int sleep_disabled = 0;

struct i2c_ctx {
	int last;
	int aok;
	int wr;
	int bits;
	int b;
	int pend;
};

struct cctx {
	struct rnndeccontext *ctx;
	struct chipset_info chipset;
	uint64_t praminbase;
	uint64_t ramins;
	uint64_t fakechan;
	int i2cip;
	int hwsqip;
	uint32_t hwsqnext;
	uint32_t ctxpos;
	uint8_t hwsq[0x200];
	struct mpage **pages;
	int pagesnum, pagesmax;
	uint64_t bar0, bar0l, bar1, bar1l, bar2, bar2l;
	struct i2c_ctx i2cb[10];
	int crx0, crx1;
	struct {
		uint32_t len;
		uint32_t script[2048];
		enum {
			SEQ_NONE = 0,
			SEQ_PRINT,
			SEQ_SKIP,
		} action;
	} seq;
};

struct cctx *cctx = 0;
int cctxnum = 0, cctxmax = 0;

struct mpage {
	uint64_t tag;
	uint32_t contents[0x1000/4];
};

uint32_t *findmem (struct cctx *ctx, uint64_t addr) {
	int i;
	uint64_t tag = addr & ~0xfffull;
	for (i = 0; i < ctx->pagesnum; i++) {
		if (tag == ctx->pages[i]->tag)
			return &ctx->pages[i]->contents[(addr&0xfff)/4];
	}
	struct mpage *pg = calloc (sizeof *pg, 1);
	pg->tag = tag;
	ADDARRAY(ctx->pages, pg);
	return &pg->contents[(addr&0xfff)/4];
}

int i2c_bus_num (uint64_t addr) {
	switch (addr) {
		case 0xe138:
			return 0;
		case 0xe150:
			return 1;
		case 0xe168:
			return 2;
		case 0xe180:
			return 3;
		case 0xe254:
			return 4;
		case 0xe274:
			return 5;
		case 0xe764:
			return 6;
		case 0xe780:
			return 7;
		case 0xe79c:
			return 8;
		case 0xe7b8:
			return 9;
		default:
			return -1;
	}
}

void doi2cr (struct cctx *cc, struct i2c_ctx *ctx, int byte) {
	if (ctx->pend) {
		if (ctx->bits == 8) {
			if (byte & 2)
				printf ("- ");
			else
				printf ("+ ");
			if (!ctx->aok) {
				ctx->aok = 1;
				ctx->wr = !(ctx->b&1);
			}
			ctx->bits = 0;
			ctx->b = 0;
		} else {
			ctx->b <<= 1;
			ctx->b |= (byte & 2) >> 1;
			ctx->bits++;
			if (ctx->bits == 8) {
				printf ("<%02x", ctx->b);
			}
		}
		ctx->pend = 0;
	}
}

void doi2cw (struct cctx *cc, struct i2c_ctx *ctx, int byte) {
	if (!ctx->last)
		ctx->last = 7;
	if (!(byte & 1) && (ctx->last & 1)) {
		/* clock went low */
	}
	if ((byte & 1) && !(ctx->last & 1)) {
		if (ctx->pend) {
			printf ("\nI2C LOST!\n");
			doi2cr(cc, ctx, 0);
			ctx->pend = 0;
		}
		/* clock went high */
		if (ctx->bits == 8) {
			if (ctx->wr || !ctx->aok) {
				ctx->pend = 1;
			} else {
				if (byte & 2)
					printf ("- ");
				else
					printf ("+ ");
				ctx->bits = 0;
				ctx->b = 0;
			}
		} else {
			if (ctx->wr || !ctx->aok) {
				ctx->b <<= 1;
				ctx->b |= (byte & 2) >> 1;
				ctx->bits++;
				if (ctx->bits == 8) {
					printf (">%02x", ctx->b);
				}
			} else {
				ctx->pend = 1;
			}
		}
	}
	if ((byte & 1) && !(byte & 2) && (ctx->last & 2)) {
		/* data went low with high clock - start bit */
		printf ("START ");
		ctx->bits = 0;
		ctx->b = 0;
		ctx->aok = 0;
		ctx->wr = 0;
		ctx->pend = 0;
		sleep_disabled = 1;
	}
	if ((byte & 1) && (byte & 2) && !(ctx->last & 2)) {
		/* data went high with high clock - stop bit */
		printf ("STOP\n");
		cc->i2cip = -1;
		ctx->bits = 0;
		ctx->b = 0;
		ctx->aok = 0;
		ctx->wr = 0;
		ctx->pend = 0;
		sleep_disabled = 0;
	}
	ctx->last = byte;
}

int main(int argc, char **argv) {
	char *file = NULL;
	int c,use_colors=1;
	while ((c = getopt (argc, argv, "f:c")) != -1) {
		switch (c) {
			case 'f':{
				file = strdup(optarg);
				break;
			}
			case 'c':{
				use_colors = 0;
				break;
			}
			default:{
				break;
			}
		}
	}
	rnn_init();

	struct rnndb *db = rnn_newdb();
	rnn_parsefile (db, "nv_mmio.xml");
	rnn_prepdb (db);
	struct rnndomain *mmiodom = rnn_finddomain(db, "NV_MMIO");
	struct rnndomain *crdom = rnn_finddomain(db, "NV_CR");
	FILE *fin = (file==NULL) ? stdin : open_input(file);
	if (!fin) {
		fprintf (stderr, "Failed to open input file!\n");
		return 1;
	}

	char line[1024];
	int i;
	const struct disisa *ctx_isa = ed_getisa("ctx");
	struct varinfo *ctx_var_nv40 = varinfo_new(ctx_isa->vardata);
	struct varinfo *ctx_var_g80 = varinfo_new(ctx_isa->vardata);
	varinfo_set_variant(ctx_var_nv40, "nv40");
	varinfo_set_variant(ctx_var_g80, "g80");
	const struct disisa *hwsq_isa = ed_getisa("hwsq");
	struct varinfo *hwsq_var_nv17 = varinfo_new(hwsq_isa->vardata);
	struct varinfo *hwsq_var_nv41 = varinfo_new(hwsq_isa->vardata);
	struct varinfo *hwsq_var_g80 = varinfo_new(hwsq_isa->vardata);
	varinfo_set_variant(hwsq_var_nv17, "nv17");
	varinfo_set_variant(hwsq_var_nv41, "nv41");
	varinfo_set_variant(hwsq_var_g80, "g80");
	const struct envy_colors *colors = use_colors ? &envy_def_colors : &envy_null_colors;
	while (1) {
		/* yes, static buffer. but mmiotrace lines are bound to have sane length anyway. */
		if (!fgets(line, sizeof(line), fin))
			break;
		if (!strncmp(line, "PCIDEV ", 7)) {
			uint64_t bar[4], len[4], pciid;
			sscanf (line, "%*s %*s %"SCNx64" %*s %"SCNx64" %"SCNx64" %"SCNx64" %"SCNx64" %*s %*s %*s %"SCNx64" %"SCNx64" %"SCNx64" %"SCNx64"", &pciid, &bar[0], &bar[1], &bar[2], &bar[3], &len[0], &len[1], &len[2], &len[3]);
			if ((pciid >> 16) == 0x10de && bar[0] && (bar[0] & 0xf) == 0 && bar[1] && (bar[1] & 0x1) == 0x0) {
				struct cctx nc = { 0 };
				nc.bar0 = bar[0], nc.bar0l = len[0];
				nc.bar1 = bar[1], nc.bar1l = len[1];
				if (bar[2])
					nc.bar2 = bar[2], nc.bar2l = len[2];
				else
					nc.bar2 = bar[3], nc.bar2l = len[3];
				nc.bar0 &= ~0xf;
				nc.bar1 &= ~0xf;
				nc.bar2 &= ~0xf;
				nc.i2cip = -1;
				nc.ctx = rnndec_newcontext(db);
				nc.ctx->colors = colors;
				for (i = 0; i < 10; i++)
					nc.i2cb[i].last = 7;
				ADDARRAY(cctx, nc);
			}
			printf ("%s", line);
		} else if (!strncmp(line, "W ", 2) || !strncmp(line, "R ", 2)) {
			int skip = 0;
			static double timestamp, timestamp_old = 0;
			uint64_t addr, value;
			int width;
			int cci;
			sscanf (line, "%*s %d %lf %*d %"SCNx64" %"SCNx64, &width, &timestamp, &addr, &value);
			width *= 8;

			/* Add a SLEEP line when two mmio accesses are more distant than 100µs */
			if (!sleep_disabled && timestamp_old > 0 && (timestamp - timestamp_old) > 0.0001)
				printf("SLEEP %lfms\n", (timestamp - timestamp_old)*1000.0);
			timestamp_old = timestamp;

			for (cci = 0; cci < cctxnum; cci++) {
				struct cctx *cc = &cctx[cci];
				if (cc->bar0 && addr >= cc->bar0 && addr < cc->bar0+cc->bar0l) {
					addr -= cc->bar0;
					if (cc->hwsqip && addr != cc->hwsqnext) {
						struct varinfo *var = hwsq_var_nv17;
						if (cc->chipset.chipset >= 0x41)
							var = hwsq_var_nv41;
						if (cc->chipset.card_type == 0x50)
							var = hwsq_var_g80;
						envydis(hwsq_isa, stdout, cc->hwsq, 0, cc->hwsqnext & 0x3fc, var, 0, 0, 0, colors);
						cc->hwsqip = 0;
					}
					/* Seq */
					if (cc->seq.action == SEQ_SKIP && addr != 0x10a1c4) {
						cc->seq.action = SEQ_NONE;
					} else if (cc->seq.action == SEQ_PRINT && addr != 0x10a1c4) {
						seq_print(cc->seq.script, cc->seq.len);
						cc->seq.len = 0;
						cc->seq.action = SEQ_NONE;
					}

					if (addr == 0 && !cc->chipset.chipset) {
						parse_pmc_id(value, &cc->chipset);
						if (cc->chipset.chipset)
							rnndec_varaddvalue(cc->ctx, "chipset", cc->chipset.chipset);
					} else if (cc->chipset.card_type >= 0x50 && addr == 0x1700) {
						cc->praminbase = value << 16;
					} else if (cc->chipset.card_type == 0x50 && addr == 0x1704) {
						cc->fakechan = (value & 0xfffffff) << 12;
					} else if (cc->chipset.card_type == 0x50 && addr == 0x170c) {
						cc->ramins = (value & 0xffff) << 4;
					} else if (cc->chipset.card_type >= 0xc0 && addr == 0x1714) {
						cc->ramins = (value & 0xfffffff) << 12;
					} else if (addr == 0x6013d4) {
						cc->crx0 = value & 0xff;
					} else if (addr == 0x6033d4) {
						cc->crx1 = value & 0xff;
					} else if (addr == 0x6013d5) {
						struct rnndecaddrinfo *ai = rnndec_decodeaddr(cc->ctx, crdom, cc->crx0, line[0] == 'W');
						char *decoded_val = rnndec_decodeval(cc->ctx, ai->typeinfo, value, ai->width);
						printf ("[%d] %lf CRTC0 %c     0x%02x       0x%02"PRIx64" %s %s %s\n", cci, timestamp, line[0], cc->crx0, value, ai->name, line[0]=='W'?"<=":"=>", decoded_val);
						rnndec_free_decaddrinfo(ai);
						free(decoded_val);
						skip = 1;
					} else if (addr == 0x6033d5) {
						struct rnndecaddrinfo *ai = rnndec_decodeaddr(cc->ctx, crdom, cc->crx1, line[0] == 'W');
						char *decoded_val = rnndec_decodeval(cc->ctx, ai->typeinfo, value, ai->width);
						printf ("[%d] %lf CRTC1 %c     0x%02x       0x%02"PRIx64" %s %s %s\n", cci, timestamp, line[0], cc->crx1, value, ai->name, line[0]=='W'?"<=":"=>", decoded_val);
						rnndec_free_decaddrinfo(ai);
						free(decoded_val);
						skip = 1;
					} else if (cc->chipset.card_type >= 0x50 && (addr & 0xfff000) == 0xe000) {
						int bus = i2c_bus_num(addr);
						if (bus != -1) {
							if (cc->i2cip != bus) {
								if (cc->i2cip != -1)
									printf ("\n");
								struct rnndecaddrinfo *ai = rnndec_decodeaddr(cc->ctx, mmiodom, addr, line[0] == 'W');
								printf ("[%d] I2C      0x%06"PRIx64"            %s ", cci, addr, ai->name);
								rnndec_free_decaddrinfo(ai);
								cc->i2cip = bus;
							}
							if (line[0] == 'R') {
								doi2cr(cc, &cc->i2cb[bus], value);
							} else {
								doi2cw(cc, &cc->i2cb[bus], value);
							}
							skip = 1;
						}
					} else if ((addr & 0xfff000) == 0x9000 && (cc->i2cip != -1)) {
						/* ignore PTIMER meddling during I2C */
						skip = 1;
					} else if (addr == 0x1400 || addr == 0x80000 || (addr == cc->hwsqnext && cc->hwsqip)) {
						if (!cc->hwsqip) {
							struct rnndecaddrinfo *ai = rnndec_decodeaddr(cc->ctx, mmiodom, addr, line[0] == 'W');
							printf ("[%d] HWSQ     0x%06"PRIx64"            %s\n", cci, addr, ai->name);
							rnndec_free_decaddrinfo(ai);
						}
						cc->hwsq[(addr & 0x1fc) + 0] = value;
						cc->hwsq[(addr & 0x1fc) + 1] = value >> 8;
						cc->hwsq[(addr & 0x1fc) + 2] = value >> 16;
						cc->hwsq[(addr & 0x1fc) + 3] = value >> 24;
						cc->hwsqip = 1;
						cc->hwsqnext = addr + 4;
						skip = 1;
					} else if (addr == 0x10a1c4) {
						if (cc->seq.action == SEQ_NONE) {
							/* Crude test whether this vaguely looks like an opcode..
							 * print will do a more thorough check */
							if ((value & 0xfc00ffc0) == 0 && value != 0) {
								cc->seq.action = SEQ_PRINT;
							} else {
								cc->seq.action = SEQ_SKIP;
							}
						}

						if(cc->seq.action == SEQ_PRINT) {
							if (cc->seq.len < 2048) {
								cc->seq.script[cc->seq.len] = value;
								cc->seq.len++;
							} else {
								printf("[%d] PDAEMON  %06"PRIx64" Script too long, skipping\n", cci, addr);
								cc->seq.len = 0;
								cc->seq.action = SEQ_SKIP;
							}
						}
					} else if (addr == 0x400324 && cc->chipset.card_type >= 0x40 && cc->chipset.card_type <= 0x50) {
						cc->ctxpos = value;
					} else if (addr == 0x400328 && cc->chipset.card_type >= 0x40 && cc->chipset.card_type <= 0x50) {
						uint8_t param[4];
						param[0] = value;
						param[1] = value >> 8;
						param[2] = value >> 16;
						param[3] = value >> 24;
						struct rnndecaddrinfo *ai = rnndec_decodeaddr(cc->ctx, mmiodom, addr, line[0] == 'W');
						printf ("[%d] MMIO%d %c 0x%06"PRIx64" 0x%08"PRIx64" %s %s ", cci, width, line[0], addr, value, ai->name, line[0]=='W'?"<=":"=>");
						envydis(ctx_isa, stdout, param, cc->ctxpos, 1, (cc->chipset.card_type == 0x50 ? ctx_var_g80 : ctx_var_nv40), 0, 0, 0, colors);
						cc->ctxpos++;
						rnndec_free_decaddrinfo(ai);
						skip = 1;
					}
					if (!skip && (cc->i2cip != -1)) {
						printf ("\n");
						cc->i2cip = -1;
					}
					if (cc->chipset.card_type >= 0x50 && addr >= 0x700000 && addr < 0x800000) {
						addr -= 0x700000;
						addr += cc->praminbase;
						printf ("[%d] %lf, MEM%d %"PRIx64" %s %"PRIx64"\n", cci, timestamp, width, addr, line[0]=='W'?"<=":"=>", value);
						*findmem(cc, addr) = value;
					} else if (!skip) {
						struct rnndecaddrinfo *ai = rnndec_decodeaddr(cc->ctx, mmiodom, addr, line[0] == 'W');
						if (width == 32 && ai->width == 8) {
							/* 32-bit write to 8-bit location - split it up */
							int b;
							rnndec_free_decaddrinfo(ai);
							int cnt;
							for (b = 0; b < 4; b++) {
								struct rnndecaddrinfo *ai = rnndec_decodeaddr(cc->ctx, mmiodom, addr+b, line[0] == 'W');
								char *decoded_val = rnndec_decodeval(cc->ctx, ai->typeinfo, value >> b * 8 & 0xff, ai->width);
								if (b == 0) {
									printf ("[%d] %lf MMIO%d %c 0x%06"PRIx64" 0x%08"PRIx64" %n%s %s %s\n", cci, timestamp, width, line[0], addr, value, &cnt, ai->name, line[0]=='W'?"<=":"=>", decoded_val);
								} else {
									int c;
									for (c = 0; c < cnt; c++)
										printf(" ");
									printf ("%s %s %s\n", ai->name, line[0]=='W'?"<=":"=>", decoded_val);
								}
								rnndec_free_decaddrinfo(ai);
								free(decoded_val);
							}
						} else {
							char *decoded_val = rnndec_decodeval(cc->ctx, ai->typeinfo, value, ai->width);
							printf ("[%d] %lf MMIO%d %c 0x%06"PRIx64" 0x%08"PRIx64" %s %s %s\n", cci, timestamp, width, line[0], addr, value, ai->name, line[0]=='W'?"<=":"=>", decoded_val);
							free(ai->name);
							free(ai);
							free(decoded_val);
						}
					}
				} else if (cc->bar1 && addr >= cc->bar1 && addr < cc->bar1+cc->bar1l) {
					addr -= cc->bar1;
					printf ("[%d] %lf, FB%d %"PRIx64" %s %"PRIx64"\n", cci, timestamp, width, addr, line[0]=='W'?"<=":"=>", value);
				} else if (cc->bar2 && addr >= cc->bar2 && addr < cc->bar2+cc->bar2l) {
					addr -= cc->bar2;
					if (cc->chipset.card_type >= 0xc0) {
						uint64_t pd = *findmem(cc, cc->ramins + 0x200);
						uint64_t pt = *findmem(cc, pd + 4);
						pt &= 0xfffffff0;
						pt <<= 8;
						uint64_t pg = *findmem(cc, pt + (addr/0x1000) * 8);
						pg &= 0xfffffff0;
						pg <<= 8;
						pg += (addr&0xfff);
						*findmem(cc, pg) = value;
	//					printf ("%"PRIx64" %"PRIx64" %"PRIx64" %"PRIx64"\n", ramins, pd, pt, pg);
						printf ("[%d] %lf RAMIN%d %"PRIx64" %"PRIx64" %s %"PRIx64"\n", cci, timestamp, width, addr, pg, line[0]=='W'?"<=":"=>", value);
					} else if (cc->chipset.card_type == 0x50) {
						uint64_t paddr = addr;
						paddr += *findmem(cc, cc->fakechan + cc->ramins + 8);
						paddr += (uint64_t)(*findmem(cc, cc->fakechan + cc->ramins + 12) >> 24) << 32;
						uint64_t pt = *findmem(cc, cc->fakechan + (cc->chipset.chipset == 0x50 ? 0x1400 : 0x200) + ((paddr >> 29) << 3));
	//					printf ("%#"PRIx64" PT: %#"PRIx64" %#"PRIx64" ", paddr, fakechan + 0x200 + ((paddr >> 29) << 3), pt);
						uint32_t div = (pt & 2 ? 0x1000 : 0x10000);
						pt &= 0xfffff000;
						uint64_t pg = *findmem(cc, pt + ((paddr&0x1ffff000)/div) * 8);
						uint64_t pgh = *findmem(cc, pt + ((paddr&0x1ffff000)/div) * 8 + 4);
	//					printf ("PG: %#"PRIx64" %#"PRIx64"\n", pt + ((paddr&0x1ffff000)/div) * 8, pgh << 32 | pg);
						pg &= 0xfffff000;
						pg |= (pgh & 0xff) << 32;
						pg += (paddr & (div-1));
						*findmem(cc, pg) = value;
	//					printf ("%"PRIx64" %"PRIx64" %"PRIx64" %"PRIx64"\n", ramins, pd, pt, pg);
						printf ("[%d] %lf RAMIN%d %"PRIx64" %"PRIx64" %s %"PRIx64"\n", cci, timestamp, width, addr, pg, line[0]=='W'?"<=":"=>", value);
					} else {
						printf ("[%d] %lf RAMIN%d %"PRIx64" %s %"PRIx64"\n", cci, timestamp, width, addr, line[0]=='W'?"<=":"=>", value);
					}
				}
			}
		} else {
			printf ("%s", line);
		}
	}

	rnn_freedb(db);
	rnn_fini();

	return 0;
}
