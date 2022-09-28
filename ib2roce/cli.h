#ifndef IB2ROCE_CLI
#define IB2ROCE_CLI
/*
 * Command Line support
 *
 * (C) 2021-2022 Christoph Lameter <cl@linux.com>
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * $Author: Christoph Lameter [cl@linux.com]$
 *
 */

#include <stdbool.h>
#include <getopt.h>

#define VERSION "2022.0512"

/* Command registration for the CLI */
void register_concom(const char *name, bool prompt, int parameters, const char *text, void (*callback)(FILE *out, char *parameters));

/* Register options that can be enabled via the "enable" command on the CLI or on the command line */
void register_enable(const char *name, bool runtime, bool  *bool_flag, int *int_flag, const char *on_value, const char *off_value, void (*callback)(void), const char *description);

/* Register commandline options */
void register_option(const char  *name, int has_arg, const char x, void (*callback)(char *optarg), const char *pardesc, const char *description);

void enable(FILE *out, char *option, bool enable);

void parse_options(int argc, char **argv);

void concom_init(void);

#endif
