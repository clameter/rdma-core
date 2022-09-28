/*
 * Command line Interface
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

#include "interfaces.h"
#include "multicast.h"
#include "logging.h"
#include "cli.h"

#include <unistd.h>

/*
 * Implementation of a console for ib2roce with commands that can be registered
 */

#define MAX_CONCOMS 30

static struct concom {
	const char *name;
	bool prompt;
	int parameters;
	const char *description;
	void (*callback)(FILE *out, char *parameters);
} concoms[MAX_CONCOMS];

static int nr_concoms;

void register_concom(const char *name, bool prompt, int parameters, const char *text, void (*callback)(FILE *out, char *parameters))
{
	struct concom *c = concoms + nr_concoms;

	if (nr_concoms == MAX_CONCOMS - 1)
		panic("Too many console commands limit is %d\n", MAX_CONCOMS);

	c->name = name;
	c->prompt = prompt;
	c->parameters = parameters;
	c->description = text;
	c->callback = callback;

	nr_concoms++;
}

static void help(FILE *out, char *parameters)
{
	struct concom * cc;

	fprintf(out, "List of ib2roce console commands:\n");
	fprintf(out, "Command		Description\n");
	fprintf(out, "----------------------------------------\n");

	for(cc = concoms; cc->name; cc++) {
		fprintf(out, "%-16s%s\n", cc->name, cc->description);
	}
}

static void exitcmd(FILE *out, char *parameters)
{
	terminate(0);
}

static void prompt(void *private)
{
	printf("ib2roce-$ ");
	fflush(stdout);
}

static void console_input(void *private)
{
	struct concom * cc;
	char in[80];
	int ret;
	char *p;
	unsigned len;
	FILE *out = stdout;

	ret = read(STDIN_FILENO, in, sizeof(in));

	if (ret == 0) {
		printf("\n");
		terminate(0);
		return;
	}

	if (ret < 0) {
		printf("Console Input Error: %s\n", errname());
		goto out;
	}

	if (ret < 1 || in[0] == '#' || in[0] == '\n' || in[0] <= ' ')
		goto out;

	if (in[ret - 1] == '\n')
		in[ret - 1] = 0;

	for (p = in; *p; p++)
	{
		if (*p < ' ') {
			printf("\nControl Character %d at position %ld\n", *p, p - in);
			goto out;
		}
	}

	p = index(in, ' ');
	if (p)
		*p++ = 0;

	len = strlen(in);

	for(cc = concoms; cc->name; cc++) {
		if (strncasecmp(in, cc->name, len) == 0) {

			if (p && !cc->parameters) {
				fprintf(out, "Command does not allow parameters\n");
				goto out;
			}

			cc->callback(out, p);

			if (!cc->prompt)
				return;

			goto out;
		}
	};
	printf("Command \"%s\" not found. Try \"help\".\n", in);
out:
	prompt(NULL);
}

/* Only called if ib2roce is in the foreground */
void concom_init(void)
{
	register_concom("help",	true,	0,	"Print a list of commands",			help );
	register_concom("quit",	false,	0,	"Terminate ib2roce",				exitcmd);

	register_callback(console_input, STDIN_FILENO, NULL);
	add_event(timestamp() + seconds(2), prompt, NULL, "Console Prompt");
}

/*
 * Process command line options
 */

#define MAX_OPTS 30

/* What is passed to getopt_long */
static struct option opts[MAX_OPTS];

int nr_opts;

struct opts_data {
	void (*callback)(char *optarg);
	const char *description;
	const char *pardesc;
	struct option *opt;
} opts_datas[128];

void register_option(const char  *name, int has_arg, const char x, void (*callback)(char *optarg),
	const char *pardesc, const char *description)
{
	struct option *o;
	struct opts_data *od = opts_datas + x;

	if (x <= 0 || od->description)
		panic("Cannot add command line option '%c' = %d\n",x, x);

	o = opts + nr_opts;

	o->name = name;
	o->has_arg = has_arg;
	o->flag = NULL;
	o->val = x;
	od->callback = callback;
	od->description = description;
	od->pardesc = pardesc;
	od->opt = o;

	nr_opts++;
}

static void help_opt(char *);

void parse_options(int argc, char **argv)
{
	char opt_string[300];
	char *p;
	int op;
	int i;

	/* Compose opt_string from opts */
	p = opt_string;
	for(i = 0; i < 128; i++) {
		struct opts_data *od = opts_datas + i;
		struct option *o = od->opt;

		if (!od->description)
			continue;

		*p++ = i;
		if (o->has_arg != no_argument)
			*p++ = ':';
		if (o->has_arg == optional_argument)
			*p++ = ':';

		*p = 0;
	}

	while ((op = getopt_long(argc, argv, opt_string,
					opts, NULL)) != -1) {
		if (!optarg && argv[optind] && argv[optind][0] != '-') {
			optarg = argv[optind];
			optind++;
		}
		if (op != '?' && opts_datas[op].callback)

			opts_datas[op].callback(optarg);
		else
			help_opt(NULL);
	}
}

/*
 * Read settings from a configuration file
 */
static void readconfig(char *file)
{
	char *line = NULL;
	size_t chars = 0;
	FILE *f = fopen(file, "r");

	if (!f)
		panic("Config file %s not found:%s\n", file, errname());

	while (getline(&line, &chars, f) > 0) {
		char *p = line;
		char *q, *optarg;
		struct option *o;

		while (isspace(*p))
			p++;

		if (!isalpha(*p))
			goto skip;

		q = p;
		while (isalpha(*p))
			p++;

		*p++ = 0;

		optarg = p;
		while (!isspace(*p))
			p++;

		*p = 0;
		for(o = opts; o->name; o++)
			if (strcasecmp(o->name, q) == 0) {
				struct opts_data *od = opts_datas + o->val;

				od->callback(optarg);
				goto skip;
			}

		fprintf(stderr, "Unknown option: %s %s\n", q, optarg);
		exit(1);
skip:
		free(line);
		line = NULL;
		chars = 0;
	}
	fclose(f);
}

static void help_opt(char *optarg)
{
	int i;

	printf("ib2roce " VERSION " Christoph Lameter <cl@linux.com>\n");
	printf("Usage: ib2roce [<option>] ... \n");

	for(i = 0; i < 128; i++) {
		struct opts_data *od = opts_datas + i;
		struct option *o = od->opt;
		char buffer[60];

		if (!od->description)
			continue;

		snprintf(buffer, sizeof(buffer), "-%c|--%s %s ", i, o->name, od->pardesc? od->pardesc : " ");
		printf("%-50s %s\n", buffer, od->description);
	}
	exit(1);
}

static void enable_opt(char *optarg)
{
	enable(stdout, optarg, true);
}

static void disable_opt(char *optarg)
{
	enable(stdout, optarg, false);
}

__attribute__((constructor))
static void opts_init(void)
{
	register_option("config", required_argument, 'c', readconfig, "<file>", "Read config from file");
	register_option("enable", optional_argument, 'e', enable_opt, "<option>[=<value>]",
		       "Setup up additional options and features");
	register_option("disable", required_argument, 'y', disable_opt,"<option>",
			"Disable feature");
	register_option("help", no_argument, 'h', help_opt, NULL, "Show these instructions");
}



/*
 * Global options that can be enabled/disabled from the command line or from the console
 */

#define MAX_ENABLE 30

/* Table of options that can be set via -e option[=value] */
struct enable_option {
	const char *id;
	bool runtime;		/* Is it changeable at runtime? */
	bool *bool_flag;
	int *int_flag;
	const char *on_value;
	const char *off_value;
	void (*callback)(void);
	const char *description;
} enable_table[MAX_ENABLE];

static int nr_enable_options;

void enable(FILE *out, char *option, bool enable)
{
	char *name;
	const char *value = NULL;
	char *r;
	int i;
	struct enable_option *eo;

	if (!option || !option[0]) {
		fprintf(out, "List of available options that can be enabled\n");
		fprintf(out, "Setting\t\tType\tActive\tDescription\n");
		fprintf(out, "----------------------------------------------------------------\n");
		for(i = 0; enable_table[i].id; i++) {
			char state[10];

			eo = enable_table + i;

			if (eo->bool_flag) {
				if (*eo->bool_flag)
					strcpy(state, "on");
				else
					strcpy(state, "off");
			} else
				snprintf(state, 10, "%d", *eo->int_flag);

			fprintf(out, "%-14s\t%s\t%s\t%s\n", eo->id, eo->bool_flag ? "bool" : "int", state, eo->description);
		}
		return;
	}

	r = index(option, '=');
	if (!r)
		r = index(option, ' ');

	if (!r) {
		name = option;
	} else {
		*r = 0;
		name = option;
		value = r + 1;
	}

	for(i = 0; enable_table[i].id; i++) {
		if (strncasecmp(name, enable_table[i].id, strlen(name)) == 0)
			goto got_it;
	}
	fprintf(out, "Unknown option %s\n", name);
	return;

got_it:
	eo = enable_table + i;
	if (!eo->runtime && (i2r[ROCE].context || i2r[INFINIBAND].context)) {
		fprintf(out, "Cannot change option \"%s\" at runtime\n", option);
		return;
	}
	if (!value) {
		if (enable)
			value = eo->on_value;
		else
			value = eo->off_value;
	}

	if (eo->bool_flag) {
		if (strcasecmp(value, "on") == 0 ||
			strcasecmp(value, "enable") == 0 ||
			strcasecmp(value, "1") == 0)
				*eo->bool_flag = true;
		else
		if (strcasecmp(value, "off") == 0 ||
			strcasecmp(value, "disable") == 0 ||
			strcasecmp(value, "0") == 0)
				*eo->bool_flag = false;
		else {
			fprintf(out, "Unknown bool value %s for option %s\n", value, name);
			return;
		}
	} else
	if (eo->int_flag)
		*eo->int_flag = atoi(value);
	else
		panic("object type unknown\n");

	if (eo->callback)
		eo->callback();
}

void register_enable(const char *id, bool runtime, bool  *bool_flag, int *int_flag, const char *on_value, const char *off_value, void (*callback)(void), const char *description)
{
	struct enable_option *c = enable_table + nr_enable_options;

	if (nr_enable_options == MAX_ENABLE)
		panic("Too many console commands limit is %d\n", MAX_CONCOMS);

	c->id = id;
	c->runtime = runtime;
	c->bool_flag = bool_flag;
	c->int_flag = int_flag;
	c->on_value = on_value;
	c->off_value = off_value;
	c->callback = callback;
	c->description = description;

	nr_enable_options++;
}

static void enablecmd(FILE *out, char *parameters) {
	enable(out, parameters, true);
}

static void disablecmd(FILE *out, char *parameters) {
	enable(out, parameters, false);
}

__attribute__((constructor))
static void enable_init(void)
{
	/* Integration into  the console */
	register_concom("disable", true, 1, "Disable optional features", disablecmd);
	register_concom("enable", true,	1, "Setup optional features and list them", enablecmd);
}


