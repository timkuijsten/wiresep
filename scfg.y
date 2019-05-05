/*
 * Copyright (c) 2018, 2019 Tim Kuijsten
 *
 * Permission to use, copy, modify, and distribute this software for any purpose
 * with or without fee is hereby granted, provided that the above copyright
 * notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

%{
#include <ctype.h>
#include <err.h>
#include <stdio.h>

#include "scfg.h"

int yydebug = 0;

typedef struct {
	union {
		struct scfge *scfge;
		char *str;
		char **strv;
	};
	int lineno;
	int colno;
} YYSTYPE;

extern int verbose;

/* Should be assigned externally. */
int yyd = -1;

/* Use a stream internally for easy look-ahead using ungetc. */
static FILE *yyfp = NULL;
static int curcol;
static int curline;

/*
 * Global config vector that holds entries.
 */
static struct scfge *cfgroot, *cfgparent, *cfglast;

static int allocated = 0;

static void addentry(struct scfge *, struct scfge *);
static void addstr(struct scfge *, const char *str);
static struct scfge *allocentry(void);
static void freeentry(struct scfge **);

static char *getstr(FILE *);
static char *appendc(char *, char, size_t *);

void
yyerror(char *msg)
{
        warnx("%s at line %d, column %d", msg, curline, curcol);
}

%}

%start grammar

%token <str> STRING
%token OBRACE CBRACE EOS

%type <scfge> grammar entryv

%%

grammar:	/* new */ {
		if (cfgroot == NULL)
			scfg = cfgroot = cfgparent = allocentry();
	}
	| grammar {
		$$ = cfglast = allocentry();
	} strv entryv EOS {

		if ($2->strvsize == 0 && $2->entryvsize == 0) {
			freeentry(&$2);
			$$ = NULL;
		} else {
			addentry(cfgparent, $2);
			$$ = $2;
		}
	}
	;
strv:	/* optional */
	| strv STRING {
		addstr(cfglast, $2);
	}
	;
entryv:	/* optional */ { $$ = NULL; }
	| OBRACE {
		/* descend */
		$$ = cfgparent;
		cfgparent = cfglast;
	} grammar CBRACE {
		/* ascend */
		cfgparent = $2;

		/* return entryv or null */
		$$ = $3;
	}
	;

%%
int
yylex(void)
{
	extern int error;
	static int prevtoken = 0, nexttoken = 0;

	if (yyd == -1) {
		yyerror("no descriptor open");
		return -1;
	}

	/* Init on first call. */
	if (yyfp == NULL) {
		curcol = 0;
		curline = 1;
		if ((yyfp = fdopen(yyd, "r")) == NULL)
				err(1, "%s: fdopen", __func__);
	}

	/*
	 * Maybe the next token was cached because of an implicit
	 * end-of-statement.
	 */

	if (nexttoken > 0) {
		prevtoken = nexttoken;
		nexttoken = 0;
		return prevtoken;
	}

	/* Expect yylval be either NULL or initialized in a previous call. */

	free(yylval.str);

	while ((yylval.str = getstr(yyfp)) != NULL) {
		yylval.lineno = curline;
		yylval.colno = curcol;

		if (strcmp(yylval.str, "\n") == 0) {
			prevtoken = EOS;
			return EOS;
		} else if (strcmp(yylval.str, ";") == 0) {
			prevtoken = EOS;
			return EOS;
		} else if (strcmp(yylval.str, "{") == 0) {
			prevtoken = OBRACE;
			return OBRACE;
		} else if (strcmp(yylval.str, "}") == 0) {
			/*
			 * Return end-of-statement if not set explicitly after
			 * the last entry in a entryv.
			 */
			if (prevtoken != EOS) {
				nexttoken = CBRACE;
				prevtoken = EOS;
				return EOS;
			}
			prevtoken = CBRACE;
			return CBRACE;
		} else {
			prevtoken = STRING;
			return STRING;
		}
	}

	if (ferror(yyfp) != 0)
		err(1, "yyfp error");

	if (feof(yyfp) == 0)
		errx(1, "yyfp still open");

	/* Cleanup and signal the end. */
	yyfp = NULL;
	return 0;
}

/*
 * Parse input for strings.
 *
 * A string is a concatenation of non-null and non-control characters. Strings
 * are expected to be separated by blanks, newlines or ';'. A string may
 * only contain spaces if it is enclosed in double quotes or if every space is
 * escaped using a '\' character.
 *
 * The following special characters outside a string are returned as null-
 * terminated character strings:
 * 	'{'
 * 	'}'
 * 	'\n'
 * 	';'
 *
 * A '#' outside of a string ignores all characters up to the first newline.
 *
 * Any control characters or '\0' outside of a string, except for '\t' and '\n'
 * are considered illegal.
 *
 * Return a pointer to a new string on success or NULL on end-of-file or error.
 */
static char *
getstr(FILE *stream)
{
	enum states { S, STR, QSTR, ESCQ, ESCS, COMMENT };
	size_t len;
	int c, state;
	char *r;

	state = S;
	r = NULL;
	len = 0;
	while ((c = fgetc(stream)) != EOF) {

		/* Track position in file for debugging. */

		if (c == '\n') {
			curline++;
			curcol = 0;
		}

		curcol++;

		switch (state) {
		case S:
			if (isblank(c)) {
				/* Swallow any preceding blanks. */

			} else if (c == ';' || c == '\n' || c == '{'
					|| c == '}') {
				/* These characters are strings by themselves. */

				r = appendc(r, c, &len);
				goto end;

			} else if (c == '\\') {
				state = ESCS;

			} else if (c == '"') {
				state = QSTR;

			} else if (c == '#') {
				state = COMMENT;

			} else if (c != '\0' && !iscntrl(c)) {
				r = appendc(r, c, &len);
				state = STR;

			} else {
				warnx("unexpected char %d at %d,%d", c, curline, curcol);
				goto err;

			}
			break;
		case STR:
			if (isblank(c)) {
				/* End of string. */
				goto end;

			} else if (c == ';' || c == '\n' || c == '{'
					|| c == '}') {
				/*
				 * End of string. Finish this string and leave
				 * the newline or curly brace for the next run
				 * because these are special strings by
				 * themselves.
				 */

				ungetc(c, stream);

				/* don't count the characater twice */

				if (c == '\n')
					curline--;
				else
					curcol--;

				goto end;

			} else if (c == '\\') {
				state = ESCS;

			} else if (c != '\0' && !iscntrl(c)) {
				r = appendc(r, c, &len);

			} else {
				warnx("unexpected char %d at %d,%d", c, curline, curcol);
				goto err;

			}
			break;
		case QSTR:
			if (c == '\\') {
				state = ESCQ;

			} else if (c == '"') {
				goto end;

			} else if (c != '\0' && !iscntrl(c)) {
				r = appendc(r, c, &len);

			} else {
				warnx("unexpected char %d at %d,%d", c, curline, curcol);
				goto err;

			}
			break;
		case ESCS:
			if (c == '\0' || iscntrl(c)) {
				warnx("unexpected char %d at %d,%d", c, curline, curcol);
				goto err;
			}

			r = appendc(r, c, &len);
			state = STR;
			break;
		case ESCQ:
			if (c == '\0' || iscntrl(c)) {
				warnx("unexpected char %d at %d,%d", c, curline, curcol);
				goto err;
			}

			r = appendc(r, c, &len);
			state = QSTR;
			break;
		case COMMENT:
			if (c == '\t') {
				/* swallow the tab control-character */
			} else if (c == '\n') {
				/*
				 * End of comment, a newline is a string by
				 * itself.
				 */

				r = appendc(r, c, &len);
				goto end;
			} else if (c == '\0' || iscntrl(c)) {
				warnx("unexpected char %d at %d,%d", c, curline, curcol);
				goto err;
			}

			break;
		}
	}

err:
	free(r);
	r = NULL;
end:
	if (verbose > 3)
		warnx("returning %lu \"%s\"", r == NULL ? 0 : strlen(r), r == NULL ? "NULL" : r);
	return r;
}

/*
 * Append a character to a dynamically allocated string.
 *
 * Return a pointer to the possibly relocated string on success, or exit on
 * error.
 */
static char *
appendc(char *str, char c, size_t *len)
{
		/* account for terminating null byte */
		str = realloc(str, *len + 2);
		if (str == NULL)
			err(1, "%s: realloc", __func__);

		str[*len] = c;
		str[*len + 1] = 0;
		(*len)++;

		return str;
}

/* Add an entry to an entry vector. */
static void
addentry(struct scfge *parent, struct scfge *child)
{
	parent->entryv = reallocarray(parent->entryv, parent->entryvsize + 1,
	    sizeof(*parent->entryv));
	if (parent->entryv == NULL)
		err(1, "%s: reallocarray", __func__);

	parent->entryv[parent->entryvsize] = child;
	parent->entryvsize++;
}

static void
addstr(struct scfge *scfge, const char *str)
{
	scfge->strv = reallocarray(scfge->strv, scfge->strvsize + 1,
	    sizeof(*scfge->strv));
	if (scfge->strv == NULL)
		err(1, "%s: reallocarray", __func__);

	if ((scfge->strv[scfge->strvsize] = strdup(str)) == NULL)
		err(1, "%s: strdup", __func__);
	scfge->strvsize++;
}

/* Allocate a new entry. */
static struct scfge *
allocentry(void)
{
	struct scfge *scfge;

	if ((scfge = calloc(1, sizeof(*scfge))) == NULL)
		err(1, "%s: calloc", __func__);
	allocated++;
	if (verbose > 3)
		warnx("%s:  allocated %p %d", __func__, (void *)scfge,
		    allocated);

	scfge->strv = NULL;
	scfge->entryv = NULL;

	return scfge;
}

static void
freeentry(struct scfge **scfge)
{
	size_t n;

	if (*scfge == NULL)
		return;

	if (verbose > 3)
		warnx("%s: deallocating %p %d", __func__, (void *)*scfge, allocated);

	for (n = 0; n < (*scfge)->strvsize; n++)
		free((*scfge)->strv[n]);
	free((*scfge)->strv);
	(*scfge)->strv = NULL;
	(*scfge)->strvsize = 0;

	for (n = 0; n < (*scfge)->entryvsize; n++)
		freeentry(&(*scfge)->entryv[n]);
	free((*scfge)->entryv);
	(*scfge)->entryv = NULL;
	(*scfge)->entryvsize = 0;

	allocated--;

	if (verbose > 3)
		warnx("%s: deallocated %p %d", __func__, (void *)*scfge, allocated);

	free(*scfge);
	*scfge = NULL;
}

/*
 * Recursively print all strings of all configuration entries.
 */
static void
printr(struct scfge *scfge, int depth)
{
	size_t n;

	if (scfge == NULL)
		return;

	fprintf(stdout, "%d: ", depth);

	if (scfge->strvsize == 0) {
		printf("%p\n", (void *)scfge);
	} else {
		for (n = 0; n < scfge->strvsize; n++)
			printf("%s ", scfge->strv[n]);
		printf("\n");
	}

	for (n = 0; n < scfge->entryvsize; n++)
		printr(scfge->entryv[n], depth + 1);
}

/*
 * Recursively print all strings of all configuration entries.
 */
void
scfg_printr(void)
{
	if (cfgroot == NULL)
		return;

	printr(cfgroot, 0);
}

/*
 * Remove the complete config from memory and check for leaks.
 *
 * Return 0 on success, -1 if an error occurred.
 */
int
scfg_clear(void)
{
	if (verbose > 3)
		warnx("%s", __func__);

	if (cfgroot == NULL) {
		if (allocated > 0) {
			warnx("no cfgroot while %d entries allocated",
				allocated);
			return -1;
		}
		return 0;
	}

	freeentry(&cfgroot);

	if (allocated > 0) {
		warnx("memleak: still %d entries allocated", allocated);
		return -1;
	}

	return 0;
}
