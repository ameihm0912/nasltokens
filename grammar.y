%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "nasltokens.h"

extern void		yyerror(const char *);
extern int		yylex(void);

void		parser_handler(void);
void		proc_isdpkgvuln(void);
void		proc_isrpmvuln(void);
void		proc_scripttag(void);
void		reset_fargs(void);
void		add_farg(char *, char *);

void
reset_fargs()
{
	if (ps.nfargs > 0) {
		free(ps.fargs);
	}
	ps.nfargs = 0;
	ps.fargs = NULL;
}

void
add_farg(char *key, char *value)
{
	struct funcargs *p0;

	ps.nfargs++;
	ps.fargs = realloc(ps.fargs, sizeof(struct funcargs) * ps.nfargs);
	if (ps.fargs == NULL) {
		perror("malloc");
		exit(2);
	}
	p0 = &ps.fargs[ps.nfargs - 1];
	memset(p0, 0, sizeof(struct funcargs));
	if (key != NULL)
		strncpy(p0->key, key, sizeof(p0->key) - 1);
	if (value != NULL)
		strncpy(p0->val, value, sizeof(p0->val) - 1);
}

void
parser_handler()
{
	if (debug)
		fprintf(stderr, "parser handler running\n");
	if (ps.funcname[0] != '\0') {
		if (debug)
			fprintf(stderr, "function: %s\n", ps.funcname);
		if (strcmp(ps.funcname, "scripttag") == 0) {
			proc_scripttag();
		} else if (strcmp(ps.funcname, "isdpkgvuln") == 0) {
			proc_isdpkgvuln();
		} else if (strcmp(ps.funcname, "isrpmvuln") == 0) {
			proc_isrpmvuln();
		}
	}
}

void
proc_isdpkgvuln()
{
	char *pkgname, *resver;

	if (ps.nfargs != 3) {
		fprintf(stderr, "error: invalid number of arguments for isdpkgvuln\n");
		exit(2);
	}
	pkgname = ps.fargs[0].val;
	resver = ps.fargs[1].val;
	printf("%s %s < %s\n", ps.release_cond_arg, pkgname, resver);
}

void
proc_isrpmvuln()
{
	char *pkgname, *resver;

	if (ps.nfargs != 3) {
		fprintf(stderr, "error: invalid number of arguments for isrpmvuln\n");
		exit(2);
	}
	pkgname = ps.fargs[0].val;
	resver = ps.fargs[1].val;
	printf("%s %s < %s\n", ps.release_cond_arg, pkgname, resver);
}

void
proc_scripttag()
{
	struct funcargs *p0;

	if (ps.nfargs < 2)
		return;
	p0 = &ps.fargs[0];

	if ((strcmp(p0->key, "name") != 0) ||
	    (strcmp(p0->val, "\"check_type\"") != 0))
		return;

	p0 = &ps.fargs[1];
	if (strcmp(p0->val, "\"authenticated package test\"") != 0) {
		fprintf(stderr, "exiting, plugin is not an authenticated package test\n");
		exit(3);
	}
}


%}

%union {
	char	*str;
}

%token OPENPA CLOSEPA
%token OPENBR CLOSEBR
%token IDENTIFIER
%token ARGVAL
%token NULLTOK
%token SEMICOLON COLON COMMA EQUALS NOT PLUS
%token IF ELSE

%type <str> IDENTIFIER
%type <str> ARGVAL

%%

statements:
	| statements statement
	;

statement:
	if_state OPENPA condition CLOSEPA OPENBR statements CLOSEBR
	{
		if ((ps.release_cond_flag) && (ps.level == ps.release_entry_level)) {
			ps.release_cond_flag = 0;
			if (debug)
				fprintf(stderr, "release context exit\n");
		}
	}
	| if_state OPENPA condition CLOSEPA statement
	| IDENTIFIER OPENPA funcargs CLOSEPA SEMICOLON
	{
		memset(&ps.funcname, 0, sizeof(ps.funcname));
		strncpy(ps.funcname, $1, sizeof(ps.funcname) - 1);
		parser_handler();
		reset_fargs();
		ps.funcname[0] = '\0';
	}
	| IDENTIFIER EQUALS IDENTIFIER OPENPA funcargs CLOSEPA SEMICOLON
	{
		memset(&ps.funcname, 0, sizeof(ps.funcname));
		strncpy(ps.funcname, $3, sizeof(ps.funcname) - 1);
		parser_handler();
		reset_fargs();
		ps.funcname[0] = '\0';
	}
	| IDENTIFIER EQUALS IDENTIFIER OPENPA funcargs CLOSEPA
	{
		memset(&ps.funcname, 0, sizeof(ps.funcname));
		strncpy(ps.funcname, $3, sizeof(ps.funcname) - 1);
		parser_handler();
		reset_fargs();
		ps.funcname[0] = '\0';
	}
	| IDENTIFIER EQUALS ARGVAL SEMICOLON
	| IDENTIFIER PLUS EQUALS IDENTIFIER SEMICOLON

if_state:
	IF
	| ELSE IF

condition:
	IDENTIFIER
	| IDENTIFIER evaluator IDENTIFIER
	{
		if (strcmp($1, "release") == 0) {
			ps.release_cond_flag = 1;
			ps.release_entry_level = ps.level;
			if (debug)
				fprintf(stderr, "release context entry at level %d\n",
				    ps.release_entry_level);
			strncpy(ps.release_cond_arg,
			    $3, sizeof(ps.release_cond_arg) - 1);
		}
	}
	| IDENTIFIER evaluator ARGVAL
	{
		if (strcmp($1, "release") == 0) {
			ps.release_cond_flag = 1;
			ps.release_entry_level = ps.level;
			if (debug)
				fprintf(stderr, "release context entry at level %d\n",
				    ps.release_entry_level);
			strncpy(ps.release_cond_arg,
			    $3, sizeof(ps.release_cond_arg) - 1);
		}
	}
	| IDENTIFIER evaluator NULLTOK
	| OPENPA statement CLOSEPA evaluator ARGVAL
	| OPENPA statement CLOSEPA evaluator NULLTOK
	;

evaluator:
	EQUALS EQUALS
	| NOT EQUALS

funcargs:
	funcarg
	| funcargs COMMA funcarg

/* A single function argument, arguments are pushed onto the parser state
 * as we see them. */
funcarg:
	IDENTIFIER COLON ARGVAL
	{
		add_farg($1, $3);
	}
	| IDENTIFIER COLON IDENTIFIER
	{
		add_farg($1, $3);
	}
	| ARGVAL
	{
		add_farg(NULL, $1);
	}
	| IDENTIFIER
	{
		add_farg(NULL, $1);
	}
