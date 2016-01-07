%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "nasltokens.h"

struct s_relcondtab {
	char *naslid;
	char *scribeid;
	char *os;
} relcondtab[] = {
	{ "UBUNTU15.10", "wily", "ubuntu" },
	{ "UBUNTU15.04", "vivid", "ubuntu" },
	{ "UBUNTU14.10", "utopic", "ubuntu" },
	{ "UBUNTU14.04 LTS", "trusty", "ubuntu" },
	{ "UBUNTU12.04 LTS", "precise", "ubuntu" },
	{ "UBUNTU10.04", "lucid", "ubuntu" },
	{ "RHENT_7", "rhel7", "redhat" },
	{ "RHENT_6", "rhel6", "redhat" },
	{ "RHENT_5", "rhel5", "redhat" },
	{ "", "", "" }
};

static int inlist;

extern void		yyerror(const char *);
extern int		yylex(void);

char		*reltrans(char *);
void		parser_handler(void);
void		proc_isdpkgvuln(void);
void		proc_isrpmvuln(void);
void		proc_scripttag(void);
void		proc_scriptname(void);
void		proc_scriptcveid(void);
void		reset_fargs(void);
void		rpm_translate(char *, char *, char **);
void		add_farg(char *, char *);
void		printmeta(void);

/*
 * Reset function arguments in the parser state
 */
void
reset_fargs()
{
	if (ps.nfargs > 0) {
		free(ps.fargs);
	}
	ps.nfargs = 0;
	ps.fargs = NULL;
}

/*
 * Add a function argument for the current function stored within the parser
 * state
 */
void
add_farg(char *key, char *value)
{
	char *p1;
	struct funcargs *p0;

	ps.nfargs++;
	ps.fargs = realloc(ps.fargs, sizeof(struct funcargs) * ps.nfargs);
	if (ps.fargs == NULL) {
		perror("malloc");
		exit(2);
	}
	p0 = &ps.fargs[ps.nfargs - 1];

	/* If a value begins and ends in a quote character, strip the quotes
	 * from the value */
	for (p1 = value; *p1 == '"'; p1++);
	value = p1;
	if (p1[strlen(p1) - 1] == '"') {
		p1[strlen(p1) - 1] = '\0';
	}

	memset(p0, 0, sizeof(struct funcargs));
	if (key != NULL)
		strncpy(p0->key, key, sizeof(p0->key) - 1);
	if (value != NULL)
		strncpy(p0->val, value, sizeof(p0->val) - 1);
}

/*
 * Interpret the parser state and handle the stored function
 */
void
parser_handler()
{
	if (debug)
		fprintf(stderr, "parser handler running\n");
	if (ps.funcname[0] != '\0') {
		if (debug)
			fprintf(stderr, "function: %s\n", ps.funcname);
		if (strcmp(ps.funcname, "script_tag") == 0) {
			proc_scripttag();
		} else if (strcmp(ps.funcname, "script_name") == 0) {
			proc_scriptname();
		} else if (strcmp(ps.funcname, "script_cve_id") == 0) {
			proc_scriptcveid();
		} else if (strcmp(ps.funcname, "isdpkgvuln") == 0) {
			proc_isdpkgvuln();
		} else if (strcmp(ps.funcname, "isrpmvuln") == 0) {
			proc_isrpmvuln();
		}
	}
}

/*
 * Translate the release name used in the NASL file into a release identifier
 * that is used by scribe; the parser state is updated
 */
void
release_cond_trans()
{
	char tmpbuf[1024];
	struct s_relcondtab *sptr;

	/* First update the existing stored release string and remove any
	 * leading or trailing quote characters */
	if (ps.release_cond_arg[0] == '"' && strlen(ps.release_cond_arg) > 1) {
		strncpy(tmpbuf, ps.release_cond_arg + 1, sizeof(tmpbuf) - 1);
		tmpbuf[strlen(tmpbuf) - 1] = '\0';
		strncpy(ps.release_cond_arg, tmpbuf, sizeof(ps.release_cond_arg) - 1);
	}

	memset(ps.release_os, 0, sizeof(ps.release_os));
	memset(ps.release_cond_trans, 0, sizeof(ps.release_cond_trans));

	for (sptr = relcondtab; strlen(sptr->naslid) != 0; sptr++) {
		if (strcmp(sptr->naslid, ps.release_cond_arg) == 0) {
			strncpy(ps.release_cond_trans, sptr->scribeid,
			    sizeof(ps.release_cond_trans) - 1);
			strncpy(ps.release_os, sptr->os,
			    sizeof(ps.release_os) - 1);
			break;
		}
	}
	if (strlen(ps.release_os) == 0) {
		fprintf(stderr, "WARNING: unknown release identifier \"%s\"\n",
		    ps.release_cond_arg);
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
	if (inlist) {
		printf(",\n");
	}
	printf("        {\n");
	printf("            \"os\": \"%s\",\n", ps.release_os);
	printf("            \"release\": \"%s\",\n", ps.release_cond_trans);
	printf("            \"package\": \"%s\",\n", pkgname);
	printf("            \"version\": \"%s\",\n", resver);
	printmeta();
	printf("        }");
	inlist = 1;
}

/*
 * Reformat the arguments to isrpmvuln() to make it more directly
 * usable. The package version strings contain the package name in this
 * case. It is removed, in addition ~ strings are converted to - for
 * version string comparison.
 */
void
rpm_translate(char *rel, char *pkgname, char **resver)
{
	char *bufcpy, *p0;
	size_t buflen;

	if (strncasecmp(rel, "rhel", 4) != 0) {
		return;
	}
	if (strlen(*resver) < strlen(pkgname)) {
		fprintf(stderr, "error: malformed resver/pkgname in rpm_translate\n");
		exit(2);
	}
	buflen = strlen(*resver) + 1;
	bufcpy = malloc(buflen);
	if (bufcpy == NULL) {
		perror("malloc");
		exit(2);
	}
	memset(bufcpy, 0, buflen);
	p0 = *resver + strlen(pkgname);
	if ((*p0 != '~' && *p0 != '-') || strlen(p0) < 2) {
		fprintf(stderr, "error: malformed rpm version string: \"%s\", " \
		    "package \"%s\"\n", *resver, pkgname);
		exit(2);
	}
	p0++; /* Skip the ~/- seperator between the pkg name and version string */
	strncpy(bufcpy, p0, buflen - 1);
	strncpy(*resver, bufcpy, buflen);
	free(bufcpy);

	/* Finally, convert all the ~ in the version string to a - */
	for (p0 = *resver; *p0 != '\0'; p0++) {
		if (*p0 == '~')
			*p0 = '-';
	}
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
	rpm_translate(ps.release_cond_trans, pkgname, &resver);
	if (inlist) {
		printf(",\n");
	}
	printf("        {\n");
	printf("            \"os\": \"%s\",\n", ps.release_os);
	printf("            \"release\": \"%s\",\n", ps.release_cond_trans);
	printf("            \"package\": \"%s\",\n", pkgname);
	printf("            \"version\": \"%s\",\n", resver);
	printmeta();
	printf("        }");
	inlist = 1;
}

void
proc_scripttag()
{
	struct funcargs *p0;

	if (ps.nfargs < 2)
		return;
	p0 = &ps.fargs[0];

	if ((strcmp(p0->key, "name") == 0) &&
	    (strcmp(p0->val, "check_type") == 0)) {
		p0 = &ps.fargs[1];
		if (strcmp(p0->val, "authenticated package test") != 0) {
			fprintf(stderr, "exiting, plugin is not an " \
			    "authenticated package test\n");
			exit(3);
		}
	} else if ((strcmp(p0->key, "name") == 0) &&
	    (strcmp(p0->val, "cvss_base") == 0)) {
		p0 = &ps.fargs[1];
		strncpy(ps.cvss, p0->val, sizeof(ps.cvss) - 1);
	}
}

void
proc_scriptname()
{
	struct funcargs *p0;

	if (ps.nfargs < 1)
		return;
	p0 = &ps.fargs[0];
	strncpy(ps.script_name, p0->val, sizeof(ps.script_name) - 1);
}

void
proc_scriptcveid()
{
	struct funcargs *p0;
	int i;

	if (ps.nfargs < 1)
		return;

	for (i = 0; i < ps.nfargs; i++) {
		p0 = &ps.fargs[i];
		strncpy(ps.cvelist[ps.cvelist_num], p0->val,
		    sizeof(ps.cvelist[ps.cvelist_num]) - 1);
		ps.cvelist_num++;
	}
}

void
printmeta()
{
	int i;

	printf("            \"metadata\": {\n");

	printf("                \"description\": \"%s\",\n", ps.script_name);
	printf("                \"cvss\": \"%s\",\n", ps.cvss);

	for (i = 0; i < ps.cvelist_num; i++) {
		if (i == 0)
			printf("                \"cve\": [\n");
		else
			printf(",\n");
		printf("                    \"%s\"", ps.cvelist[i]);
	}
	if (i > 0)
		printf("\n                ]\n");

	printf("            }\n");
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
		free($1);
	}
	| IDENTIFIER EQUALS IDENTIFIER OPENPA funcargs CLOSEPA SEMICOLON
	{
		memset(&ps.funcname, 0, sizeof(ps.funcname));
		strncpy(ps.funcname, $3, sizeof(ps.funcname) - 1);
		parser_handler();
		reset_fargs();
		ps.funcname[0] = '\0';
		free($1);
		free($3);
	}
	| IDENTIFIER EQUALS IDENTIFIER OPENPA funcargs CLOSEPA
	{
		memset(&ps.funcname, 0, sizeof(ps.funcname));
		strncpy(ps.funcname, $3, sizeof(ps.funcname) - 1);
		parser_handler();
		reset_fargs();
		ps.funcname[0] = '\0';
		free($1);
		free($3);
	}
	| IDENTIFIER EQUALS ARGVAL appendops SEMICOLON
	{
		free($1);
		free($3);
	}
	| IDENTIFIER PLUS EQUALS IDENTIFIER SEMICOLON
	{
		free($1);
		free($4);
	}

appendops:
	 | appendops appendop

appendop:
	PLUS IDENTIFIER
	{
		free($2);
	}
	| PLUS ARGVAL
	{
		free($2);
	}

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
			release_cond_trans();
		}
		free($1);
		free($3);
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
			release_cond_trans();
		}
		free($1);
		free($3);
	}
	| IDENTIFIER evaluator NULLTOK
	{
		free($1);
	}
	| OPENPA statement CLOSEPA evaluator ARGVAL
	{
		free($5);
	}
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
		free($1);
		free($3);
	}
	| IDENTIFIER COLON IDENTIFIER
	{
		add_farg($1, $3);
		free($1);
		free($3);
	}
	| ARGVAL
	{
		add_farg(NULL, $1);
		free($1);
	}
	| IDENTIFIER
	{
		add_farg(NULL, $1);
		free($1);
	}
