#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "nasltokens.h"

extern FILE	*yyin;
extern char	*yytext;
extern int	yyparse(void);

struct parserstate	ps;
char			*curfile = NULL;
int 			lineno = 1;
int			debug = 0;

void	yyerror(const char *);
int	yywrap(void);
void	nparse();
void	usage(void);

int
yywrap()
{
	return (1);
}

void
yyerror(const char *s)
{
	fprintf(stderr, "yyparse: %s: %s: line %d\n", curfile, s, lineno);
	exit(2);
}

void
nparse()
{
	FILE *f;

	f = fopen(curfile, "r");
	if (f == NULL) {
		perror("fopen");
		exit(2);
	}
	yyin = f;
	lineno = 1;
	yyparse();
	fclose(f);
}

void
usage()
{
	printf("usage: nasltokens [-dh] file.nasl file.nasl ...\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	char ch;
	int i;

	while ((ch = getopt(argc, argv, "dh")) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;
		case 'h':
			usage();
			break;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 1) {
		usage();
	}

	printf("{\n    \"vulnerabilities\": [\n");
	for (i = 0; i < argc; i++) {
		curfile = argv[i];
		memset(&ps, 0, sizeof(ps));
		nparse(curfile);
	}
	printf("\n    ]\n}\n");

	return (0);
}
