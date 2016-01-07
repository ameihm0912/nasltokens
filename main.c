#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "nasltokens.h"

extern FILE	*yyin;
extern char	*yytext;
extern int	yyparse(void);

struct parserstate	ps;
int 			lineno = 1;
int			debug = 0;

void	yyerror(const char *);
int	yywrap(void);
void	nparse(char *);
void	usage(void);

int
yywrap()
{
	return (1);
}

void
yyerror(const char *s)
{
	fprintf(stderr, "yyparse: %s: line %d\n", s, lineno);
	exit(2);
}

void
nparse(char *fp)
{
	FILE *f;

	f = fopen(fp, "r");
	if (f == NULL) {
		perror("fopen");
		exit(2);
	}
	yyin = f;
	printf("{\n    \"vulnerabilities\": [\n");
	yyparse();
	printf("\n    ]\n}\n");
	fclose(f);
}

void
usage()
{
	printf("usage: nasltokens [-dh] file.nasl\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	char ch;
	char *fp;

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
	if (argc != 1) {
		usage();
	}
	fp = argv[0];

	memset(&ps, 0, sizeof(ps));
	nparse(fp);

	return (0);
}
