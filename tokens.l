%{
#include <stdio.h>
#include "nasltokens.h"
#include "grammar.tab.h"

#define YY_NO_INPUT
%}

%option nounput

identifierch	[A-Za-z0-9._]
identifierstr	{identifierch}+
poundcomment	\#.*\n

%%

{poundcomment}		lineno++;
[ \t]+			/* Ignore whitespace */
\n			lineno++;
\(			return (OPENPA);
\)			return (CLOSEPA);
\{			{
				ps.level++;
				if (debug)
					fprintf(stderr, "level: %d\n",
					    ps.level);
				return (OPENBR);
			}
\}			{
				ps.level--;
				if (debug)
					fprintf(stderr, "level: %d\n",
					    ps.level);
				return (CLOSEBR);
			}
\;			return (SEMICOLON);
\:			return (COLON);
\,			return (COMMA);
\=			return (EQUALS);
\+			return (PLUS);
\!			return (NOT);
if			return (IF);
else			return (ELSE);
NULL			return (NULLTOK);
{identifierstr}		{
				yylval.str = strdup(yytext);
				return (IDENTIFIER);
			}
\"[^"]*\"		{
				// It's possible the string could be multiline,
				// in this case increment the line counter
				// as needed.
				int i;
				for (i = 0; i < strlen(yytext); i++) {
					if (yytext[i] == '\n')
						lineno++;
				}
				yylval.str = strdup(yytext);
				if (yylval.str == NULL) {
					perror("strdup");
					exit(2);
				}
				return (ARGVAL);
			}
