TARGETS = nasltokens
CFLAGS = -Wall -g
OBJ = main.o grammar.tab.o lex.yy.o
FLEX = flex
BISON = bison
BISON_FLAGS = --defines -v

nasltokens: $(OBJ)
	$(CC) -o $@ $(OBJ)

lex.yy.c: tokens.l
	$(FLEX) tokens.l

grammar.tab.c: grammar.y
	$(BISON) $(BISON_FLAGS) grammar.y

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o *.core core $(TARGETS)
	rm -f *.tab.c *.tab.h lex.yy.c
	rm -f *.output
