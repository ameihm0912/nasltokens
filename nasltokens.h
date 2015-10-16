/* Parser state */
struct parserstate {
	/* Parser context level */
	int		level;

	/* Conditional release entry state */
	int		release_cond_flag;
	char		release_cond_arg[1024];
	int		release_entry_level;

	char		funcname[1024];
	struct funcargs	*fargs;
	int		nfargs;
};

struct funcargs {
	char key[1024];
	char val[1024];
};

extern int			lineno;
extern int			debug;
extern struct parserstate	ps;
