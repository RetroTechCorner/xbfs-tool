
#ifndef UTILS_H
#define UTILS_H
#include <sys/types.h>
#include <unistd.h>

typedef struct {
	int i;		// info
	int f;		// input xbfs
	char *f_val;
	int e;		// extract 
	char *e_val;
	int j;		// inject
    char *j_val;
	int s; 		// sequence
	char *s_val;
} args_t;

int usage(args_t *);
int mk_string(char *buf, uint8_t *input, uint8_t size, uint8_t hex); 
int mk_printf(char *buf, uint8_t *input, uint8_t size);

#endif