#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "utils.h"
#include "xbfs.h"

/*
-i 				info
-f <file_name> 	input xbfs image
-e <dir> 		extract files
-j <dir>		inject
-s <sequence>	set sequence number
*/

char *_usage_str = 
    "Usage:\n"
    "xbfs-tool -i -f <xbfs_file>\n"
    "xbfs-tool -f <xbfs_file> -e <output directory>\n"
    "xbfs_tool -f <xbfs_file> -j <input_directory> [-s <sequence_number>]\n";

int _usage() {
    printf("\n%s\n", _usage_str);
    return 1;
}
int usage(args_t *args) {
    if(args->f_val == NULL)
        return _usage();
    if(args->i == 1)
        return 0;
    if(args->e_val != args->j_val && (args->e_val == NULL || args->j_val == NULL)) 
        return 0;
    return _usage();
}

int mk_string(char *buf, uint8_t *input, uint8_t size, uint8_t hex) {
	memset(buf, '\0', 255);
	for (int i=0; i<size; i++) {
		if(hex) {
			sprintf(buf, "%02X", *input);
			buf+=2;
		} else {		
			sprintf(buf++, "%c", *input);
		}
		input++;
	};	
	return 0;
}

