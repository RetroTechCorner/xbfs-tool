
#ifndef XBFS_H
#define XBFS_H
#include <sys/types.h>
#include "utils.h"

#define PAGE_SIZE	0x1000
#define XBFS_OFFSET	0x18008000
#define SERIES_FILE_OFFSET 0x6000
#define NUM_FILES	58
#define NUM_KNOWN_FILES 	34

// #define BOOT_BAK_OFFSET (uint64_t) 0x1800C000
#define BOOT_BAK_OFFSET (uint64_t) 0x4000
#define BOOT_BAK_SIZE (uint32_t) 0x2700   // * PAGE_SIZE
#define BOOT_BAK_INDEX 99
#define BOOT_BAK "boot.bak"

#define UPDATE_CFG_UUID_OFFSET 0x0B14;

extern char *xbfs_filenames[];
extern uint8_t xbfs_magic[];
extern uint8_t bmfs_magic[];

extern uint32_t xbfs_offset;

typedef struct {
	uint32_t	offset;
	uint32_t	size;
	uint64_t	unknown;
} XBFS_File_Entry;

typedef struct {
	uint8_t 	magic[4];
	uint8_t 	format_version;
	uint8_t 	sequence_number;
	uint16_t 	layout_version;
	uint64_t 	unknown_1;
	uint64_t 	unknown_2;
	uint64_t 	unknown_3;
	
	XBFS_File_Entry	file_entry_table[NUM_FILES];

	uint8_t		update_uuid[16];	
	uint8_t		uuid[16];
	uint8_t 	sha[32];
} XBFS_Header;

char* filename_from_index(uint16_t);
int16_t index_from_filename(char *);
uint64_t real_offset(uint32_t);
int save_file(FILE *, uint64_t, uint32_t, uint16_t, char []);
int xbfs_info(XBFS_Header *, FILE *, args_t *, int);
int inject(XBFS_Header *x, FILE *, args_t *, int, char **, int);
uint16_t inject_file(XBFS_Header *, FILE *, char *, char *, XBFS_File_Entry *);


#endif