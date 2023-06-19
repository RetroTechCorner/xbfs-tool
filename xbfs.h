
#ifndef XBFS_H
#define XBFS_H
#include <sys/types.h>
#include "utils.h"

#define PAGE_SIZE	0x1000
#define XBFS_OFFSET	0x18008000
#define SERIES_FILE_OFFSET 0x6000
#define NUM_FILES	58
#define NUM_KNOWN_FILES 	34

// there is a hidden boot backup in XBFS partition 
// that is not part of XBFS file system (ie. not listed in header)
// it seems it's a boot.bin of previously installed version/update
// but... in some cases (where XBFS starts at offset 0x00) that "backup"
// boot.bin is referenced in XBFS header and "regular" boot.bin
// is still at usual offset but not references in XBFS header...
#define BOOT_BAK_OFFSET (uint64_t) 0x4000
#define BOOT_BAK_SIZE (uint32_t) 0x2700   // * PAGE_SIZE
#define BOOT_BAK_INDEX 99
#define BOOT_BAK "boot.bak"
#define BOOT_BIN_INDEX	16
#define BOOT_BIN_OFFSET (uint64_t) 0x1800C000

#define UPDATE_CFG_UUID_OFFSET 0x0B14

// "interesting" files
#define UPDATE_CFG_INDEX 22
#define SP_S_CFG_INDEX	10
#define SP_S_CFG_OFFSET 0x5400


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

typedef struct {
	uint8_t		unknown[50];
	uint8_t		prev_osu[176];
	uint8_t 	cur_osu[176];
	uint8_t		prev_osu_version[134];
} Update_Header;

typedef struct {
	uint8_t		unknown[560];
	uint8_t		serial[12];		
	uint8_t		unknown1[40];
	uint8_t		board_version[28];
	uint8_t		unknown2[432];
	uint8_t		sb_mobo_number[32];
	uint8_t		sb_mobo_number2[32];
	uint8_t		sb_mobo_type[16];
	uint8_t		sb_mobo_version[8];
	uint8_t		unknown3[32];
	uint8_t		br_drive[48];
} SP_S_Header;

char* filename_from_index(uint16_t);
int16_t index_from_filename(char *);
uint64_t real_offset(uint32_t);
int save_file(FILE *, uint64_t, uint32_t, uint16_t, char []);
int xbfs_info(XBFS_Header *, FILE *, args_t *, int);
int inject(XBFS_Header *x, FILE *, args_t *, int, char **, int);
uint16_t inject_file(XBFS_Header *, FILE *, char *, char *, XBFS_File_Entry *);


#endif