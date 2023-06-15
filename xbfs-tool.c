#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <ctype.h>
#include "sha256.h"
#include "xbfs.h"

char *xbfs_filenames[] = {
            "1smcbl_a.bin", // 0
            "header.bin", // 1
            "devkit.ini", // 2
            "mtedata.cfg", // 3
            "certkeys.bin", // 4
            "smcerr.log", // 5
            "system.xvd", // 6
            "$sospf.xvd", // 7, formerly $sosrst.xvd
            "download.xvd", // 8
            "smc_s.cfg", // 9
            "sp_s.cfg", // 10, keyvault? has serial/partnum/osig, handled by psp.sys (/Device/psp)
            "os_s.cfg", // 11
            "smc_d.cfg", // 12
            "sp_d.cfg", // 13
            "os_d.cfg", // 14
            "smcfw.bin", // 15
            "boot.bin", // 16
            "host.xvd", // 17
            "settings.xvd", // 18
            "1smcbl_b.bin", // 19
            "bootanim.dat", // 20, this entry and ones below it are only in retail 97xx and above?
            "obsolete.001", // 21, formerly sostmpl.xvd
            "update.cfg", // 22
            "obsolete.002", // 23, formerly sosinit.xvd
            "hwinit.cfg", // 24
            "qaslt.xvd", // 25
            "sp_s.bak", // 26, keyvault backup? has serial/partnum/osig
            "update2.cfg", // 27
            "obsolete.003", // 28
            "dump.lng", // 29
            "os_d_dev.cfg", // 30
            "os_glob.cfg", // 31
            "sp_s.alt", // 32
            "sysauxf.xvd", // 33
};

uint8_t xbfs_magic[] = {
	'S', 'F', 'B', 'X'
};

uint32_t xbfs_offset;

// boot loaders have their own file system...?
uint8_t bmfs_magic[] = {
	'B', 'M', 'F', 'S'
};

static char asterisk[] = " ";

static uint8_t read_buf[4096];


int main(int argc, char *argv[]) {
	// arguments / flags
	args_t args = { .i = 0, .f_val = NULL, .e = 0, .e_val = NULL, .j_val = NULL, .s_val = NULL};
  	opterr = 0;
	int c;

	while ((c = getopt (argc, argv, "if:e:j:s:")) != -1)
		switch (c) {
			case 'i':
				args.i = 1;
				break;
			case 'f':
				args.f_val = optarg;
				break;
			case 'e':
				args.e_val = optarg;
				break;
			case 'j':
				args.j_val = optarg;
				break;
			case 's':
				args.s_val = optarg;
				break;
			default:
				return 1;
		}
	int u = usage(&args);
	if(u != 0)
		return 1;

	XBFS_Header xbfs_header;
	FILE *fin;
	
	fin = fopen(args.f_val, "rb");
	if(fin == NULL) {
		printf("Error opening input file: %s\n", args.f_val);
		return 1;
	}
	xbfs_offset = (uint32_t) 0;
	// try XBFS header at offset 0x00
	fseek(fin, xbfs_offset, SEEK_SET);
	while(1) {
		fread(&xbfs_header, sizeof(XBFS_Header), 1, fin);
		break;
	}
	int magic_nok = 0;
	// check magic
	for(int i=0; i<4; i++) {
		if(xbfs_header.magic[i] != xbfs_magic[i]) {
			magic_nok = 1;
			break;
		}
	}
	if(magic_nok == 1) { // try at offset
		xbfs_offset = XBFS_OFFSET;
		fseek(fin, xbfs_offset, SEEK_SET);
		while(1) {
			fread(&xbfs_header, sizeof(XBFS_Header), 1, fin);
			break;
		}
		magic_nok = 0;
		for(int i=0; i<4; i++) {
			if(xbfs_header.magic[i] != xbfs_magic[i]) {
				magic_nok = 1;
				break;
			}
		}
		if(magic_nok == 1) {
			printf("Invalid XBFS header.\n");
			fclose(fin);
			return 1;
		}
	}

	// info and/or extract
	if(args.i != 0 || args.e_val != NULL) {
		int save = 0;
		if(args.e_val != NULL) 
			save = 1;
		xbfs_info(&xbfs_header, fin, &args, save);
	}

	// inject
	if(args.j_val != NULL) {
		// copy original file first
		// we'll be working on a backup
		char ch, out_fname[255];
		size_t n, m;
		FILE *fout;

		sprintf(out_fname, "%s.out", args.f_val);
		args.f_val = (char *)out_fname;
		fout = fopen(out_fname, "wb");
		fseek(fin, 0x00, SEEK_SET);
		do {
			n = fread(read_buf, 1, sizeof(read_buf), fin);
			if (n) m = fwrite(read_buf, 1, n, fout);
			else   m = 0;
		} while ((n > 0) && (n == m));    
		if (m) {
			printf("Error copying input file\n");
			fclose(fin);
			fclose(fout);
			return 1;
		}
    	int ret = inject(&xbfs_header, fout, &args, argc, argv, optind);
		char buf[255];
		if(ret == 0) {
			if(args.s_val != NULL) {	// update sequence number
				uint8_t new_seq = (uint8_t)strtol(args.s_val, NULL, 16);
    			xbfs_header.sequence_number = new_seq;
				mk_string(buf, &new_seq, 1, 1);
				printf("New Sequence: 0x%s\n", buf);

				// recauculate hash
				calc_sha_256((uint8_t *)&xbfs_header.sha, (char*)&xbfs_header, sizeof(XBFS_Header)-SIZE_OF_SHA_256_HASH);
				mk_string(buf, xbfs_header.sha, 32, 1);
				printf("New SHA256: 0x%s\n", buf);
			}
			// update/save header
			fseek(fout, xbfs_offset, SEEK_SET);
			fwrite(&xbfs_header, sizeof(XBFS_Header), 1, fout);
		}
		fclose(fout);
	}
	fclose(fin);
	return 0;
}

int inject(XBFS_Header *xbfs_header, FILE *fout, args_t *opts, int argc, char **argv, int optind) {
	XBFS_File_Entry *cur_file = &(xbfs_header->file_entry_table[0]);
	uint16_t j = 0;
	for(int i=0; i<NUM_FILES; i++) {
		if(cur_file->size > 0) {
            // check if this is a file we want to inject
            char *injected_fname = filename_from_index(j);
            // iterate through all argv arguments 
            for(int c=optind; c<argc; c++) {
                if(!strcmp(injected_fname, argv[c])) {
                    printf("Injecting: %s at offset: %08X\n", injected_fname, cur_file->offset);
                    int ret = inject_file(xbfs_header, fout, opts->j_val, argv[c], cur_file);
                    if(ret!=0) {
                        printf("Error injecting file: %s [%d]\n", argv[c], ret);
                        fclose(fout);
                        return 1;
                    }
                    break;
                }
            }
        }
		j++;
		cur_file+=1;        
    }
    
	return 0;
}

uint16_t inject_file(XBFS_Header *xbfs_header, FILE *fout, char *dir, char *filename, XBFS_File_Entry *fentry) {
    FILE *fin;
    size_t n, m;
    char out_fname[255];
	char buf[255];

    sprintf(out_fname, "%s/%s", dir, filename);
    fin = fopen(out_fname, "rb");
    if(!fin) {
        return 1;
    }
    uint64_t cur_offset = (uint64_t) fentry->offset * 0x1000;    
    cur_offset -= SERIES_FILE_OFFSET;
    fseek(fout, cur_offset, SEEK_SET);
    do {
        n = fread(read_buf, 1, sizeof(read_buf), fin);
        if (n) m = fwrite(read_buf, 1, n, fout);
        else   m = 0;
    } while ((n > 0) && (n == m));    
    if (m) {
        return 2;
    }
	if(!strcmp(filename, xbfs_filenames[22])) { 	// update.cfg
		cur_offset = UPDATE_CFG_UUID_OFFSET;
		fseek(fin, cur_offset, SEEK_SET);
		fread(&(xbfs_header->update_uuid), 1, 16, fin);
		mk_string(buf, xbfs_header->update_uuid, 16, 1);
		printf("New Update UUID: 0x%s\n", buf);
	}
    fclose(fin);
    return 0;
}

int xbfs_info(XBFS_Header *xbfs_header, FILE *fin, args_t *opts, int save) {
	char buf[255];

	printf(" === HBFS Header ===\n");
	mk_string(buf, xbfs_header->magic, 4, 0);
	printf("%17s: %s [0x%08" PRIX32 "]\n", "Magic [offset]", buf, xbfs_offset);

	printf("%17s: %02X\n", "Format Version", xbfs_header->format_version);
	
	printf("%17s: %02X\n", "Sequence Number", xbfs_header->sequence_number);

	printf("%17s: %04X\n", "Layout Version", xbfs_header->layout_version);

	// check for presence of "backup" boot.bin
	fseek(fin, BOOT_BAK_OFFSET, SEEK_SET);
	while(1) {
		fread(buf, 0x4, 1, fin);
		break;
	}
	int bmfs_magic_nok = 0;
	// check magic
	for(int i=0; i<4; i++) {
		if(buf[i] != bmfs_magic[i]) {
			bmfs_magic_nok = 1;
			break;
		}
	}
	if(bmfs_magic_nok) 
		printf("%17s: %s\n", "Backup boot.bin", "Missing");
	else 
		printf("%17s: %s\n", "Backup boot.bin", "Present");
	
	mk_string(buf, xbfs_header->update_uuid, 16, 1);
	printf("%17s: %s\n", "Update UUID?", buf);

	mk_string(buf, xbfs_header->uuid, 16, 1);
	printf("%17s: %s\n", "UUID", buf);

	mk_string(buf, xbfs_header->sha, 32, 1);
	printf("%17s: %s\n", "SHA256", buf);

	if(save) { 		// create output dir
		struct stat st = {0};
		if (stat(opts->e_val, &st) == -1) {
			mkdir(opts->e_val, 0700);
		}
	}
		
	printf(" === XFBS Files ===\n");	
	// iterate through files
	XBFS_File_Entry *cur_file = &(xbfs_header->file_entry_table[0]);
	uint16_t j = 0;
	uint64_t boot_bak_offset = BOOT_BAK_OFFSET;

	for(int i=0; i<NUM_FILES; i++) {
		if(cur_file->size > 0) {
			uint64_t offset = real_offset(cur_file->offset);
			// make an exception for "unusual" boot.bin
			if(i == BOOT_BIN_INDEX) {		// boot.bin 
				if(offset == 0x4000) {
					boot_bak_offset = BOOT_BIN_OFFSET;
				}
			}
			printf("[%2d] %15s %1s %8s: 0x%08" PRIX64 " %6s: 0x%04" PRIX32 " %6s: 0x%" PRIX64 "\n", j, filename_from_index(j), asterisk, "Offset", offset & 0xffffffff, "Size", cur_file->size, "Unkn", cur_file->unknown);
			if(save != 0)
				save_file(fin, offset, cur_file->size, j, opts->e_val);
		}
		j++;
		cur_file+=1;
	}
	// save backup boot.bin (if present)
	if(!bmfs_magic_nok) {
		if(boot_bak_offset == BOOT_BIN_OFFSET) 
			asterisk[0] = '*';
		printf("[%2s] %15s %1s %8s: 0x%08" PRIX64 " %6s: 0x%04" PRIX32 " %6s: %s\n", "--", filename_from_index(BOOT_BAK_INDEX), asterisk, "Offset", boot_bak_offset & 0xffffffff, "Size", BOOT_BAK_SIZE, "Unkn", "---");
		if(save != 0)
			save_file(fin, boot_bak_offset, BOOT_BAK_SIZE, BOOT_BAK_INDEX, opts->e_val);
	}
	printf("\n");


	// print console info: "sp_s.cfg", file# 10,
	printf(" === Console info ===\n");	
	SP_S_Header sp_s_header;
	cur_file = &(xbfs_header->file_entry_table[SP_S_CFG_INDEX]);
	uint64_t offset = real_offset(cur_file->offset);
	fseek(fin, offset + SP_S_CFG_OFFSET, SEEK_SET);
	fread(&sp_s_header, sizeof(sp_s_header), 1, fin);
	mk_string(buf, sp_s_header.serial, sizeof(sp_s_header.serial), 0);
	printf("%15s: %s\n", "Serial number", buf);
	mk_string(buf, sp_s_header.board_version, sizeof(sp_s_header.board_version), 0);
	printf("%15s: %s\n", "Board version", buf);
	mk_string(buf, sp_s_header.sb_mobo_number, sizeof(sp_s_header.sb_mobo_number), 0);
	printf("%15s: %s\n", "SB Mobo version (?)", buf);
	mk_string(buf, sp_s_header.sb_mobo_type, sizeof(sp_s_header.sb_mobo_type), 0);
	printf("%15s: %s\n", "SB Mobo type (?)", buf);
	mk_string(buf, sp_s_header.br_drive, sizeof(sp_s_header.br_drive), 0);
	printf("%15s: %s\n", "Optical Drive", buf);
	printf("\n");
	// print update info: "update.cfg", file# 22
	// get update.cfg offset
	printf(" === Update info ===\n");	

	Update_Header update_header;
	cur_file = &(xbfs_header->file_entry_table[UPDATE_CFG_INDEX]);
	offset = real_offset(cur_file->offset);
	fseek(fin, offset, SEEK_SET);
	fread(&update_header, sizeof(update_header), 1, fin);
	mk_printf(buf, update_header.prev_update, sizeof(update_header.prev_update));
	printf("%15s: %s\n", "Previous update", buf);
	mk_printf(buf, update_header.cur_update, sizeof(update_header.cur_update));
	printf("%15s: %s\n", "Current update", buf);
	mk_printf(buf, update_header.os, sizeof(update_header.os));
	printf("%15s: %s\n", "OS (?)", buf);

	return 0;
}

int save_file(FILE *fp, uint64_t cur_offset, uint32_t size, uint16_t fnum, char dir[]) {
	uint8_t block[PAGE_SIZE];
	char fpath[255];
	
	sprintf(fpath, "%s/%s", dir, filename_from_index(fnum));
	FILE *fw = fopen(fpath, "wb");
	
	fseek(fp, cur_offset, SEEK_SET);
	for(uint32_t i=0; i<size; i++) {
		fread(block, PAGE_SIZE, 1, fp);
		fwrite(block, PAGE_SIZE, 1, fw);	
	}
	
	fclose(fw);
	return 0;
}

char* filename_from_index(uint16_t idx) {
	static char fname_buf[32];
    if(idx == BOOT_BAK_INDEX)
        return BOOT_BAK;
	if(idx < NUM_KNOWN_FILES) {
		return xbfs_filenames[idx];
	}
	sprintf(fname_buf, "%d.bin", idx);
	return fname_buf;
}

int16_t index_from_filename(char *filename) {
    int16_t index = -1;
    if(!strcmp(filename, BOOT_BAK)) 
        return BOOT_BAK_INDEX;
    for(int16_t i=0; i<NUM_KNOWN_FILES; i++) {
        if(!strcmp(filename, xbfs_filenames[i])) {
            return i;
        }
    }
    return index;
}

uint64_t real_offset(uint32_t offset) {
	uint64_t cur_offset = (uint64_t) offset * 0x1000;
	cur_offset -= SERIES_FILE_OFFSET;

    return cur_offset;
}
