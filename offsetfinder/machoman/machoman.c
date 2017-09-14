//
//  machoman.c
//  machoman
//
//  Created by jndok on 14/05/16.
//  Copyright © 2016 jndok. All rights reserved.
//

#include "machoman.h"

macho_map_t *map_macho_with_path(const char *path, int mode)
{
    if (!path)  return NULL;
    if (access(path, R_OK) == -1)   return NULL;
    
    int32_t fd = open(path, mode);
    if (fd < 0) {
        return NULL;
    }
    
    struct stat st;
    if(fstat(fd, &st) != 0)
        goto fail;
    
    macho_map_t *map = (macho_map_t *)malloc(sizeof(macho_map_t));
    if((map->map_data = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, (mode == O_RDONLY) ? MAP_PRIVATE : MAP_SHARED, fd, 0)) == MAP_FAILED)
        goto fail;
    map->map_magic = MACHO_MAP_MAGIC;
    map->map_size = (mach_vm_size_t)st.st_size;
    map->unique_id = (uint32_t)(((uint64_t)map << 32) >> 32);
    
    return map;
    
fail:
    close(fd);
    
    return NULL;
}

void free_macho_map(macho_map_t *map)
{
    if (!is_valid_macho_map(map)) {
        return;
    }
    
    munmap(map->map_data, map->map_size);
    free(map);
}

__attribute__((always_inline))
boolean_t is_valid_macho_file(const char *path)
{
    if (!path)  return FALSE;
    if (access(path, R_OK) == -1)   return FALSE;
    
    int32_t fd = open(path, O_RDONLY);
    if (fd < 0)
        return FALSE;
    
    uint32_t magic = 0;
    if (read(fd, (void*)&magic, sizeof(uint32_t)) == -1)
        return FALSE;
    
    if ((magic == MH_MAGIC) || (magic == MH_MAGIC_64))
        return TRUE;
    else
        return FALSE;
}

__attribute__((always_inline))
boolean_t is_valid_macho_map(macho_map_t *map)
{
    if (!map)   return FALSE;
    if (!map->map_data) FALSE;
    if (map->map_magic != MACHO_MAP_MAGIC)  return FALSE;
    
    return TRUE;
}

__attribute__((always_inline))
struct mach_header *get_mach_header32(macho_map_t *map)
{
    if (!is_valid_macho_map(map))   return NULL;
    
    return (struct mach_header*)(map->map_data);
}

__attribute__((always_inline))
struct load_command *find_load_command32(struct mach_header *mh, uint32_t lc)
{
    struct load_command *lcmd = (struct load_command *)(mh + 1);
    for (uint32_t i=0; i<mh->ncmds; i++, lcmd = (void *)lcmd + lcmd->cmdsize) {
        if (lcmd->cmd == lc)
            return lcmd;
    }
    
    return NULL;
}

__attribute__((always_inline))
struct segment_command *find_segment_command32(struct mach_header *mh, const char *segname)
{
    struct load_command *lcmd = (struct load_command *)(mh + 1);
    for (uint32_t i=0; i<mh->ncmds; i++, lcmd = (void *)lcmd + lcmd->cmdsize) {
        if (lcmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (struct segment_command*)(lcmd);
            if (strcmp(seg->segname, segname) == 0)
                return seg;
        }
    }
    
    return NULL;
}

__attribute__((always_inline))
struct section *find_section32(struct segment_command *seg, const char *sectname)
{
    struct section *sect = (struct section *)(seg + 1);
    for (uint32_t i=0; i<seg->nsects; i++, sect++) {
        if (strcmp(sect->sectname, sectname) == 0)
            return sect;
    }
    
    return NULL;
}

__attribute__((always_inline))
struct symtab_command *find_symtab_command(struct mach_header *mh)
{
    return (struct symtab_command *)find_load_command32(mh, LC_SYMTAB);
}

__attribute__((always_inline))
struct dysymtab_command *find_dysymtab_command(struct mach_header *mh)
{
    return (struct dysymtab_command *)find_load_command32(mh, LC_DYSYMTAB);
}
