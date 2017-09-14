//
//  of32.c
//  OF32
//
//  Created by jndok on 23/08/2017.
//  Copyright © 2017 jndok. All rights reserved.
//

#include <stdio.h>
#include <assert.h>

#include "machoman/machoman.h"
#include "patchfinder32/patchfinder32.h"

enum {
    INSN_SEARCH_MODE_THUMB = 0,
    INSN_SEARCH_MODE_ARM32
};

enum {
    INSN_SEARCH_DIRECTION_FWD = 0,
    INSN_SEARCH_DIRECTION_BWD
};

#define OSSERIALIZER_SERIALIZE_SYMBOL_NAME  "__ZNK12OSSerializer9serializeEP11OSSerialize"
#define OSSYMBOL_GETMETACLASS_SYMBOL_NAME   "__ZNK8OSSymbol12getMetaClassEv"
#define BUFATTR_CPX_SYMBOL_NAME             "_bufattr_cpx"
#define COPYIN_SYMBOL_NAME                  "_copyin"
#define KERNEL_PMAP_SYMBOL_NAME             "_kernel_pmap"

#define SLIDE(type, addr, slide)        (type)((type)addr + (type)slide)
#define UNSLIDE(type, addr, slide)      (type)((type)addr - (type)slide)

#define ADDR_MAP_TO_KCACHE(addr)        ({ uint32_t _tmp_addr =         ((addr) ? SLIDE(uint32_t, UNSLIDE(void*, addr, base), kbase) : 0); _tmp_addr; })
#define ADDR_KCACHE_TO_MAP(addr)        ({ void *_tmp_addr =    (void *)((addr) ? SLIDE(uint64_t, UNSLIDE(uint32_t, addr, kbase), base) : 0); _tmp_addr; })

void *base = NULL;
uint32_t kbase = 0;

struct mach_header *mh = NULL;
struct symtab_command *symtab = NULL;

struct nlist *find_sym(const char *sym)
{
    if (!sym || !base || !symtab)
        return NULL;
    
    void *psymtab = base + symtab->symoff;
    void *pstrtab = base + symtab->stroff;
    
    struct nlist *entry = (struct nlist *)psymtab;
    for (uint32_t i = 0; i < symtab->nsyms; i++, entry++)
        if (!strcmp(sym, (char *)(pstrtab + entry->n_un.n_strx)))
            return entry;
    
    return NULL;
}

uint32_t find_sig(uint8_t *sig, size_t size)
{
    if (!mh || !sig)
        return -1;
    
    struct segment_command *text = find_segment_command32(mh, SEG_TEXT);
    if (!text)
        return -2;
    
    void *search_base = (base + text->fileoff);
    void *p = memmem(search_base, text->filesize, sig, size);
    if (!p)
        return -3;
    
    return (uint32_t)(p - base);
}

void *find_insn(void *start, size_t num, uint32_t insn, uint8_t direction, uint8_t mode)
{
    if (!start || !num || !insn)
        return NULL;
    
    switch (mode) {
        case INSN_SEARCH_MODE_THUMB: {
            for (uint16_t *p = (uint16_t *)start;
                 ((!direction) ? p < ((uint16_t *)start + num) : p > ((uint16_t *)start - num));
                 ((!direction) ? p++ : p--))
            {
                if (*p == insn)
                    return p;
            }
            break;
        }
        
        case INSN_SEARCH_MODE_ARM32: {
            for (uint32_t *p = (uint32_t *)start;
                 ((!direction) ? p < ((uint32_t *)start + num) : p > ((uint32_t *)start - num));
                 ((!direction) ? p++ : p--))
            {
                if (*p == insn)
                    return p;
            }
            break;
        }
            
        default:
            break;
    }
    
    return NULL;
}

/* offset finders */

uint32_t find_OSSerializer_serialize(void)
{
    struct nlist *n = find_sym(OSSERIALIZER_SERIALIZE_SYMBOL_NAME);
    assert(n);
    
    return UNSLIDE(uint32_t, n->n_value, kbase);
}

uint32_t find_OSSymbol_getMetaClass(void)
{
    struct nlist *n = find_sym(OSSYMBOL_GETMETACLASS_SYMBOL_NAME);
    assert(n);
    
    return UNSLIDE(uint32_t, n->n_value, kbase);
}

uint32_t find_calend_gettime(void)
{
    struct nlist *n = find_sym("_clock_get_calendar_nanotime");
    assert(n);
    
    struct segment_command *text = find_segment_command32(mh, SEG_TEXT);
    
    uint32_t xref = n->n_value;
    
    for (uint16_t *p = (uint16_t *)(base + text->fileoff); p < (uint16_t *)(base + text->filesize); p++)
        if (insn_is_32bit(p) && insn_is_bl(p)) {
            uint32_t ip = ADDR_MAP_TO_KCACHE(p);
            if ((ip + (int32_t)insn_bl_imm32(p) + 4) == xref) // XXX: assuming first xref is correct one, may not be (?)
                return UNSLIDE(uint32_t,
                               ADDR_MAP_TO_KCACHE(find_insn(p, 10, 0xB590, INSN_SEARCH_DIRECTION_BWD, INSN_SEARCH_MODE_THUMB)),
                               kbase);
        }
     
    return 0;
}

uint32_t find_bufattr_cpx(void)
{
    struct nlist *n = find_sym(BUFATTR_CPX_SYMBOL_NAME);
    assert(n);
    
    return UNSLIDE(uint32_t, n->n_value, kbase);
}

uint32_t find_clock_ops(void)
{
    struct nlist *n = find_sym("_clock_get_system_value");
    assert(n);
    
    uint32_t val = 0;
    
    for (uint16_t *p = (uint16_t *)(ADDR_KCACHE_TO_MAP(n->n_value)); *p != 0xBF00; p++) {
        if (insn_is_mov_imm(p) && (!insn_mov_imm_rd(p))) {
            val = insn_mov_imm_imm(p);
        } else if (insn_is_movt(p) && (!insn_movt_rd(p))) {
            val |= (insn_movt_imm(p) << 16);
        } else if (insn_is_add_reg(p) && (!insn_add_reg_rd(p)) && (insn_add_reg_rm(p) == 0xF)) {
            uint32_t ip = ADDR_MAP_TO_KCACHE(p);
            uint32_t *addr = (uint32_t *)ADDR_KCACHE_TO_MAP(ip+val+4);
            assert(*addr);
            
            return UNSLIDE(uint32_t, ((*addr) + 0xC), kbase);
        }
    }
    
    return 0;
}

uint32_t find_copyin(void)
{
    struct nlist *n = find_sym(COPYIN_SYMBOL_NAME);
    assert(n);
    
    return UNSLIDE(uint32_t, n->n_value, kbase);
}

uint32_t find_bx_lr(void)
{
    return find_bufattr_cpx() + 0x2;
}

uint32_t find_write_gadget(void)
{
    struct nlist *n = find_sym("_enable_kernel_vfp_context");
    assert(n);
    
    uint16_t *p = find_insn(ADDR_KCACHE_TO_MAP(n->n_value), 50, 0x100C, INSN_SEARCH_DIRECTION_BWD, INSN_SEARCH_MODE_THUMB);
    assert(p);
    
    return UNSLIDE(uint32_t, ADDR_MAP_TO_KCACHE(p), kbase);
}

uint32_t find_vm_kernel_addrperm(void)
{
    struct nlist *n = find_sym("_vm_kernel_addrperm_external");
    assert(n);
    
    uint32_t val = 0;
    
    for (uint16_t *p = (uint16_t *)(base + (n->n_value - kbase)); *p != 0xBF00; p++) {
        if (insn_is_mov_imm(p) && (insn_mov_imm_rd(p) == 2)) {
            val = insn_mov_imm_imm(p);
        } else if (insn_is_movt(p) && (insn_movt_rd(p) == 2)) {
            val |= (insn_movt_imm(p) << 16);
        } else if (insn_is_add_reg(p) && (insn_add_reg_rd(p) == 2) && (insn_add_reg_rm(p) == 0xF)) {
            uint32_t ip = ADDR_MAP_TO_KCACHE(p);
            val += ip+4;
        } else if (insn_is_ldr_imm(p) && (insn_ldr_imm_rt(p) == 2)) {
            val += insn_ldr_imm_imm(p);
            val -= 0x8;
            
            return UNSLIDE(uint32_t, val, kbase);
        }
    }
    
    return 0;
}

uint32_t find_kernel_pmap(void)
{
    struct nlist *n = find_sym(KERNEL_PMAP_SYMBOL_NAME);
    assert(n);
    
    return UNSLIDE(uint32_t, n->n_value, kbase);
}

uint32_t find_flush_dcache(void)
{
    uint8_t sig[] = {
        0x00, 0x00, 0xA0, 0xE3,
        0x5E, 0x0F, 0x07, 0xEE
    };
    
    return find_sig((void *)&sig, sizeof(sig));
}

uint32_t find_invalidate_tlb(void)
{
    uint8_t sig[] = {
        0x00, 0x00, 0xA0, 0xE3,
        0x17, 0x0F, 0x08, 0xEE,
        0x4B, 0xF0, 0x7F, 0xF5,
        0x6F, 0xF0, 0x7F, 0xF5,
        0x1E, 0xFF, 0x2F, 0xE1
    };
    
    return find_sig((void *)&sig, sizeof(sig));
}

uint32_t find_allproc(void)
{
    struct nlist *n = find_sym("_groupmember");
    struct nlist *n2 = find_sym("_kauth_cred_get");
    struct nlist *n3 = find_sym("_lck_mtx_lock");
    
    assert(n);
    assert(n2);
    assert(n3);
    
    boolean_t mark1 = FALSE;
    boolean_t mark2 = FALSE;
    
    uint32_t *p = NULL;
    for (p = (uint32_t *)(ADDR_KCACHE_TO_MAP(n->n_value));; p++) {
        if (insn_is_32bit((uint16_t *)p) && insn_is_bl((uint16_t *)p)) {
            uint32_t ip = ADDR_MAP_TO_KCACHE(p);
            uint32_t val = (ip + (int32_t)insn_bl_imm32((uint16_t *)p) + 4);
            
            if (!mark1 && (val == n2->n_value))
                mark1++;
            else if (!mark2 && mark1 && (val == n3->n_value))
                break;
        }
    }
    
    uint32_t val = 0;
        
    for (uint16_t *p2 = (uint16_t *)p; *p2 != 0xBF00; p2++) {
        if (insn_is_mov_imm(p2) && (!insn_mov_imm_rd(p2))) {
            val = insn_mov_imm_imm(p2);
        } else if (insn_is_movt(p2) && (!insn_movt_rd(p2))) {
            val |= (insn_movt_imm(p2) << 16);
        } else if (insn_is_add_reg(p2) && (!insn_add_reg_rd(p2)) && (insn_add_reg_rm(p2) == 0xF)) {
            uint32_t ip = (uint32_t)((void *)(p2+2) - base) + kbase;
            val += ip;
        } else if (insn_is_ldr_imm(p2) && (!insn_ldr_imm_rt(p2))) {
            val += insn_ldr_imm_imm(p2);
            val += 0x8;
            
            return UNSLIDE(uint32_t, val, kbase);
        }
    }
    
    return 0;
}

uint32_t find_proc_ucred(void)
{
    struct nlist *n = find_sym("_proc_ucred");
    assert(n);
    
    uint32_t *addr = (uint32_t *)(ADDR_KCACHE_TO_MAP(n->n_value));
    assert(addr && *addr);
    
    return ((*addr) >> 16);
}

uint32_t find_setreuid(void)
{
    uint8_t sig[] = {
        0xf0, 0xb5, 0x03, 0xaf,
        0x2d, 0xe9, 0x00, 0x0d,
        0x87, 0xb0, 0x04, 0x46,
        0x02, 0x91, 0x03, 0x94,
        0xd1, 0xf8, 0x00, 0xb0,
        0x4d, 0x68, 0xdf, 0xf7
    };
    
    return find_sig((void *)&sig, sizeof(sig));
}

uint32_t find_task_for_pid(void)
{
    uint8_t sig[] = {
        0xf0, 0xb5, 0x03, 0xaf,
        0x2d, 0xe9, 0x00, 0x0d,
        0x84, 0xb0, 0x01, 0x46,
        0x91, 0xe8, 0x41, 0x08,
        0x00, 0x21, 0x03, 0x91
    };
    
    return find_sig((void *)&sig, sizeof(sig));
}

#define FIND_OFFSET(name)               uint32_t off_##name = find_##name();
#define PRINT_OFFSET(name)              fprintf(stdout, "[%-25s]: %#x\n", #name, off_##name)

#define FIND_AND_PRINT_OFFSET(name)     { FIND_OFFSET(name); PRINT_OFFSET(name); }

int main(int argc, const char * argv[]) {
    
    if (argc != 2) {
        printf("Usage: ./OF32 [kernelcache_path]\n");
        return 1;
    }
    
    fprintf(stdout, "(+) Opening \'%s\', found in %s\n", strrchr(argv[1], '/')+1, argv[1]);
    
    macho_map_t *map = map_macho_with_path(argv[1], O_RDONLY);
    assert(map);
    
    mh = get_mach_header32(map);
    
    if (mh->magic != MH_MAGIC) {
        printf("Error: Invalid kernelcache!\n");
        return 2;
    }
    
    fprintf(stdout, "(+) Successfully mapped and validated kernelcache. Dumping offsets...\n\n");
    
    base = map->map_data;
    kbase = find_segment_command32(mh, SEG_TEXT)->vmaddr;
    
    symtab = find_symtab_command(mh);
    assert(symtab);
    
    FIND_AND_PRINT_OFFSET(OSSerializer_serialize);
    FIND_AND_PRINT_OFFSET(OSSymbol_getMetaClass);
    FIND_AND_PRINT_OFFSET(calend_gettime);
    FIND_AND_PRINT_OFFSET(bufattr_cpx);
    FIND_AND_PRINT_OFFSET(clock_ops);
    FIND_AND_PRINT_OFFSET(copyin);
    FIND_AND_PRINT_OFFSET(bx_lr);
    FIND_AND_PRINT_OFFSET(write_gadget);
    FIND_AND_PRINT_OFFSET(vm_kernel_addrperm);
    FIND_AND_PRINT_OFFSET(kernel_pmap);
    FIND_AND_PRINT_OFFSET(flush_dcache);
    FIND_AND_PRINT_OFFSET(invalidate_tlb);
    FIND_AND_PRINT_OFFSET(setreuid);
    FIND_AND_PRINT_OFFSET(proc_ucred);
    FIND_AND_PRINT_OFFSET(task_for_pid);
    FIND_AND_PRINT_OFFSET(allproc);
    
    return 0;
}
