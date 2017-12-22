//
//  of32.c
//  OF32
//
//  Created by jndok on 23/08/2017.
//  Copyright © 2017 jndok. All rights reserved.
//

#include <stdio.h>
#include <assert.h>

#include "offsetfinder.h"
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

#define ADDR_KCACHE_TO_MAP(addr)        ({ void *_tmp_addr =    (void *)((addr) ? SLIDE(uint64_t, UNSLIDE(uint32_t, addr, kbase), base) : 0); _tmp_addr; })

uint8_t *base = NULL;
uint32_t kbase = 0;
uint32_t ksize = 0;

uint32_t ADDR_MAP_TO_KCACHE(uint16_t* addr) { uint32_t _tmp_addr = ((addr) ? SLIDE(uint32_t, UNSLIDE(void*, addr, base), kbase) : 0); return _tmp_addr; }


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
    uint8_t *p = memmem(search_base, text->filesize, sig, size);
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

static int insn_cmp_imm_rn(uint16_t* i)
{
    if((*i & 0xF800) == 0x2800)
        return (*i >> 8) & 7;
    else if((*i & 0xFBF0) == 0xF1B0 && (*(i + 1) & 0x8F00) == 0x0F00)
        return *i & 0xF;
    else
        return 0;
}

static uint32_t bit_range(uint32_t x, int start, int end)
{
    x = (x << (31 - start)) >> (31 - start);
    x = (x >> end);
    return x;
}

static uint32_t ror(uint32_t x, int places)
{
    return (x >> places) | (x << (32 - places));
}

static int thumb_expand_imm_c(uint16_t imm12)
{
    if(bit_range(imm12, 11, 10) == 0)
    {
        switch(bit_range(imm12, 9, 8))
        {
            case 0:
                return bit_range(imm12, 7, 0);
            case 1:
                return (bit_range(imm12, 7, 0) << 16) | bit_range(imm12, 7, 0);
            case 2:
                return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 8);
            case 3:
                return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 16) | (bit_range(imm12, 7, 0) << 8) | bit_range(imm12, 7, 0);
            default:
                return 0;
        }
    } else
    {
        uint32_t unrotated_value = 0x80 | bit_range(imm12, 6, 0);
        return ror(unrotated_value, bit_range(imm12, 11, 7));
    }
}

static int insn_cmp_imm_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x2800)
        return *i & 0xFF;
    else if((*i & 0xFBF0) == 0xF1B0 && (*(i + 1) & 0x8F00) == 0x0F00)
        return thumb_expand_imm_c(((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF));
    else
        return 0;
}

static int insn_is_cmp_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x2800)
        return 1;
    else if((*i & 0xFBF0) == 0xF1B0 && (*(i + 1) & 0x8F00) == 0x0F00)
        return 1;
    else
        return 0;
}

static uint16_t* find_next_insn_matching(uint32_t region, uint8_t* kdata, size_t ksize, uint16_t* current_instruction, int (*match_func)(uint16_t*)){
    while((uintptr_t)current_instruction < (uintptr_t)kdata+ksize)
    {
        if(insn_is_32bit(current_instruction) && !insn_is_32bit(current_instruction +1))
        {
            current_instruction += 2;
        } else
        {
            ++current_instruction;
        }
        
        if(match_func(current_instruction))
        {
            return current_instruction;
        }
    }
    
    return NULL;
}

/* offset finders */

uint32_t find_OSSerializer_serialize(void)
{
    struct nlist *n = find_sym(OSSERIALIZER_SERIALIZE_SYMBOL_NAME);
    assert(n);
    
    return UNSLIDE(uint32_t, n->n_value+1, kbase);
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
    //0x3accdc
    uint32_t val = 0;
    uint32_t *addr = 0;
    
    uint32_t addr2 = 0;
    
    for (uint16_t *p = (uint16_t *)(ADDR_KCACHE_TO_MAP(n->n_value)); !insn_is_pop(p); p++) {
        if (insn_is_mov_imm(p) && insn_is_mov_imm(p) && !val) {
            val = insn_mov_imm_imm(p++);
        } else if (insn_is_movt(p) && val < (1<<16) ) {
            val |= (insn_movt_imm(p++) << 16);
        } else if (insn_is_add_reg(p) && (insn_add_reg_rm(p) == 0xF) && !addr) {
            uint32_t ip = ADDR_MAP_TO_KCACHE(p);
            addr = (uint32_t *)ADDR_KCACHE_TO_MAP(ip+val+4);
        } else if (insn_is_thumb2_ldr(p)){
            addr2 = *(addr + ((*++p)& ((1<<12)-1))/4);
        } else if (insn_is_ldr_imm(p) && addr2){
            addr2 += insn_ldr_imm_imm(p) + 4;
            return UNSLIDE(uint32_t, (addr2), kbase);
        }
    }
    return 0;
}

uint32_t find_copyin(void){
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
    struct nlist *n = find_sym("_buf_kernel_addrperm_addr"); //THIS WAS TESTED ON 8.4.1
    assert(n);
    
    uint32_t val = 0;
    uint32_t *addr = 0;
    uint32_t addr2 = 0;
    
    for (uint16_t *p = (uint16_t *)(base + (n->n_value - kbase)); *p != 0xBF00; p++) {
        if (insn_is_mov_imm(p) && insn_is_mov_imm(p) && !val) {
            val = insn_mov_imm_imm(p++);
        } else if (insn_is_movt(p) && val < (1<<16) ) {
            val |= (insn_movt_imm(p++) << 16);
        } else if (insn_is_add_reg(p) && (insn_add_reg_rm(p) == 0xF) && !addr) {
            uint32_t ip = ADDR_MAP_TO_KCACHE(p);
            addr = (uint32_t *)ADDR_KCACHE_TO_MAP(ip+val+4);
        } else if (insn_is_thumb2_ldr(p)){
            addr2 = (uint32_t)ADDR_MAP_TO_KCACHE(addr) + ((*++p)& ((1<<12)-1));
            return UNSLIDE(uint32_t, (addr2-4), kbase);
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

uint32_t find_kernel_pmap_nosym(void){
    uint8_t *str = memmem(base, ksize, "\"out of ptd entry", sizeof("\"out of ptd entry")-1);
    assert(str);
    
    uint16_t *ref = find_literal_ref(kbase, base, ksize, str-(uint8_t*)base);
    assert(ref);
    
    while (!insn_is_ldr_imm(ref)) ref ++;
    
    uint32_t *pmap = 0;
    for (uint16_t *p = ref; p>base; p--) {
        if (insn_is_bl(p)) {
            int32_t dst = (insn_bl_imm32(p) + 4);
            uint16_t *abs_dst = (uint16_t *)((uint8_t*)p+dst);
            if (abs_dst == ref){
                pmap = p;
                break;
            }
        }
    }
    
    while (!insn_is_movt(pmap) || !insn_is_mov_imm(pmap-1)) pmap--;
    pmap--;
    uint32_t pmap_add_val = insn_mov_imm_imm(pmap++);
    pmap_add_val |= insn_movt_imm(pmap++) << 16;
    
    pmap = (uint8_t*)pmap + pmap_add_val + 4;
    
    return UNSLIDE(uint32_t, pmap, base);
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
    uint8_t *str = memmem(base, ksize, "\"pgrp_add : pgrp is dead adding process", sizeof("pgrp_add : pgrp is dead adding process")-1);
    assert(str);
    
    uint16_t *ref = find_literal_ref(kbase, base, ksize, str-(uint8_t*)base);
    assert(ref);

    while (!insn_is_thumb2_pop(ref++)) assert(ref<base+ksize);
    uint16_t *bottom=ref;
    
    while (!insn_is_thumb2_push(--ref)) assert(ref>base);
    uint16_t *top = ref;
    
    uint16_t *itttne = 0;
    for (uint16_t*i=bottom; i>base; i--)
        if (*i == 0xbf1e){
            itttne = i;
            break;
        }
    assert(itttne);
    
    uint16_t *ittne = 0;
    for (uint16_t*i=itttne; i<bottom; i++)
        if (*i == 0xbf1c){
            ittne = i;
            break;
        }
    assert(ittne);
    
    uint32_t offset = 0;
    uint16_t *pos = 0;
    int rn = 0;
    for (uint16_t *i=ittne; i>itttne; i--) {
        if (insn_is_thumb2_ldr(i)){
            pos = i;
            offset = *(i+1) & ((1<<12)-1);
            rn = *i & ((1<<4)-1);
            break;
        }
    }
    assert(offset);
    
    uint32_t val = 0;
    for (uint16_t *p=pos; p>top; p--) {
        if (insn_add_reg_rm(p) == 15 && insn_add_reg_rd(p) == rn){
            offset += (uint8_t*)p - (uint8_t*)base + kbase;
        }else if (insn_is_movt(p) && insn_movt_rd(p) == rn && !(val>>16)){
            val |= insn_movt_imm(p) << 16;
        }else if (insn_is_mov_imm(p) && insn_mov_imm_rd(p) == rn && !(val & ((1<<16)-1))){
            val |= insn_mov_imm_imm(p);
        }
        if (val >> 16 && (val & ((1<<16)-1)))
            break;
    }
    offset += val + 4;
    
    return UNSLIDE(uint32_t, offset, kbase);
}

uint32_t find_proc_ucred(void){
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

uint32_t find_zone_map(){
    uint8_t *ptr=memmem(base, ksize, "zone_init", sizeof("zone_init"));
    uint16_t *ref = find_literal_ref(kbase, base, ksize, ptr-(uint8_t*)base);
    
    uint32_t val = 0;
    int rd = -1;
    while (!(val >> 16 && (val & ((1<<16)-1)))){
        if (insn_is_mov_imm(ref)){
            int trd = insn_movt_rd(ref);
            if (rd != trd && rd != -1)
                return 0;
            else
                rd = trd;
            val |= insn_mov_imm_imm(ref++);
        }else if (insn_is_movt(ref)){
            int trd = insn_movt_rd(ref);
            if (rd != trd && rd != -1)
                return 0;
            else
                rd = trd;
            val |= insn_movt_imm(ref++) << 16;
        }
        ref++;
    }
    while (!insn_is_add_reg(ref))
        ref++;
    
    if (insn_add_reg_rd(ref) != rd || insn_add_reg_rm(ref) != 15)
        return 0;
    
    return (uint32_t)UNSLIDE(uint32_t,((uint8_t*)ref+4+val),base);
}

uint32_t find_kernel_map(void){
    struct nlist *n = find_sym("_kernel_map");
    assert(n);
    return UNSLIDE(uint32_t, n->n_value, kbase);
}

uint32_t find_kernel_task(void){
    struct nlist *n = find_sym("_kernel_task");
    assert(n);
    return UNSLIDE(uint32_t, n->n_value, kbase);
}

uint32_t find_realhost(void){
    struct nlist *n = find_sym("_KUNCExecute");
    assert(n);
    uint16_t *ref = ADDR_KCACHE_TO_MAP(n->n_value);

    uint32_t val = 0;
    int rd = -1;
    while (!(val >> 16 && (val & ((1<<16)-1)))){
        if (insn_is_mov_imm(ref)){
            int trd = insn_movt_rd(ref);
            if (rd != trd && rd != -1)
                return 0;
            else
                rd = trd;
            val |= insn_mov_imm_imm(ref++);
        }else if (insn_is_movt(ref)){
            int trd = insn_movt_rd(ref);
            if (rd != trd && rd != -1)
                return 0;
            else
                rd = trd;
            val |= insn_movt_imm(ref++) << 16;
        }
        ref++;
    }
    
    if (insn_add_reg_rd(ref) != rd || insn_add_reg_rm(ref) != 15)
        return 0;
    
    return (uint32_t)UNSLIDE(uint32_t,((uint8_t*)ref+4+val),base);
}

uint32_t find_bzero(void){
    struct nlist *n = find_sym("___bzero");
    assert(n);
    return UNSLIDE(uint32_t, n->n_value, kbase);
}

uint32_t find_bcopy(void){
    struct nlist *n = find_sym("_bcopy");
    assert(n);
    return UNSLIDE(uint32_t, n->n_value+1, kbase);
}

uint32_t find_copyout(void){
    struct nlist *n = find_sym("_copyout");
    assert(n);
    return UNSLIDE(uint32_t, n->n_value, kbase);
}

uint32_t find_ipc_port_alloc_special(void){
    struct nlist *n = find_sym("_KUNCGetNotificationID");
    assert(n);
    uint16_t *ref = ADDR_KCACHE_TO_MAP(n->n_value);
    
    while (!insn_is_bl(ref))
        ref++;
    ref++;
    while (!insn_is_bl(ref))
        ref++;
    
    int32_t val = insn_bl_imm32(ref);
    
    return (uint32_t)UNSLIDE(uint32_t,((uint8_t*)ref+4+val+1),base);
}

uint32_t find_ipc_kobject_set(void){
    struct nlist *n = find_sym("_KUNCGetNotificationID");
    assert(n);
    uint16_t *ref = ADDR_KCACHE_TO_MAP(n->n_value);
    
    while (!insn_is_bl(ref))
        ref++;
    ref++;
    while (!insn_is_bl(ref))
        ref++;
    ref++;
    while (!insn_is_bl(ref))
        ref++;
    
    int32_t val = insn_bl_imm32(ref);
    
    return (uint32_t)UNSLIDE(uint32_t,((uint8_t*)ref+4+val+1),base);
}

uint32_t find_ipc_port_make_send(void){
    struct nlist *n = find_sym("_convert_task_to_port");
    assert(n);
    uint16_t *ref = ADDR_KCACHE_TO_MAP(n->n_value);
    
    while (!insn_is_bl(ref))
        ref++;
    ref++;
    while (!insn_is_bl(ref))
        ref++;
    
    int32_t val = insn_bl_imm32(ref);
    
    return (uint32_t)UNSLIDE(uint32_t,((uint8_t*)ref+4+val+1),base);
}

uint32_t find_rop_ldr_r0_r0_0xc(){
    uint8_t *p = memmem(base, ksize, "\xC0\x68\x70\x47", 4);
    if (!p)
        return 0;
    
    return (uint32_t)(p+1 - base);
}

uint32_t find_ipc_space_is_task(){
    uint8_t *ptr=memmem(base, ksize, "\"ipc_task_init\"", sizeof("\"ipc_task_init\""));
    uint16_t *ref = find_literal_ref(kbase, base, ksize, (uint32_t)(ptr-base));
    
    int foundboth = 0;
    int rd = -1;
    do{
        ref--;
        if (insn_is_mov_imm(ref)){
            int trd = insn_movt_rd(ref);
            if (rd != trd && rd != -1)
                return 0;
            else
                rd = trd;
            foundboth |=1;
        }else if (insn_is_movt(ref)){
            int trd = insn_movt_rd(ref);
            if (rd != trd && rd != -1)
                return 0;
            else
                rd = trd;
            foundboth |=2;
        }
    } while (foundboth!=3);
    
    uint16_t *beq = find_rel_branch_ref(ref, 0x1200, -1,insn_is_thumb2_branch);
    assert(beq);
    
    uint16_t *strw = beq;
    while (!insn_is_thumb2_strw(--strw));
    
    return insn_thumb2_strw_imm(strw);
}


typedef struct mig_subsystem_struct {
    uint32_t min;
    uint32_t max;
    char *names;
} mig_subsys;

mig_subsys task_subsys ={ 0xd48, 0xd7a , NULL};
uint32_t find_task_itk_self(){
    uint32_t *task_subsystem=memmem(base, ksize, &task_subsys, 4);
    if (!task_subsystem)
        return 0;
    task_subsystem += 5;
    
    uint16_t *mach_ports_register = task_subsystem[3*6];
    mach_ports_register = ADDR_KCACHE_TO_MAP(((uint64_t)mach_ports_register &~1));
    
    
    struct nlist *n = find_sym("_lck_mtx_lock");
    assert(n);
    uint16_t *lck_mtx_lock = ADDR_KCACHE_TO_MAP(n->n_value);
    
    uint16_t *thebl = 0;
    for (uint16_t *p = mach_ports_register; p<mach_ports_register+0x200; p++) {
        if (insn_is_bl(p)) {
            int32_t dst = (insn_bl_imm32(p) + 4);
            uint16_t *abs_dst = (uint16_t *)((uint8_t*)p+dst);
            if (abs_dst == lck_mtx_lock){
                thebl = p;
                break;
            }
        }
    }
    
    while (!insn_is_thumb2_ldr(++thebl));
    
    return insn_thumb2_ldr_imm_imm(thebl);
}

uint32_t find_task_itk_registered(){
    uint32_t *task_subsystem=memmem(base, ksize, &task_subsys, 4);
    if (!task_subsystem)
        return 0;
    task_subsystem += 5;
    
    uint16_t *mach_ports_register = task_subsystem[3*6];
    mach_ports_register = ADDR_KCACHE_TO_MAP(((uint64_t)mach_ports_register &~1));
    
    
    struct nlist *n = find_sym("_lck_mtx_lock");
    assert(n);
    uint16_t *lck_mtx_lock = ADDR_KCACHE_TO_MAP(n->n_value);
    
    uint16_t *thebl = 0;
    for (uint16_t *p = mach_ports_register; p<mach_ports_register+0x200; p++) {
        if (insn_is_bl(p)) {
            int32_t dst = (insn_bl_imm32(p) + 4);
            uint16_t *abs_dst = (uint16_t *)((uint8_t*)p+dst);
            if (abs_dst == lck_mtx_lock){
                thebl = p;
                break;
            }
        }
    }
    
    while (!insn_is_thumb2_ldr(++thebl));
    
    while (!insn_is_thumb2_ldr(++thebl));
    
    return insn_thumb2_ldr_imm_imm(thebl);
}

uint32_t find_vtab_get_external_trap_for_index(){
    struct nlist *n = find_sym("__ZTV12IOUserClient");
    assert(n);
    uint32_t *vtab_IOUserClient = ADDR_KCACHE_TO_MAP(n->n_value);
    vtab_IOUserClient += 2;
    
    struct nlist *nn = find_sym("__ZN12IOUserClient23getExternalTrapForIndexEm");
    assert(nn);
    uint32_t getExternalTrapForIndex = nn->n_value+1;
    
    for (int i=0; i<0x200; i++) {
        if (vtab_IOUserClient[i]==getExternalTrapForIndex)
            return i;
    }
    
    return 0;
}

//IOUSERCLIENT_IPC
mig_subsys host_priv_subsys = { 400, 426 } ;
uint32_t find_iouserclient_ipc(){
    uint32_t *host_priv_subsystem=memmem(base, ksize, &host_priv_subsys, 8);
    if (!host_priv_subsystem)
        return 0;
    
    uint32_t *thetable = 0;
    while (host_priv_subsystem>base){
        struct _anon{
            uint32_t ptr;
            uint32_t z0;
            uint32_t z1;
        } *obj = host_priv_subsystem;
        if (!obj->z0 && !obj->z1 &&
            !memcmp(&obj[0], &obj[1], sizeof(struct _anon)) &&
            !memcmp(&obj[0], &obj[2], sizeof(struct _anon)) &&
            !memcmp(&obj[0], &obj[3], sizeof(struct _anon)) &&
            !memcmp(&obj[0], &obj[4], sizeof(struct _anon)) &&
            !obj[-1].ptr && obj[-1].z0 == 1 && !obj[-1].z1) {
            thetable = host_priv_subsystem;
            break;
        }
        host_priv_subsystem--;
    }
    
    uint16_t *iokit_user_client_trap = ((uint32_t)UNSLIDE(uint32_t, (thetable[100*3] &~1), kbase) + base);
    
    uint16_t *bl_to_iokit_add_connect_reference = iokit_user_client_trap;
    
    while (!insn_is_bl(bl_to_iokit_add_connect_reference) || bl_to_iokit_add_connect_reference[-1] != 0x4620) //mov r0, r4
           bl_to_iokit_add_connect_reference++;
    
    int32_t dst = (insn_bl_imm32(bl_to_iokit_add_connect_reference) + 4);
    uint16_t *abs_dst = (uint16_t *)((uint8_t*)bl_to_iokit_add_connect_reference+dst);
    
    struct nlist *n = find_sym("_OSDecrementAtomic");
    assert(n);
    uint16_t *OSDecrementAtomic = ADDR_KCACHE_TO_MAP(n->n_value);
    
    uint16_t *thebl = 0;
    for (uint16_t *p = abs_dst; p<abs_dst+0x200; p++) {
        if (insn_is_bl(p)) {
            int32_t dst = (insn_bl_imm32(p) + 4);
            uint16_t *abs_dst = (uint16_t *)((uint8_t*)p+dst);
            if (abs_dst == OSDecrementAtomic){
                thebl = p;
                break;
            }
        }
    }
    thebl-=2;
    
    assert(insn_is_thumb2_add(thebl) && insn_thumb2_add_rd(thebl) == 0);
    
    return insn_thumb2_add_imm(thebl);
}

uint32_t find_chgproccnt(){
    uint8_t *ptr=memmem(base, ksize, "\"chgproccnt: lost user\"", sizeof("\"chgproccnt: lost user\""));
    uint16_t *ref = find_literal_ref(kbase, base, ksize, (uint32_t)(ptr-base));
    
    while (!insn_is_thumb2_push(--ref));
    while (!insn_is_push(--ref));
    
    return UNSLIDE(uint8_t*, ref+1, base);
}

uint32_t find_kauth_cred_ref(void){
    struct nlist *n = find_sym("_kauth_cred_ref");
    assert(n);
    return UNSLIDE(uint32_t, n->n_value+1, kbase);
}

uint32_t find_sizeof_task(){
    uint8_t *ptr=memmem(base, ksize, "tasks", sizeof("tasks"));
    uint16_t *ref = find_literal_ref(kbase, base, ksize, (uint32_t)(ptr-base));
    assert(ref);
    ref++;
    
    uint16_t *zinit = 0;
    
    struct nlist *n = find_sym("_zinit");
    if (n) {
        zinit = ADDR_KCACHE_TO_MAP(n->n_value);
    }else if ((ptr=memmem(base, ksize, "zlog%d", sizeof("zlog%d")))){
        uint16_t *ref2 = find_literal_ref(kbase, base, ksize, (uint32_t)(ptr-base));
        if (ref2) {
            while (!insn_is_thumb2_push(--ref2));
            while (!insn_is_push(--ref2));
            zinit = ref2;
        }
    }

    uint16_t *bl = ref+2;
    if (!insn_is_bl(bl))
        bl+=2;
    
    assert(insn_is_mov_imm(ref) && insn_is_bl(bl));
    
    if (zinit)
        assert(insn_bl_imm32(bl)+4+(uint8_t*)bl == zinit);
    else{
        fprintf(stderr, "WARNING: can't find zinit. Can't verify sizeof_task\n");
    }
    
    return insn_mov_imm_imm(ref);
}

uint32_t find_task_bsd_info(void){
    struct nlist *n = find_sym("_get_bsdtask_info");
    assert(n);
    
    uint32_t *addr = (uint32_t *)(ADDR_KCACHE_TO_MAP(n->n_value));
    assert(addr && *addr);
    
    return ((*addr) >> 16);
}

#define FIND_OFFSET(name)               uint32_t off_##name = find_##name()
#define PRINT_OFFSET(name,slide)              fprintf(stdout, "pushOffset(0x%08x); //%s\n", off_##name + (slide ? kbase : 0), #name)

#define FIND_AND_PRINT_OFFSET(name,slide)     { FIND_OFFSET(name); PRINT_OFFSET(name,slide);}

int printKernelConfig(macho_map_t *map, int (*doprint)(char*version)) {
//    macho_map_t *map = map_macho_with_path(kernelpath, O_RDONLY);
    assert(map);
    
    mh = get_mach_header32(map);
    
    if (mh->magic != MH_MAGIC) {
        printf("Error: Invalid kernelcache!\n");
        return 2;
    }
    fprintf(stderr, "(+) Successfully mapped and validated kernelcache. Dumping offsets...\n\n");
    
    base = map->map_data;
    ksize = (uint32_t)map->map_size;
    kbase = find_segment_command32(mh, SEG_TEXT)->vmaddr;
    
    symtab = find_symtab_command(mh);
    assert(symtab);
    char *version = ADDR_KCACHE_TO_MAP(find_sym("_version")->n_value);
    
    if (!doprint(version))
        return 1;

    printf("if (!dstrcmp(uname, \"%s\")){\n", version);
    FIND_AND_PRINT_OFFSET(zone_map,1);
    FIND_AND_PRINT_OFFSET(kernel_map,1);
    FIND_AND_PRINT_OFFSET(kernel_task,1);
    FIND_AND_PRINT_OFFSET(realhost,1);
    FIND_AND_PRINT_OFFSET(bzero,1);
    FIND_AND_PRINT_OFFSET(bcopy,1);
    FIND_AND_PRINT_OFFSET(copyin,1);
    FIND_AND_PRINT_OFFSET(copyout,1);
    FIND_AND_PRINT_OFFSET(ipc_port_alloc_special,1);
    FIND_AND_PRINT_OFFSET(ipc_kobject_set,1);
    FIND_AND_PRINT_OFFSET(ipc_port_make_send,1);
    FIND_AND_PRINT_OFFSET(rop_ldr_r0_r0_0xc,1);
    FIND_AND_PRINT_OFFSET(chgproccnt,1);
    FIND_AND_PRINT_OFFSET(kauth_cred_ref,1);
    FIND_AND_PRINT_OFFSET(OSSerializer_serialize,1);
    
    FIND_AND_PRINT_OFFSET(ipc_space_is_task,0);
    FIND_AND_PRINT_OFFSET(task_itk_self,0);
    FIND_AND_PRINT_OFFSET(task_itk_registered,0);
    FIND_AND_PRINT_OFFSET(vtab_get_external_trap_for_index,0);
    FIND_AND_PRINT_OFFSET(iouserclient_ipc,0);
    FIND_AND_PRINT_OFFSET(proc_ucred,0);
    FIND_AND_PRINT_OFFSET(task_bsd_info,0);
    FIND_AND_PRINT_OFFSET(sizeof_task,0);
    
    
    
    printf("}");
    fprintf(stderr, "\n");

    
    return 0;
}

