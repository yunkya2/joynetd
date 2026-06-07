/*
 * Copyright (c) 2026 Yuichi Nakamura (@yunkya2)
 *
 * The MIT License (MIT)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <x68k/dos.h>
#include <x68k/iocs.h>

#include "w55pileder.h"

#include <stdio.h>

//****************************************************************************
// Macros and definitions
//****************************************************************************

#define F55_BASE_ADDR 0xecc0a0

#define F55_ADDR()  (*((volatile uint8_t *)(F55_BASE_ADDR + 0x01)))
#define F55_DATA()  (*((volatile uint8_t *)(F55_BASE_ADDR + 0x00)))

//****************************************************************************
// Global variables
//****************************************************************************

//****************************************************************************
// Private functions
//****************************************************************************

static inline void set_addr(uint16_t addr, uint8_t block)
{
    F55_ADDR() = 0x80 | ((block & 0x1f) << 2) | ((addr >> 14) & 0x03);
    F55_ADDR() = (addr >> 7) & 0x7f;
    F55_ADDR() = addr & 0x7f;
}

//****************************************************************************
// Public functions
//****************************************************************************

void w5500_ini(void)
{
    // TBD
    // WiFi pilederの検出
}


uint8_t w5500_read_b(uint16_t addr, uint8_t block)
{
    set_addr(addr, block);
    return F55_DATA();
}

uint16_t w5500_read_w(uint16_t addr, uint8_t block)
{
    set_addr(addr, block);
    uint16_t data;
    data = F55_DATA() << 8;
    data |= F55_DATA();
    return data;
}

uint32_t w5500_read_l(uint16_t addr, uint8_t block)
{
    set_addr(addr, block);
    uint32_t data;
    data = F55_DATA() << 24;
    data |= F55_DATA() << 16;
    data |= F55_DATA() << 8;
    data |= F55_DATA();
    return data;
}

void w5500_read(uint16_t addr, uint8_t block, uint8_t *data, size_t len)
{
    if (len > 2048) {
        printf("f55_read: len=%lu is too large\n", len);
    }

    set_addr(addr, block);
    __asm__ volatile (
        "movea.l %0,%%a0\n"
        "movea.l %1,%%a1\n"
        "move.w  %2,%%d0\n"
        "movea.l %3,%%a2\n"

        "move.w  %%a0,%%d1\n"
        "btst    #0,%%d1\n"
        "bne.s   4f\n"

        "bra.s   2f\n"
        "1:\n"
        "move.w  %%a2@,%%a1@+\n"
        "move.w  %%a2@,%%a1@+\n"
        "move.w  %%a2@,%%a1@+\n"
        "move.w  %%a2@,%%a1@+\n"
        "move.w  %%a2@,%%a1@+\n"
        "move.w  %%a2@,%%a1@+\n"
        "move.w  %%a2@,%%a1@+\n"
        "move.w  %%a2@,%%a1@+\n"
        "2:\n"
        "subi.w  #16,%%d0\n"
        "bcc.s   1b\n"
        "addi.w  #16,%%d0\n"
        "bra.s   4f\n"

        "3:\n"      // (12+10)*16 = 352 cycles/16 bytes = 22 cycles/byte
        "move.b %%a0@,%%a1@+\n"     // 12
        "4:\n"
        "dbra %%d0,3b\n"            // 10(taken) 14(not taken)

        : : "i"(&F55_DATA()), "a"(data), "d"(len), "i"(0xecc080) : "a0", "a1", "a2", "d0"
    );
}

void w5500_write_b(uint16_t addr, uint8_t block, uint8_t data)
{
    set_addr(addr, block);
    F55_DATA() = data;
}

void w5500_write_w(uint16_t addr, uint8_t block, uint16_t data)
{
    set_addr(addr, block);
    F55_DATA() = (data >> 8) & 0xff;
    F55_DATA() = data & 0xff;
}

void w5500_write_l(uint16_t addr, uint8_t block, uint32_t data)
{
    set_addr(addr, block);
    F55_DATA() = (data >> 24) & 0xff;
    F55_DATA() = (data >> 16) & 0xff;
    F55_DATA() = (data >> 8) & 0xff;
    F55_DATA() = data & 0xff;
}

void w5500_write(uint16_t addr, uint8_t block, const uint8_t *data, size_t len)
{
    set_addr(addr, block);
    for (size_t i = 0; i < len; i++) {
        F55_DATA() = data[i];
    }
}
