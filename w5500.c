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

#include "w5500.h"

#define PRINTF(...)
//#define PRINTF(...) printf(__VA_ARGS__)

#define SPI_MOSI    0x01
#define SPI_CLK     0x02
#define SPI_CS      0x04

#if 1
// Port A
#define JOYPORT_A       0xe9a001
#define SPI_MISO        0x10
#define MISO_SHIFT      4
#define JOYPORT_CTL_INI 0x8a        // A OUT  B IN  C IN:OUT
#else
// Port B
#define JOYPORT_A       0xe9a003
#define SPI_MISO        0x20
#define MISO_SHIFT      3
#define JOYPORT_CTL_INI 0x98        // A IN  B OUT  C IN:OUT
#endif
#define JOYPORT_C       0xe9a005
#define JOYPORT_CTL     0xe9a007
#define JOYPORT_CTL_FIN 0x92        // A IN  B IN  C OUT

#define STRINGIFY(s)    #s
#define STR(s)          STRINGIFY(s)

#define INI_8255()      *(volatile uint8_t *)JOYPORT_CTL = JOYPORT_CTL_INI
#define FIN_8255()      *(volatile uint8_t *)JOYPORT_CTL = JOYPORT_CTL_FIN
#define INI_W5500_CS()  *(volatile uint8_t *)JOYPORT_A = SPI_MOSI | SPI_CLK | 0
#define FIN_W5500_CS()  *(volatile uint8_t *)JOYPORT_A = SPI_MOSI | SPI_CLK | SPI_CS

//////////////////////////////////////////////////////////////////////////////

static inline void spi_sendbyte(int data)
{
    for (int i = 0; i < 8; i++) {
        *(volatile uint8_t *)JOYPORT_A = ((data & 0x80) ? SPI_MOSI : 0) | 0       | 0;
        *(volatile uint8_t *)JOYPORT_A = ((data & 0x80) ? SPI_MOSI : 0) | SPI_CLK | 0;
        data <<= 1;
    }
}

static inline int spi_recvbyte(void)
{
    int data = 0;
#if 0
    for (int i = 0; i < 8; i++) {
        *(volatile uint8_t *)JOYPORT_A = SPI_MOSI | 0       | 0;
        *(volatile uint8_t *)JOYPORT_A = SPI_MOSI | SPI_CLK | 0;
        data <<= 1;
        data |= (*(volatile uint8_t *)JOYPORT_C & SPI_MISO) ? 1 : 0;
    }
#else
    __asm__ volatile (
        "lea.l " STR(JOYPORT_A) ",%%a0\n"
        "lea.l " STR(JOYPORT_C) ",%%a1\n"
        "moveq.l #0,%0\n"
        "moveq.l #1,%%d1\n"
        "moveq.l #3,%%d2\n"
        "moveq.l #" STR(SPI_MISO) ",%%d3\n"

        "move.b %%d1,%%a0@\n"
        "move.b %%d2,%%a0@\n"
        "move.b %%a1@,%%d4\n"
        "and.b  %%d3,%%d4\n"
        "or.b   %%d4,%0\n"
        "rol.b  #1,%0\n"

        "move.b %%d1,%%a0@\n"
        "move.b %%d2,%%a0@\n"
        "move.b %%a1@,%%d4\n"
        "and.b  %%d3,%%d4\n"
        "or.b   %%d4,%0\n"
        "rol.b  #1,%0\n"

        "move.b %%d1,%%a0@\n"
        "move.b %%d2,%%a0@\n"
        "move.b %%a1@,%%d4\n"
        "and.b  %%d3,%%d4\n"
        "or.b   %%d4,%0\n"
        "rol.b  #1,%0\n"

        "move.b %%d1,%%a0@\n"
        "move.b %%d2,%%a0@\n"
        "move.b %%a1@,%%d4\n"
        "and.b  %%d3,%%d4\n"
        "or.b   %%d4,%0\n"
        "rol.b  #1,%0\n"

        "move.b %%d1,%%a0@\n"
        "move.b %%d2,%%a0@\n"
        "move.b %%a1@,%%d4\n"
        "and.b  %%d3,%%d4\n"
        "or.b   %%d4,%0\n"
        "rol.b  #1,%0\n"

        "move.b %%d1,%%a0@\n"
        "move.b %%d2,%%a0@\n"
        "move.b %%a1@,%%d4\n"
        "and.b  %%d3,%%d4\n"
        "or.b   %%d4,%0\n"
        "rol.b  #1,%0\n"

        "move.b %%d1,%%a0@\n"
        "move.b %%d2,%%a0@\n"
        "move.b %%a1@,%%d4\n"
        "and.b  %%d3,%%d4\n"
        "or.b   %%d4,%0\n"
        "rol.b  #1,%0\n"

        "move.b %%d1,%%a0@\n"
        "move.b %%d2,%%a0@\n"
        "move.b %%a1@,%%d4\n"
        "and.b  %%d3,%%d4\n"
        "or.b   %%d4,%0\n"

        "rol.b  #" STR(MISO_SHIFT) ",%0\n"
        : "=d"(data) : : "a0","a1","d1","d2","d3","d4"
    );
#endif
    return data;
}

//////////////////////////////////////////////////////////////////////////////

void w5500_ini(void)
{
    INI_8255();
    FIN_W5500_CS();
}

void w5500_fin(void)
{
    FIN_8255();
}


uint8_t w5500_read_b(uint16_t addr, uint8_t block)
{
    uint8_t data;
    INI_W5500_CS();
    spi_sendbyte((addr >> 8) & 0xff);
    spi_sendbyte(addr & 0xff);
    spi_sendbyte((block << 3) | 0 | 1);
    data = spi_recvbyte();
    FIN_W5500_CS();
    return data;
}

uint16_t w5500_read_w(uint16_t addr, uint8_t block)
{
    uint16_t data;
    INI_W5500_CS();
    spi_sendbyte((addr >> 8) & 0xff);
    spi_sendbyte(addr & 0xff);
    spi_sendbyte((block << 3) | 0 | 2);
    data = spi_recvbyte() << 8;
    data |= spi_recvbyte();
    FIN_W5500_CS();
    return data;
}

uint32_t w5500_read_l(uint16_t addr, uint8_t block)
{
    uint32_t data;
    INI_W5500_CS();
    spi_sendbyte((addr >> 8) & 0xff);
    spi_sendbyte(addr & 0xff);
    spi_sendbyte((block << 3) | 0 | 3);
    data = spi_recvbyte() << 24;
    data |= spi_recvbyte() << 16;
    data |= spi_recvbyte() << 8;
    data |= spi_recvbyte();
    FIN_W5500_CS();
    return data;
}

void w5500_read(uint16_t addr, uint8_t block, uint8_t *data, size_t len)
{
    INI_W5500_CS();
    spi_sendbyte((addr >> 8) & 0xff);
    spi_sendbyte(addr & 0xff);
    spi_sendbyte((block << 3) | 0 | 0);
#if 0
    for (int i = 0; i < len; i++) {
        data[i] = spi_recvbyte();
    }
#else
    __asm__ volatile (
        "lea.l " STR(JOYPORT_A) ",%%a0\n"
        "lea.l " STR(JOYPORT_C) ",%%a1\n"
        "moveq.l #1,%%d1\n"
        "moveq.l #3,%%d2\n"
        "moveq.l #" STR(SPI_MISO) ",%%d3\n"

        "1:\n"
        "moveq.l #0,%%d0\n"
        "move.b %%d1,%%a0@\n"
        "move.b %%d2,%%a0@\n"
        "move.b %%a1@,%%d4\n"
        "and.b  %%d3,%%d4\n"
        "or.b   %%d4,%%d0\n"
        "rol.b  #1,%%d0\n"

        "move.b %%d1,%%a0@\n"
        "move.b %%d2,%%a0@\n"
        "move.b %%a1@,%%d4\n"
        "and.b  %%d3,%%d4\n"
        "or.b   %%d4,%%d0\n"
        "rol.b  #1,%%d0\n"

        "move.b %%d1,%%a0@\n"
        "move.b %%d2,%%a0@\n"
        "move.b %%a1@,%%d4\n"
        "and.b  %%d3,%%d4\n"
        "or.b   %%d4,%%d0\n"
        "rol.b  #1,%%d0\n"

        "move.b %%d1,%%a0@\n"
        "move.b %%d2,%%a0@\n"
        "move.b %%a1@,%%d4\n"
        "and.b  %%d3,%%d4\n"
        "or.b   %%d4,%%d0\n"
        "rol.b  #1,%%d0\n"

        "move.b %%d1,%%a0@\n"
        "move.b %%d2,%%a0@\n"
        "move.b %%a1@,%%d4\n"
        "and.b  %%d3,%%d4\n"
        "or.b   %%d4,%%d0\n"
        "rol.b  #1,%%d0\n"

        "move.b %%d1,%%a0@\n"
        "move.b %%d2,%%a0@\n"
        "move.b %%a1@,%%d4\n"
        "and.b  %%d3,%%d4\n"
        "or.b   %%d4,%%d0\n"
        "rol.b  #1,%%d0\n"

        "move.b %%d1,%%a0@\n"
        "move.b %%d2,%%a0@\n"
        "move.b %%a1@,%%d4\n"
        "and.b  %%d3,%%d4\n"
        "or.b   %%d4,%%d0\n"
        "rol.b  #1,%%d0\n"

        "move.b %%d1,%%a0@\n"
        "move.b %%d2,%%a0@\n"
        "move.b %%a1@,%%d4\n"
        "and.b  %%d3,%%d4\n"
        "or.b   %%d4,%%d0\n"

        "rol.b  #" STR(MISO_SHIFT) ",%%d0\n"
        "move.b %%d0,%0@+\n"
        "subq.l #1,%1\n"
        "bhi.s 1b\n"
        : : "a"(data),"d"(len) : "a0","a1","d0","d1","d2","d3","d4"
    );
#endif
    FIN_W5500_CS();
}

void w5500_write_b(uint16_t addr, uint8_t block, uint8_t data)
{
    INI_W5500_CS();
    spi_sendbyte((addr >> 8) & 0xff);
    spi_sendbyte(addr & 0xff);
    spi_sendbyte((block << 3) | 4 | 1);
    spi_sendbyte(data);
    FIN_W5500_CS();
}

void w5500_write_w(uint16_t addr, uint8_t block, uint16_t data)
{
    INI_W5500_CS();
    spi_sendbyte((addr >> 8) & 0xff);
    spi_sendbyte(addr & 0xff);
    spi_sendbyte((block << 3) | 4 | 2);
    spi_sendbyte((data >> 8) & 0xff);
    spi_sendbyte(data & 0xff);
    FIN_W5500_CS();
}

void w5500_write_l(uint16_t addr, uint8_t block, uint32_t data)
{
    INI_W5500_CS();
    spi_sendbyte((addr >> 8) & 0xff);
    spi_sendbyte(addr & 0xff);
    spi_sendbyte((block << 3) | 4 | 3);
    spi_sendbyte((data >> 24) & 0xff);
    spi_sendbyte((data >> 16) & 0xff);
    spi_sendbyte((data >> 8) & 0xff);
    spi_sendbyte(data & 0xff);
    FIN_W5500_CS();
}

void w5500_write(uint16_t addr, uint8_t block, uint8_t *data, size_t len)
{
    INI_W5500_CS();
    spi_sendbyte((addr >> 8) & 0xff);
    spi_sendbyte(addr & 0xff);
    spi_sendbyte((block << 3) | 4 | 0);
    for (int i = 0; i < len; i++) {
        spi_sendbyte(data[i]);
    }
    FIN_W5500_CS();
}
