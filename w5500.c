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

//****************************************************************************
// Macros and definitions
//****************************************************************************

// JOYPORT pin assign

#define SPI_MOSI    0x01
#define SPI_CLK     0x02
#define SPI_CS      0x04

// 8255 parameter structure for Port A/B

struct w5500_param {
    uint32_t port_a;            // +0  8255 Port A/B address
    uint32_t port_c;            // +4  8255 Port C address
    uint32_t port_ctl;          // +8  8255 Port Control address
    uint8_t port_ctl_ini;       // +12 Port control initialize value
    uint8_t port_ctl_fin;       // +13 Port control finalize value
    uint8_t spi_miso;           // +14 SPI MISO bit mask
    uint8_t spi_miso_shift;     // +15 SPI data bit shift count
};

// 8255 port control macro

#define W5500_CS_ENB()  do { *(volatile uint8_t *)joyport->port_a = SPI_MOSI | SPI_CLK | 0; } while(0)
#define W5500_CS_DIS()  do { *(volatile uint8_t *)joyport->port_a = SPI_MOSI | SPI_CLK | SPI_CS; } while(0)

//****************************************************************************
// Global variables
//****************************************************************************

static const struct w5500_param w5500_param[] = {
    // Port A
    { 0xe9a001, 0xe9a005, 0xe9a007,     // Port A address
      0x8a,                             // A OUT  B IN  C IN:OUT
      0x92,                             // A IN   B IN  C OUT
      0x10, 4 },                        // MISO: PC4
    // Port B
    { 0xe9a003, 0xe9a005, 0xe9a007,     // Port B address
      0x98,                             // A IN   B OUT C IN:OUT
      0x92,                             // A IN   B IN  C OUT
      0x20, 5 },                        // MISO: PC5
};

static const struct w5500_param *joyport = NULL;

//****************************************************************************
// Private functions
//****************************************************************************

// SPI receive asm macros
// a0: PORT_A address  a1: PORT_C address
// d1: SPI_MOSI  d2: SPI_MOSI|SPI_CLK  d3: SPI_MISO  d4: SPI data bit shift count
// d5: temporary

#define W5500_RECV_BIT(d)   \
    "move.b %%d1,%%a0@\n"   \
    "move.b %%d2,%%a0@\n"   \
    "move.b %%a1@,%%d5\n"   \
    "and.b  %%d3,%%d5\n"    \
    "or.b   %%d5," d "\n"

#define W5500_RECV_8BITS(d) \
    W5500_RECV_BIT(d)       \
    "add.w   " d "," d "\n" \
    W5500_RECV_BIT(d)       \
    "add.w   " d "," d "\n" \
    W5500_RECV_BIT(d)       \
    "add.w   " d "," d "\n" \
    W5500_RECV_BIT(d)       \
    "add.w   " d "," d "\n" \
    W5500_RECV_BIT(d)       \
    "add.w   " d "," d "\n" \
    W5500_RECV_BIT(d)       \
    "add.w   " d "," d "\n" \
    W5500_RECV_BIT(d)       \
    "add.w   " d "," d "\n" \
    W5500_RECV_BIT(d)       \

#define W5500_RECV_BYTE(d)  \
    "moveq.l #0," d "\n"    \
    W5500_RECV_8BITS(d)     \
    "ror.w   %%d4," d "\n"

#define W5500_RECV_8BITS_L(d) \
    W5500_RECV_BIT(d)       \
    "add.w   " d "," d "\n" \
    W5500_RECV_BIT(d)       \
    "add.l   " d "," d "\n" \
    W5500_RECV_BIT(d)       \
    "add.l   " d "," d "\n" \
    W5500_RECV_BIT(d)       \
    "add.l   " d "," d "\n" \
    W5500_RECV_BIT(d)       \
    "add.l   " d "," d "\n" \
    W5500_RECV_BIT(d)       \
    "add.l   " d "," d "\n" \
    W5500_RECV_BIT(d)       \
    "add.l   " d "," d "\n" \
    W5500_RECV_BIT(d)       \

#define W5500_RECV_WORD(d)  \
    "moveq.l #0," d "\n"    \
    W5500_RECV_8BITS(d)     \
    "add.w   " d "," d "\n" \
    W5500_RECV_8BITS_L(d)    \
    "ror.l   %%d4," d "\n"

static inline int spi_recvbyte(void)
{
    int data;
#ifdef NO_ASM
    data = 0;
    for (int i = 0; i < 8; i++) {
        *(volatile uint8_t *)joyport->port_a = SPI_MOSI | 0       | 0;
        *(volatile uint8_t *)joyport->port_a = SPI_MOSI | SPI_CLK | 0;
        data <<= 1;
        data |= (*(volatile uint8_t *)joyport->port_c & joyport->spi_miso) ? 1 : 0;
    }
#else
    __asm__ volatile (
        "movea.l %1@,%%a0\n"        // PORT_A address
        "movea.l %1@(4),%%a1\n"     // PORT_C address
        "moveq.l #0x01,%%d1\n"      // SPI_MOSI
        "moveq.l #0x03,%%d2\n"      // SPI_MOSI | SPI_CLK
        "move.b  %1@(14),%%d3\n"    // SPI_MISO bit mask
        "move.b  %1@(15),%%d4\n"    // SPI data bit shift count
        W5500_RECV_BYTE("%0")
        : "=d"(data) : "a"(joyport) : "a0","a1","d1","d2","d3","d4","d5"
    );
#endif
    return data;
}

static inline int spi_recvword(void)
{
    int data;
#ifdef NO_ASM
    data = 0;
    for (int i = 0; i < 16; i++) {
        *(volatile uint8_t *)joyport->port_a = SPI_MOSI | 0       | 0;
        *(volatile uint8_t *)joyport->port_a = SPI_MOSI | SPI_CLK | 0;
        data <<= 1;
        data |= (*(volatile uint8_t *)joyport->port_c & joyport->spi_miso) ? 1 : 0;
    }
#else
    __asm__ volatile (
        "movea.l %1@,%%a0\n"        // PORT_A address
        "movea.l %1@(4),%%a1\n"     // PORT_C address
        "moveq.l #0x01,%%d1\n"      // SPI_MOSI
        "moveq.l #0x03,%%d2\n"      // SPI_MOSI | SPI_CLK
        "move.b  %1@(14),%%d3\n"    // SPI_MISO bit mask
        "move.b  %1@(15),%%d4\n"    // SPI data bit shift count
        W5500_RECV_WORD("%0")
        : "=d"(data) : "a"(joyport) : "a0","a1","d1","d2","d3","d4","d5"
    );
#endif
    return data;
}

// SPI send asm macros
// a0: PORT_A address
// d1: SPI_MOSI  d2: SPI_CLK  d3: temporary

#define W5500_SEND_BIT(d)   \
    "rol.b   #1," d "\n"    \
    "move.b  " d ",%%d3\n"  \
    "and.b   %%d1,%%d3\n"   \
    "move.b  %%d3,%%a0@\n"  \
    "or.b    %%d2,%%d3\n"   \
    "move.b  %%d3,%%a0@\n"

#define W5500_SEND_BYTE(d)  \
    W5500_SEND_BIT(d)       \
    W5500_SEND_BIT(d)       \
    W5500_SEND_BIT(d)       \
    W5500_SEND_BIT(d)       \
    W5500_SEND_BIT(d)       \
    W5500_SEND_BIT(d)       \
    W5500_SEND_BIT(d)       \
    W5500_SEND_BIT(d)

#define W5500_SEND_BIT_W(d) \
    "rol.w   #1," d "\n"    \
    "move.b  " d ",%%d3\n"  \
    "and.b   %%d1,%%d3\n"   \
    "move.b  %%d3,%%a0@\n"  \
    "or.b    %%d2,%%d3\n"   \
    "move.b  %%d3,%%a0@\n"

#define W5500_SEND_BYTE_W(d) \
    W5500_SEND_BIT_W(d)     \
    W5500_SEND_BIT_W(d)     \
    W5500_SEND_BIT_W(d)     \
    W5500_SEND_BIT_W(d)     \
    W5500_SEND_BIT_W(d)     \
    W5500_SEND_BIT_W(d)     \
    W5500_SEND_BIT_W(d)     \
    W5500_SEND_BIT_W(d)

#define W5500_SEND_WORD(d) \
    W5500_SEND_BYTE_W(d)   \
    W5500_SEND_BYTE_W(d)

static inline void spi_sendbyte(int data)
{
#ifdef NO_ASM
    for (int i = 0; i < 8; i++) {
        *(volatile uint8_t *)joyport->port_a = ((data & 0x80) ? SPI_MOSI : 0) | 0       | 0;
        *(volatile uint8_t *)joyport->port_a = ((data & 0x80) ? SPI_MOSI : 0) | SPI_CLK | 0;
        data <<= 1;
    }
#else
    __asm__ volatile (
        "movea.l %0@,%%a0\n"        // PORT_A address
        "moveq.l #0x01,%%d1\n"      // SPI_MOSI
        "moveq.l #0x02,%%d2\n"      // SPI_CLK
        W5500_SEND_BYTE("%1")
        : : "a"(joyport),"d"(data) : "a0","d1","d2","d3"
    );
#endif
}

static inline void spi_sendword(int data)
{
#ifdef NO_ASM
    for (int i = 0; i < 16; i++) {
        *(volatile uint8_t *)joyport->port_a = ((data & 0x8000) ? SPI_MOSI : 0) | 0       | 0;
        *(volatile uint8_t *)joyport->port_a = ((data & 0x8000) ? SPI_MOSI : 0) | SPI_CLK | 0;
        data <<= 1;
    }
#else
    __asm__ volatile (
        "movea.l %0@,%%a0\n"        // PORT_A address
        "moveq.l #0x01,%%d1\n"      // SPI_MOSI
        "moveq.l #0x02,%%d2\n"      // SPI_CLK
        W5500_SEND_WORD("%1")
        : : "a"(joyport),"d"(data) : "a0","d1","d2","d3"
    );
#endif
}

//****************************************************************************
// Public functions
//****************************************************************************

int w5500_select(int port)
{
    if (port < 1 || port > 2) {
        return -1;
    }
    joyport = &w5500_param[port - 1];
    return 0;
}

void w5500_ini(void)
{
    *(volatile uint8_t *)joyport->port_ctl = joyport->port_ctl_ini;
    W5500_CS_DIS();
}

void w5500_fin(void)
{
    *(volatile uint8_t *)joyport->port_ctl = joyport->port_ctl_fin;
}

uint8_t w5500_read_b(uint16_t addr, uint8_t block)
{
    uint8_t data;
    W5500_CS_ENB();
    spi_sendword(addr);
    spi_sendbyte((block << 3) | 0 | 1);
    data = spi_recvbyte();
    W5500_CS_DIS();
    return data;
}

uint16_t w5500_read_w(uint16_t addr, uint8_t block)
{
    uint16_t data;
    W5500_CS_ENB();
    spi_sendword(addr);
    spi_sendbyte((block << 3) | 0 | 2);
    data = spi_recvword();
    W5500_CS_DIS();
    return data;
}

uint32_t w5500_read_l(uint16_t addr, uint8_t block)
{
    uint32_t data;
    W5500_CS_ENB();
    spi_sendword(addr);
    spi_sendbyte((block << 3) | 0 | 3);
    data = spi_recvword() << 16;
    data |= spi_recvword();
    W5500_CS_DIS();
    return data;
}

void w5500_read(uint16_t addr, uint8_t block, uint8_t *data, size_t len)
{
    W5500_CS_ENB();
    spi_sendword(addr);
    spi_sendbyte((block << 3) | 0 | 0);
#ifdef NO_ASM
    for (int i = 0; i < len; i++) {
        data[i] = spi_recvbyte();
    }
#else
    if ((int)data & 1) {
        __asm__ volatile (
            "movea.l %0@,%%a0\n"        // PORT_A address
            "movea.l %0@(4),%%a1\n"     // PORT_C address
            "moveq.l #0x01,%%d1\n"      // SPI_MOSI
            "moveq.l #0x03,%%d2\n"      // SPI_MOSI | SPI_CLK
            "move.b  %0@(14),%%d3\n"    // SPI_MISO bit mask
            "move.b  %0@(15),%%d4\n"    // SPI data bit shift count
            "bra     1f\n"
        "read1o:\n"
            W5500_RECV_BYTE("%%d0")
            "move.b  %%d0,%1@+\n"
        "1:\n"
            "dbra    %2,read1o\n"
            : : "a"(joyport),"a"(data),"d"(len) : "a0","a1","d0","d1","d2","d3","d4","d5"
        );
    } else {
        __asm__ volatile (
            "movea.l %0@,%%a0\n"        // PORT_A address
            "movea.l %0@(4),%%a1\n"     // PORT_C address
            "moveq.l #0x01,%%d1\n"      // SPI_MOSI
            "moveq.l #0x03,%%d2\n"      // SPI_MOSI | SPI_CLK
            "move.b  %0@(14),%%d3\n"    // SPI_MISO bit mask
            "move.b  %0@(15),%%d4\n"    // SPI data bit shift count
            "bra     1f\n"

        "read8e:\n"
            W5500_RECV_WORD("%%d0")
            "move.w  %%d0,%1@+\n"
            W5500_RECV_WORD("%%d0")
            "move.w  %%d0,%1@+\n"
            W5500_RECV_WORD("%%d0")
            "move.w  %%d0,%1@+\n"
            W5500_RECV_WORD("%%d0")
            "move.w  %%d0,%1@+\n"
            "subq.w  #8,%2\n"
        "1:\n"
            "cmpi.w  #8,%2\n"
            "bcc     read8e\n"
            "bra.s   2f\n"

        "read1e:\n"
            W5500_RECV_BYTE("%%d0")
            "move.b  %%d0,%1@+\n"
        "2:\n"
            "dbra    %2,read1e\n"
            : : "a"(joyport),"a"(data),"d"(len) : "a0","a1","d0","d1","d2","d3","d4","d5"
        );
    }
#endif
    W5500_CS_DIS();
}

void w5500_write_b(uint16_t addr, uint8_t block, uint8_t data)
{
    W5500_CS_ENB();
    spi_sendword(addr);
    spi_sendbyte((block << 3) | 4 | 1);
    spi_sendbyte(data);
    W5500_CS_DIS();
}

void w5500_write_w(uint16_t addr, uint8_t block, uint16_t data)
{
    W5500_CS_ENB();
    spi_sendword(addr);
    spi_sendbyte((block << 3) | 4 | 2);
    spi_sendword(data);
    W5500_CS_DIS();
}

void w5500_write_l(uint16_t addr, uint8_t block, uint32_t data)
{
    W5500_CS_ENB();
    spi_sendword(addr);
    spi_sendbyte((block << 3) | 4 | 3);
    spi_sendword((data >> 16) & 0xffff);
    spi_sendword(data & 0xffff);
    W5500_CS_DIS();
}

void w5500_write(uint16_t addr, uint8_t block, const uint8_t *data, size_t len)
{
    W5500_CS_ENB();
    spi_sendword(addr);
    spi_sendbyte((block << 3) | 4 | 0);
#ifdef NO_ASM
    for (int i = 0; i < len; i++) {
        spi_sendbyte(data[i]);
    }
#else
    if ((int)data & 1) {
        __asm__ volatile (
            "movea.l %0@,%%a0\n"        // PORT_A address
            "moveq.l #0x01,%%d1\n"      // SPI_MOSI
            "moveq.l #0x02,%%d2\n"      // SPI_CLK
            "bra     1f\n"
        "write1o:\n"
            "move.b  %1@+,%%d0\n"
            W5500_SEND_BYTE("%%d0")
        "1:\n"
            "dbra    %2,write1o\n"
            : : "a"(joyport),"a"(data),"d"(len) : "a0","d0","d1","d2","d3"
        );
    } else {
        __asm__ volatile (
            "movea.l %0@,%%a0\n"        // PORT_A address
            "moveq.l #0x01,%%d1\n"      // SPI_MOSI
            "moveq.l #0x02,%%d2\n"      // SPI_CLK
            "bra     1f\n"

        "write8e:\n"
            "move.w  %1@+,%%d0\n"
            W5500_SEND_WORD("%%d0")
            "move.w  %1@+,%%d0\n"
            W5500_SEND_WORD("%%d0")
            "move.w  %1@+,%%d0\n"
            W5500_SEND_WORD("%%d0")
            "move.w  %1@+,%%d0\n"
            W5500_SEND_WORD("%%d0")
            "subq.w  #8,%2\n"
        "1:\n"
            "cmpi.w  #8,%2\n"
            "bcc     write8e\n"
            "bra.s   2f\n"

        "write1e:\n"
            "move.b  %1@+,%%d0\n"
            W5500_SEND_BYTE("%%d0")
        "2:\n"
            "dbra    %2,write1e\n"
            : : "a"(joyport),"a"(data),"d"(len) : "a0","d0","d1","d2","d3"
        );
    }
#endif
    W5500_CS_DIS();
}
