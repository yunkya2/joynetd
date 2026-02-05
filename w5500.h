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

#ifndef _W5500_H_
#define _W5500_H_

#include <stdint.h>

// w5500 APIs

void w5500_ini(void);
void w5500_fin(void);

uint8_t w5500_read_b(uint16_t addr, uint8_t block);
uint16_t w5500_read_w(uint16_t addr, uint8_t block);
uint32_t w5500_read_l(uint16_t addr, uint8_t block);
void w5500_read(uint16_t addr, uint8_t block, uint8_t *data, size_t len);

void w5500_write_b(uint16_t addr, uint8_t block, uint8_t data);
void w5500_write_w(uint16_t addr, uint8_t block, uint16_t data);
void w5500_write_l(uint16_t addr, uint8_t block, uint32_t data);
void w5500_write(uint16_t addr, uint8_t block, uint8_t *data, size_t len);

// w5500 register definitions

#define W5500_MR            0x0000  // Mode
#define W5500_GAR           0x0001  // Gateway Address
#define W5500_SUBR          0x0005  // Subnet Mask
#define W5500_SHAR          0x0009  // Source Hardware Address
#define W5500_SIPR          0x000f  // Source IP Address
#define W5500_INTLEVEL      0x0013  // Interrupt Low Level Timer
#define W5500_IR            0x0015  // Interrupt
#define W5500_IMR           0x0016  // Interrupt Mask
#define W5500_SIR           0x0017  // Socket Interrupt
#define W5500_SIMR          0x0018  // Socket Interrupt Mask
#define W5500_RTR           0x0019  // Retry Time
#define W5500_RCR           0x001b  // Retry Count
#define W5500_PTIMER        0x001c  // PPP LCP Request Timer
#define W5500_PMAGIC        0x001d  // PPP LCP Magic Number
#define W5500_PHAR          0x001e  // PPP Destination MAC Address
#define W5500_PSID          0x0024  // PPP Session Identification
#define W5500_PMRU          0x0026  // PPP Maximum Segment Size
#define W5500_UIPR          0x0028  // Unreachable IP Address
#define W5500_UPORTR        0x002c  // Unreachable Port
#define W5500_PHYCFGR       0x002e  // PHY Configuration
#define W5500_VERSIONR      0x0039  // Chip Version

#define W5500_Sn_MR         0x0000  // Socket n Mode
#define W5500_Sn_CR         0x0001  // Socket n Command
#define W5500_Sn_IR         0x0002  // Socket n Interrupt
#define W5500_Sn_SR         0x0003  // Socket n Status
#define W5500_Sn_PORT       0x0004  // Socket n Source Port
#define W5500_Sn_DHAR       0x0006  // Socket n Destination Hardware Address
#define W5500_Sn_DIPR       0x000c  // Socket n Destination IP Address
#define W5500_Sn_DPORT      0x0010  // Socket n Destination Port
#define W5500_Sn_MSSR       0x0012  // Socket n Maximum Segment Size
#define W5500_Sn_TOS        0x0015  // Socket n IP TOS
#define W5500_Sn_TTL        0x0016  // Socket n IP TTL
#define W5500_Sn_RXBUF_SIZE 0x001e  // Socket n Receive Buffer Size
#define W5500_Sn_TXBUF_SIZE 0x001f  // Socket n Transmit Buffer Size
#define W5500_Sn_TX_FSR     0x0020  // Socket n TX Free Size
#define W5500_Sn_TX_RD      0x0022  // Socket n TX Read Pointer
#define W5500_Sn_TX_WR      0x0024  // Socket n TX Write Pointer
#define W5500_Sn_RX_RSR     0x0026  // Socket n RX Received Size
#define W5500_Sn_RX_RD      0x0028  // Socket n RX Read Pointer
#define W5500_Sn_RX_WR      0x002a  // Socket n RX Write Pointer
#define W5500_Sn_IMR        0x002c  // Socket n Interrupt Mask
#define W5500_Sn_FRAG       0x002d  // Socket n Fragment Offset in IP
#define W5500_Sn_KPALVTR    0x002f  // Socket n Keep Alive Timer

#endif /* _W5500_H_ */
