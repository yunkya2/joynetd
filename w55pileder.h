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
#include "w5500regs.h"

//****************************************************************************
// W5500 APIs
//****************************************************************************

void w5500_ini(void);

uint8_t w5500_read_b(uint16_t addr, uint8_t block);
uint16_t w5500_read_w(uint16_t addr, uint8_t block);
uint32_t w5500_read_l(uint16_t addr, uint8_t block);
void w5500_read(uint16_t addr, uint8_t block, uint8_t *data, size_t len);

void w5500_write_b(uint16_t addr, uint8_t block, uint8_t data);
void w5500_write_w(uint16_t addr, uint8_t block, uint16_t data);
void w5500_write_l(uint16_t addr, uint8_t block, uint32_t data);
void w5500_write(uint16_t addr, uint8_t block, const uint8_t *data, size_t len);

#endif /* _W5500_H_ */
