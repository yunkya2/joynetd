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

    .global jsr_entry
    .global trap_entry
    .extern do_command

    .section    ".header","ax"

tcpip_magic:
    .ascii  "TCP/IP\x02\x00"

jsr_entry:
    movem.l %d0/%a0,%sp@-
    jsr     do_command
    addq.l  #8,%sp
    rts

trap_entry:
    movem.l %d0/%a0,%sp@-
    jsr     do_command
    addq.l  #8,%sp
    rte


/* Human68k device driver header */

    .global devheader
    .extern joynetd_data

devheader:
    .long   -1                  // link pointer
    .word   0x8000              // device type
    .long   strategy            // strategy routine entry point
    .long   interrupt_asm       // interrupt routine entry point
    .ascii  "/joynet/"          // device name

    .long   joynetd_data        // device data pointer

reqheader:  .long 0

strategy:
    move.l  %a5,reqheader
    rts

interrupt_asm:
    movem.l %d0-%d2/%a0-%a2/%a5,%sp@-
    move.w  #0x700d,%d0             // すべてエラーにする
    movea.l reqheader,%a5
    ror.w   #8,%d0
    move.b  %d0,%a5@(4)             // errh エラーコードを設定
    rol.w   #8,%d0
    move.b  %d0,%a5@(3)             // errl エラーコードを設定
    movem.l %sp@+,%d0-%d2/%a0-%a2/%a5
    rts

    .end
