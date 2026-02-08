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

    .section    ".header","ax"

/* TCP/IP driver header */

    .global tcpip_magic
    .global jsr_entry
    .global trap_entry
    .extern do_command

tcpip_magic:
    .ascii  "TCP/IP\x02\x00"

jsr_entry:
    pea.l   %pc@(do_command)
    .word   0xfff6              // DOS _SUPER_JSR
    addq.l  #4,%sp
    rts

trap_entry:
    bsr     do_command
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


/* IOCS _JOYGET handler */

    .global joyget
    .global joyget_stat
    .global joyget_port
    .global joyget_org

joyget:
    cmpi.w  #0x4b00,%d1
    beq.s   5f
    cmp.w   joyget_port,%d1
    beq.s   6f
    move.l  %pc@(joyget_org),%sp@-
    rts

5:
    moveq.l #0,%d0
    move.w  %pc@(joyget_stat),%d0
    rts
6:
    move.l  #0x00ff,%d0
    rts

joyget_stat:   .word  0
joyget_port:   .word  0
joyget_org:    .long  0


/* C startup routine */

    .global _start
    .extern _ENV0
    .extern _HSTA
    .extern _HEND
    .extern _cmdline
    .extern _heap_size
    .extern _stack_size
    .extern __crt1_startup

_start:
    move.l  %a0, _MCB               // MCB
    lea.l   %a0@(0x100), %a5
    move.l  %a5, _PSTA              // TEXT Start
    move.l  %a0@(0x30), %d0
    move.l  %d0, _PEND              // TEXT End
    move.l  %d0, _BSTA              // BSS Start
    move.l  %a1, _BEND              // BSS End

    lea.l   %a0@(0x10), %a5
    move.l  %a5, _PSP

    move.l  %a3, _ENV0
    move.l  %a2, _cmdline
    move.l  %a1,_HSTA
    add.l   _heap_size,%a1
    move.l  %a1,_HEND               // setup heap
    add.l   _stack_size,%a1
    cmpa.l  %a0@(8),%a1             // memory block bottom
    bhi     out_of_memory

    move.l  %a1,%sp                 // setup stack
    jmp     __crt1_startup          // Human initialization

out_of_memory:
    pea.l   %pc@(oom_msg)
    .short  0xff09                  // print
    addq.l  #4,%sp
    move.w  #0x007f,%sp@-
    .short  0xff4c                  // exit2

oom_msg:
    .asciz  "Out of memory. Program terminated.\r\n"

    .end
