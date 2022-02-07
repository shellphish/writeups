# Writeup of Chutes-and-ladders challenge from DiceCTF 2022

TDLR: UAF to tcache poisoning using a game

Writeup author: [adamd](https://adamdoupe.com)

The challenge description given by challenge author `bosh` is the following:

```
As you know, DiceGang is not about solving chutes and ladders. But I am! nc mc.ax 31326
```

In addition, the challenges gives us the binary [chutes](./chutes) along with the exact libc and ld binaries [ld-linux-x86-64.so.2](./ld-linux-x86-64.so.2) and [libc.so.6](./libc.so.6).

## Running

After the CTF I created a quick [Dockerfile](./Dockerfile) so that others can run the challenge (pinning the exact Ubuntu version with the same libc and ld).

Build it run it locally with the following:

```bash
docker build . -t chutes
docker run --rm -p 31326:31326 -it chutes
```

Now you should be able to access the challenge:

```bash
nc localhost 31326
```

Now get to hacking! Only read on if you want the spoilers.

## Prep

First thing I did was create a patched version of `chutes` so that I could run/debug locally using the correct libc and ld.
You should always do this when they give you a libc to ensure that you're debugging the same local/remote.

```bash
cp ./chutes ./chutes-patched
patchelf --set-rpath "." ./chutes-patched
patchelf --set-interpreter "./ld-linux-x86-64.so.2" ./chutes-patched
```

Next, use pwntools' `checksec` to see what pwn defenses are in place.

```bash
$ checksec ./chutes
[*] 'chutes'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

All of them, cool cool. Likely means that we'll need to use heap stuff.

What `libc` version? Simple to answer, just execute `./libc.so.6`

```
Ubuntu GLIBC 2.31-0ubuntu9.2
```

I don't have all the libc versions to heap techniques memorized, but with the version as a starting point we can do some googling to [techniques that could work](https://github.com/shellphish/how2heap).

## What is it?

Next, we need to understand what the program does. 
I typically do this before reversing so I have context.

First, the challenge asks us for `Number of players (max 10): `. 
Quick tests show us that we need at least 2 players, and no more than 10.

Next, it asks us for the markers of each player (a single character).

```
Player 1 marker (1 character): a
Player 2 marker (1 character): c
```

It then shows us the chutes and ladders (from `int` -> `int`) and then asks us if we'd like to change the chutes and laddres (hmm, let's store this in mind for later).

Next, it shows us the game board, with squares from 1 to 100, and our markers are on square 1.

It then go through each players turn in order, first asking if we'd like to change our marker (interesting), what did we spin 1--6. If we give outside this range it tells us that we're passing. If we give inside the range it moves our marker and updates us on what's going on.

At the end of the turn we're asked if we want to look at the board, then repeats with the next player's turn.

## Reversing

Armed with knowledge of what the program does, we now start to reverse the binary. 

There's a lot here, and we can take it bit by bit until we understand the whole game.

This is critical to being able to exploit the challenge, we must be able to manipulate the game to trigger the `malloc`s and `free`s that we want (or don't want).

Some interesting things popped up.

If we "win" the game we get a libc leak of `&puts`. Looking into `win_check_maybe` we win if we get exactly to square `99` (here I'll use zero-indexed squares as they appear in the binary and not in the game board).

This is clearly nice so that we don't need to leak the libc pointer (although we could do it without it would be tedious). 

```C
  while ( 1 )
  {
    print_board();
    do
    {
      play_turn();
      v10 = win_check_maybe();
      if ( v10 >= 0 )
        printf("Player %d won! Here is your prize: %p\n", (unsigned int)(v10 + 1), &puts);
      printf("Would you like to take a look at the board now? (y/n): ");
      v7 = getchar();
      getchar();
    }
    while ( v7 != 'y' );
  }
```

I also figured out the following structs that the program used:

```C
struct player
{
   char* marker;
   char player_num;
   char cur_square;
   char rest[6];
};

struct square
{
   char* markers_s10;
   int player_bitmap;
   char square_num;
}
```

Also there's a global `struct square* game_board[100]` that stores the state of all the squares on the board.

Now we care about the heap operations in this program, so let's look at those.

During the core game loop, there's only one function that calls `free` and `malloc`, a function who's purpose is to clear the current player from the square that they're on (because they will be moved).

`is_going_to` is 1 when the player is moving to a new square (hence the allocation logic of markers), and 0 when the player is moving _from_ the current square.

```C
void __fastcall update_position(struct player *cur_player, bool is_going_to)
{
  struct square *v2; // rbx
  size_t v3; // rax

  game_board[cur_player->cur_square]->player_bitmap ^= 1 << cur_player->player_num;// Clear position in current square bitmap
  if ( is_going_to )
  {
    if ( !game_board[cur_player->cur_square]->markers_s10 )
    {
      v2 = game_board[cur_player->cur_square];
      v2->markers_s10 = (char *)malloc(0xAuLL);
      memset(game_board[cur_player->cur_square]->markers_s10, ' ', 0xAuLL);
    }
    v3 = strlen(cur_player->marker);
    memcpy(&game_board[cur_player->cur_square]->markers_s10[cur_player->player_num], cur_player->marker, v3);
  }
  else
  {
    memset(
      &game_board[cur_player->cur_square]->markers_s10[cur_player->player_num],
      ' ',
      sizeof(game_board[cur_player->cur_square]->markers_s10[cur_player->player_num]));
    if ( !game_board[cur_player->cur_square]->player_bitmap )
      free(game_board[cur_player->cur_square]->markers_s10);
  }
}
```

So how can we trigger the `free`? When we're moving from a square, and there's nobody left on the square!

This makes sense, we're freeing the buffer containing the player markers for this square when there's nobody on the square. 

We can spot a key vulnerability here, `game_board[cur_player->cur_square]->markers_s10` is not `NULL`ed after we free it! If we can use it, we might be able to cause some havoc.

Without going into all the details, what's the flow of `play_turn`?

```C
// ...

update_position(cur_player, 0);
cur_player->cur_square += spin;

// process_ladders

// process chutes

update_position(cur_player, 1);

// ...

if ( !game_board[cur_square]->player_bitmap )
  game_board[cur_square]->markers_s10 = 0LL;
```

During processing `ladders` and `chutes`, we call `update_position(cur_player, 1);` when there's a hit.

Drat, it seems that we can't have any fun, because at the end of the turn it checks the current squares to see if any players are on it (which we are not because we moved off the square), so that pointer is set to `NULL`.

Now comes in our understanding of the game. Understanding the logic of the chutes and ladders is key to solving this challenge:

- If we land on a square with a ladder, it will move us up to the target square of the ladder.
- If we land on a square with a chute, it will move us down to the target square of the chute.
- Ladders are processed before chutes
- Moving through ladders or chutes doesn't free our position (you'll actually see the marker there still).
- We cannot chain chutes to chutes or ladders to ladders (the code checks for this), but _we can chain ladders to chutes and vice versa_.

Using all of these we can trigger the following scenario:

- We are on square `1`.
- There's a ladder from `2 -> 3`.
- There's a chute from `3 -> 1`.

From square `1`, if we spin a `1`, that will move us forward one square and if there's nobody else on `1` then that square's markers will be `free`d.

Then, the ladder will first move us from square `2` to square `3` (note that this will `malloc` new markers for those squares).

Then, the chute will move us from square `3` to square `1`, and now there's a person in square `1` so check at the end of `play_turn` will _not_ pass and square `1`'s marker buffer is not null. 

We now have a UAF!

## Exploitation

To continue at this point, we need to understand more about how we can control the `marker` buffer for each square. 

Each player's marker `c` is copied onto the `marker` buffer at the offset of the player's number. 

So player `0`'s marker is always copied to `marker[0]`, etc. Super important to understand this to exploit the UAF, because with this we can control what is written to `marker`. The trick will be that we need to actually move the players to those locations. 

I started to write some Python code to prove that this could work. In the process I started from @Flipout50's interaction script and the ability to setup the game with a given chutes and ladders and the ability to move specific players (this way the exploit logic wouldn't have to worry about who's turn it was). Based on what I saw from other people's writeups, this helped greatly. 

Once I proved that this loop would trigger a `free` and maintain the pointer, I also demonstrated that I could leak out the `tcache` `&key` that it adds to 8 bytes offset of the freed chunk. I did this by moving all players 0--8, then printing the board. Ultimately this was not needed in the exploitation, but it could have come in handy.

After understanding what heap techniques were possible in this libc version, the ultimate goal was straight forward: 

1. Overwrite `__free_hook` in `libc` with `@one_gadget`
2. Trigger `free`.
3. Pop shell.

This libc version has some [one_gadget](https://github.com/david942j/one_gadget)s, so we can use those. The first ended up not working, but it was trivial to change out to the second one.

To accomplish this, we need to do the following:

- Win the game to leak out `@puts`, to break ASLR on libc
- `free` two chunks (so I'll need two loops, although I still don't know if this is 100% necessary).
- Overwrite the second chunk with the `@__free_hook`.
- Trigger two `malloc`s.
- The second `malloc` now points to `__free_hook`.
- Overwrite the second `malloc` with the `@one_gadget`. 

A very important part about the last step: we absolutely cannot trigger a `free`. The program will fill the `marker` buffer with 10 bytes of `0x20` (space), so if we trigger a `free` then we crash. This means that we cannot leave any square without players on it.

To make this work I made the following important chutes and ladders:

- `1 -> 99` this made it easy to win right off the bat
- `4 -> 5 -> 3` First loop
- `7 -> 8 -> 6` Second loop
- `10 -> 9` Used to trigger the two `malloc`s
- `11 -> 0` Portal back to start, used to move all the players around to not trigger a `free`

I literally made drawings of the board and what pieces were on what squares at all points of the operation.
I also used a lot of debugging to make sure I wasn't accidentally triggering any `malloc`s or `free`s that I didn't want. 

Now I got everything finished and ran into a problem at the end (this is why we have the term CTF-close).
I needed to overwrite all 8 bytes of `__free_hook`, because the program overwrites it with `0x20` spaces.

This means that I need to have all players 0--8 on the correct square with the correct values.
But, I needed to have players on square `0`, `3`, and `6`, in addition to the target square of `9`. That means that I can't have `8` players on one square without triggering a free!

After much thinking, I realized that I didn't actually need to overwrite all 8 bytes of `__free_hook`.
I only needed to overwrite the lower 6 bytes, because the upper two will always be `0`.

So, rather than leak a pointer to `@__free_hook`, I leaked a pointer to `@__free_hook-4`. The `-4` is because the program will overwrite 10 bytes with `0x20` (spaces).

Lining things up worked correctly, and boom we got the flag.

[x.py](./x.py) has the full exploit script. 



