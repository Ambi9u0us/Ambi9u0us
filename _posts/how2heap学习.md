# how2heap学习

## 前言

how2heap是**shellphish**团队在Github上开源的堆漏洞系列教程（[项目地址在此](<https://github.com/shellphish/how2heap>)），是对堆进行学习检验比较好的项目，在学习前后参考了华庭大佬学写的**“Glibc内存管理-Ptmalloc2源码分析”**，这对于进一步理解整个堆的内存分配与管理十分有作用，[链接地址](https://paper.seebug.org/papers/Archive/refs/heap/glibc%E5%86%85%E5%AD%98%E7%AE%A1%E7%90%86ptmalloc%E6%BA%90%E4%BB%A3%E7%A0%81%E5%88%86%E6%9E%90.pdf)

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

使用Index_sentence添加句子，并且存储了一个Word结构体，然后用Search_word搜索输入的word所在的句子，找到后如果选择删除，将会把word中记录的sentence内容清空变为\x00，并free掉，但是该地址的索引并没有删除，仍然存在，这样就可以通过再次添加句子，使得Word结构体可以被调用，通过搜索\x00来找到之前删掉的句子所在内存，而Word结构体链表一直时固定存储在words所在的地址，