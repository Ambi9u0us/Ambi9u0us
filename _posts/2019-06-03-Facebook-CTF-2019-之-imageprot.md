---
layout:     post
title:      "Facebook CTF 2019 之 imageprot"
date:       2019-06-03
author:     "Ambi9u0us"
catalog: true
tags:
    - fbctf 2019
    - Writeup
    - reverse
typora-root-url: ..
---

# Facebook CTF 2019 之imageprot的分析

## 前言

这次FB CTF并没有去打，不过有人让我做一做imageprot，这是一道rust的逆向题，之前还没碰过rust的逆向，所以两眼一抹黑开始生逆，后面在他人的帮助下总算是做出来了。

## 分析

使用file命令查看文件，得到结果如下：

![1559530783320](/img/in-post/1559530783320.png)

从`not stripped`可以知道这道题符号表没有去掉，说明出题方并没有在这方面给选手加难度。

然后运行一下文件，查看结果：

![1559530941148](/img/in-post/1559530941148.png)

可以发现提示说是无法获取URI，在IDA中搜索字符串“Failed to fetch URI”，可以定位到函数`get_uri`:

![1559531103067](/img/in-post/1559531103067.png)

查看对该函数的调用，可以定位到程序的main函数`imageprot::main::h60a99eb3d3587835()`，所以使用gdb进行动态调试，给`get_uri`函数下断点，进入后发现程序试图访问`http://challenges.fbctf.com/vault_is_intern`，但是使用浏览器访问，发现这个站点并没有任何相应，由此导致后面程序退出并报错，这个地方应该就是题目要解决的第一个问题。

我想到的办法是自己构造一个http服务，至于域名解析的问题直接改`/etc/hosts`文件，添加一行解释：

```
127.0.0.1   challenges.fbctf.com
```

然后使用python搭建一个简单的http服务：

```shell
sudo python -m SimpleHTTPServer 80
```

然后重新进行调试，就会发现这一步不再报错退出。

后面运行到下面这一段时，再次报错退出：

![1559532039320](/img/in-post/1559532039320.png)

使用gdb调试时发现，这一段主要是进行反调试操作，通过查找进程中是否有gdb、vmtoolsd、VBOXClient等来判断是否被调试，确定后程序退出，这里采取的办法是将if语句判定时修改跳转语句，使得if语句内的程序退出流程不被执行，因此将程序进行patch操作，继续下一步调试。

然后就发现程序又访问了一个网页`https://httpbin.org/status/418`，这个网页可以访问：

```

    -=[ teapot ]=-

       _...._
     .'  _ _ `.
    | ."` ^ `". _,
    \_;`"---"`|//
      |       ;/
      \_     _/
        `"""`
```

不过这里又出现了问题，函数`get_uri`访问这个网页报错退出，原因是这个网页被墙了，而shell的流量没有过代理，emm，于是我又在hosts文件中加了一行

```
127.0.0.1   httpbin.org
```

当然，此时仍然是会报错的，因为题目是访问的https，所以在函数`get_uri`运行前需要修改uri，为了不影响总的位数，我将`https://httpbin.org/status/418`修改成了`http:///httpbin.org/status/418`，其效果与`http://httpbin.org/status/418`是一样的。

这样就可以是`get_uri`函数运行不出错，但是还有一步要做，那就是要将418这个文件放入对应的文件夹，所以我在创建http服务的目录下新建了文件夹status，里面包含有418文件，存储网页中的内容，原因是后面的`decrypt`函数要用到这个内容。

然后就到了`decrypt`函数：

![1559532944400](/img/in-post/1559532944400.png)

这个时候就需要重新看一下整个程序是要干什么了，从前面运行程序可以知道，整个程序是为了保护图片，那么我们要做的就是获取一张图片，进入`decrypt`函数内查看：

![1559533223031](/img/in-post/1559533223031.png)

这里先进行了base64解码，然后：

![1559533200565](/img/in-post/1559533200565.png)

是对一串数据进行异或操作，所以我们重点关注v12和v8的值，猜测v12为图片内存的起始地址，v8为长度，然后gdb调试得到v12和v8的值，查看v12处内存：

![1559533491496](/img/in-post/1559533491496.png)

ffd8为JPEG格式文件的开头标志，因此可以确定这是一个jpeg文件数据开头，而v8的值为

`0x10353`，代表图片数据长度，通过dump命令将这一段内存存储到文件中：

```shell
dump binary memory flag.jpg 0x555555c0a160 0x555555c0a160+0x10353
```

得到flag：

![](/img/in-post/imageprot_flag.jpg)

