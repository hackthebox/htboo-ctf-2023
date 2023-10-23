![](https://github.com/hackthebox/writeup-templates/raw/master/challenge/assets/images/banner.png)

<img src="https://github.com/hackthebox/writeup-templates/raw/master/challenge/assets/images/htb.png" style="margin-left: 20px; zoom: 80%;" align=left/>
<font size="10">CandyBowl</font>
17<sup>th</sup> 09 23 / Document No. D22.102.XX
Prepared By: clubby789
Challenge Author: clubby789
Difficulty: <font color=green>Very Easy</font>
Classification: Official

# Synopsis

Candy Bowl is a Very Easy reversing challenge. Players will use `strings` to discover a flag.

## Skills Learned
    - Using `strings`

# Solution

Running the binary, we're given this output.

```
Reaching into the candy bowl...
Your candy is... 'Meiji'. Enjoy!
```

Each time we run the binary, a different candy is picked. If we decompile the binary, we can see the `main` function consists of:

```c
int32_t main(int32_t argc, char** argv, char** envp)
    srand(x: time(nullptr))
    puts(str: "Reaching into the candy bowl...")
    sleep(seconds: 3)
    printf(format: "Your candy is... '%s'. Enjoy!\n", (&candy)[sx.q((sx.q(rand()) u% 0xd1).d)])
```

If we change the type of `candy` to `char *candy[0xd1]` and go to it, we can see it is a long list of pointers to different candy types. At the very end of the list there's another entry, containing the flag.
This can also be identified by running `strings` on the binary and grepping for `HTB`.