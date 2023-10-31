KEY = b"SUP3RS3CR3TK3Y"
CHECK = bytearray(b'\xe9\xef\xc0V\x8d\x8a\x05\xbe\x8ek\xd9yX\x8b\x89\xd3\x8c\xfa\xdexu\xbe\xdf1\xde\xb6\\')

def transform(flag):
    return [
        ((((f+24) & 0xff) ^ KEY[i%len(KEY)]) - 74) & 0xff
        for i, f in enumerate(flag)
    ]

def check(flag):
    return transform(flag) == CHECK

if __name__ == "__main__":
    print("🎃 Welcome to SpookyCheck 🎃")
    print("🎃 Enter your password for spooky evaluation 🎃")
    inp = input("👻 ")
    if check(inp.encode()):
        print("🦇 Well done, you're spookier than most! 🦇")
    else:
        print("💀 Not spooky enough, please try again later 💀")