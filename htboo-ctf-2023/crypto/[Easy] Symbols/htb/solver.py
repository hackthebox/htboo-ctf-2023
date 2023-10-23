def is_quadratic_residue(a, p):
    return pow(a, (p-1)//2, p) == 1

p = 307163712384204009961137975465657319439
g = 1337

with open('output.txt') as f:
    encrypted_flag = eval(f.read())

flag = ''
for b in encrypted_flag:
    if is_quadratic_residue(b, p):
        flag += '0'
    else:
        flag += '1'

flag = int(flag, 2)
flag = int.to_bytes(flag, (flag.bit_length() + 7) // 8, 'big')

print(flag.decode())
