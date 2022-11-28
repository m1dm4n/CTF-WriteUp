def getmapchar(filename, mapping):
    with open(filename, "r") as f:
        cipher_text = f.read()
    for c in cipher_text:
        if not c in mapping.keys():
            continue
        mapping[c] += 1

def main():
    # Create mapping
    characters = ''.join(map(chr, range(0x20, 0x7f)))
    print(f'{characters = }')
    mapping1 = {c: 0 for c in characters}
    mapping2 = {c: 0 for c in characters}
    # Counting characters
    getmapchar("D:\code\ctf\hackme\shuffle\crypted.txt", mapping1)
    getmapchar("D:\code\ctf\hackme\shuffle\plain.txt", mapping2)
    mapping1 = dict(sorted(mapping1.items(), key=lambda item: item[1]))
    mapping2 = dict(sorted(mapping2.items(), key=lambda item: item[1]))
    print(mapping1)
    print(mapping2)
    assert len(mapping1) == len(mapping2)

    T = str.maketrans(''.join(mapping1.keys()), ''.join(mapping2.keys()))
    print(T)
    cipher_text = open("D:\code\ctf\hackme\shuffle\crypted.txt", "r").read()
    print(cipher_text.translate(T))
    

main()