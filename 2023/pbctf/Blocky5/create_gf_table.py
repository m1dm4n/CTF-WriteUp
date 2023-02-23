from GF import GF
name1 = "add_table.inc"
name2 = "sub_table.inc"
name3 = "mul_table.inc"
f1 = open(name1, 'w')
f2 = open(name2, 'w')
f3 = open(name3, 'w')
size = 243*243
f1.write("static const uint8_t ADD_TABLE[%d] = {" % size)
f2.write("static const uint8_t SUB_TABLE[%d] = {" % size)
f3.write("static const uint8_t MUL_TABLE[%d] = {" % size)


for i in range(243):
    for j in range(243):
        f1.write("%s"%(GF(i) + GF(j)).to_int())
        f2.write("%s"%(GF(i) - GF(j)).to_int())
        f3.write("%s"%(GF(i) * GF(j)).to_int())
        if i==242 and j == 242:
            continue
        f1.write(", ")
        f2.write(", ")
        f3.write(", ")



f1.write("};")
f2.write("};")
f3.write("};")
