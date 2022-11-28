with open ("strings", "rb") as file:
    string = file.read()
can_read = ""
for i in string:
    if chr(i).isprintable():
        can_read += chr(i)
id = can_read.index("picoCTF")
end_id = can_read.index("}", id, -1)
print(can_read[id:end_id+1])