#! /bin/bash
gcc -O2 weirdaaaaeeees.c -o weirdaaaaeeees
chmod +x weirdaaaaeeees
socat tcp-l:1337,reuseaddr,fork EXEC:"./weirdaaaaeeees",pty,rawer,echo=0