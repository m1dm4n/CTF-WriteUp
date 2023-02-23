#!/bin/bash
python ./create_gf_table.py \
&& python ./getdata.py \
&& g++ -O3 findLastRoundKey.cpp -o findLastRoundKey \
&& ./findLastRoundKey | python getflag.py