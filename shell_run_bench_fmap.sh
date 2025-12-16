#! /bin/bash
printf "Running benchmarks for FuzzyPSI protocol..."
printf "[ProType] [Dim] [Delta] [Size] [Com.(MB)] [Time(s)]\n"

./build/main -p 5 -n 8 12 -d 2 6 10 15 -delta 10 60 250 -m 0  -log 0 -trait 3

