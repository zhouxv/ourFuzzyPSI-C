#! /bin/bash
printf "Running benchmarks for FuzzyPSI protocol...\n"
printf "[ProType] [Dim] [Delta] [Size] [Com.(MB)] [Time(s)]\n"

ns=(8 12 16)
dims=(2 6 10 15)
deltas=(10 60 250)


for n in "${ns[@]}"; do
  for dim in "${dims[@]}"; do
    for delta in "${deltas[@]}"; do
      ./build/main -p 5 -n $n -d $dim -delta $delta -m 0 -log 0 -trait 3 -fake
    done
  done
done
