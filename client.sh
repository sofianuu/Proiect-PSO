#!/bin/bash


CMD="dig @127.0.0.1 -p 8080 altex.com"

NUM_RUNS=10

for ((i=1; i<=NUM_RUNS; i++))
do
    echo "Running instance $i..."
    $CMD & 
done

wait

echo "All commands have completed."
