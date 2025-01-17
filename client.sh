#!/bin/bash

# Lista de domenii
DOMAINS=("altex.ro" "hm.com" "olx.com" "www.zara.com" "elefant.ro" "facebook.com" "instagram.com" "mta.ro")

# Adresa serverului și portul
SERVER="127.0.0.1"
PORT="8080"

# Numărul total de execuții
NUM_RUNS=10

for ((i=1; i<=NUM_RUNS; i++))
do
    # Selectează un domeniu aleatoriu din listă
    RANDOM_DOMAIN=${DOMAINS[$RANDOM % ${#DOMAINS[@]}]}
    
    echo "Running dig for $RANDOM_DOMAIN (instance $i)..."
    dig @$SERVER -p $PORT $RANDOM_DOMAIN &
done

# Așteaptă finalizarea tuturor proceselor
wait

echo "All commands have completed."