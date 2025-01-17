# Proiect-PSO
1. Configurarea fișierelor de zonă:
- Fișierul de zonă cuprinde domeniul principal și un subdomeniu (www).
- Serverul este configurat să răspundă la cererile A, AAAA și TXT pentru domeniul principal și la cererea A pentru subdomeniul "www".

2. Configurarea TTL:
- Fiecare domeniu care este adăugat în cache are setat un ttl de 300 de secunde.
- Compararea se va face scăzând din timpul curent, timpul de când a fost adăugat în cache.
- În funcție de rezultat, domeniul va fi păstrat sau șters din cache.

3. Subdomenii și forward DNS:
- Cererile vor fi căutate întâi în fișierele de zonă.
- Daca nu sunt găsite în zonă, vor fi căutate în cache.
- Daca nu sunt găsite în cache, cautarea se va face într-un server superior (8.8.8.8).
- Daca sunt găsite în serverul superior, vor fi adăugate în cache.
- Daca nu sunt găsite în serverul superior, sa va transmite pachetul gol.

4. Cache DNS:
- Cache-ul este configurat printr-o listă de tipul DNSCacheEntry.
- Această structură conține numele de domeniu, tipul cererii, valoarea, timpul când a fost adăugată înregistrarea și ttl-ul.
- Am adăugat și funcția print_cache() care scrie într-un fișier lista de înregistrări din cache.

5. Funcționalitate de logging:
- Este o funcție care scrie într-un fișier și ține cont de următoarele lucruri: timpul la care se scrie în fișier, tipul mesajului ("INFO", "ERROR") și mesajul propriu-zis.
