# Proiect-PSO
1. Configurarea fisierelor de zona:
- Fisierul de zona cuprinde domeniul principal si doua subdomenii.
- Serverul este configurat sa raspunda la cererile A, AAAA si TXT pentru domeniul principal si la cererea A pentru subdomeniul "www".

2. Configurarea TTL:
- Fiecare domeniu care este adaugat in cache are setat un ttl de 300 de secunde.
- Compararea se va face scazand din timpul curent, timpul de cand a fost adaugat in cache.
- In functie de rezultat, domeniul va fi pastrat sau sters din cache.

3. Subdomenii si forward DNS:
- Cererile vor fi cautate intai in cache.
- Daca nu sunt gasite in cache, vor fi cautate in fisierele de zona.
- Daca sunt gasite in fisierele de zona, vor fi adaugate in cache.
- Daca nu sunt gasite in fisierele de zona, cautarea se va face intr-un server superior (8.8.8.8).
- Daca sunt gasite in serverul superior, vor fi adaugate in cache.
- Daca nu sunt gasite in serverul superior, sa fa transmite pachetul gol.

4. Cache DNS:
- Cache-ul este configurat printr-o lista de tipul DNSCacheEntry.
- Aceasta structura contine numele de domeniu, tipul cererii, valoarea, timpul cand a fost adaugata inregistrarea si ttl-ul.
- Am adaugat si functia print_cache() care scrie intr-un fisier lista de inregistrari din cache.

5. Functionalitate de logging:
- Este o functie care scrie intr-un fisier si tine cont de urmatoarele lucruri: timpul la care se scrie in fisier, tipul mesajului ("INFO", "ERROR") si mesajul propriu-zis.