---
title: "Vinkkejä Python-ohjelmointiin"
hidden: true
---

# Vinkkejä Python-ohjelmointiin

## Lukujen käsittely

### Kokonaisluvut

Pythonissa kokonaisluvut voivat olla miten pitkiä tahansa,
minkä ansiosta suuriakin kokonaislukuja voi käsitellä koodissa huoletta.

```python
a = 123456789
b = 987654321
print(a*b) # 121932631112635269
```

```python
x = 99
print(x**x) # 369729637649726772657187905628805440595668764281741102430259972423552570455277523421410650010128232727940978889548326540119429996769494359451621570193644014418071060667659301384999779999159200499899
```

### Liukuluvut

Liukulukujen etuna on, että niissä voi olla desimaaliosa:

```python
x = 12.527
```

Liukuluvuissa on kuitenkin ongelmana, että niissä tapahtuu pyöristysvirheitä.
Seuraava koodi havainnollistaa asiaa:

```python
x = 3*0.3+0.1
y = 1
if x == y:
    print("x ja y ovat samat")
if x < y:
    print("x on pienempi kuin y")
if x > y:
    print("x on suurempi kuin y")
```

Vaikka `x`:n ja `y`:n arvon pitäisi olla sama,
koodi tulostaa `x on pienempi kuin y`.
Syynä on, että laskua `3*0.3+0.1` ei pystytä laskemaan tarkasti,
vaan `x`:n arvoksi tulee hieman alle 1.

Tämän vuoksi liukulukuja kannattaa välttää _aina kun mahdollista_.
Yleensä löytyy jokin tapa, miten algoritmin voi toteuttaa tarkasti ilman liukulukuja.

## Lause ja lauseke

_Lause_ (_statement_) on ohjelmassa oleva komento,
kun taas _lauseke_ (_expression_) on jokin koodin osa, jolla on arvo.
Esimerkiksi `print(a+b)` on lause, jonka osana on lauseke `a+b`.

Toisaalta koska `print` on funktio, niin se myös palauttaa arvon.
Koska funktiolla ei ole muuta arvoa, se palauttaa `None`:

```python
print(print("moi")) # None
```

Ehdollinen lauseke `b if a else c` on arvoltaan `b`,
jos ehto `a` pätee, ja muuten `c`.
Esimerkiksi seuraavassa koodissa ehdollisen lausekkeen arvo
on `"parillinen"`, jos ehto `x%2 == 0` pätee
(eli `x` on parillinen), ja muuten `"pariton"`.

```python
s = "parillinen" if x%2 == 0 else "pariton"
```

## Lista

Pythonin perustietorakenne on _lista_,
joka muodostuu peräkkäin olevista alkioista.
Taulukon alkiot on numeroitu kokonaisluvuin
0, 1, 2, jne., ja niihin viitataan `[]` -merkinnän avulla.

Seuraava koodi luo lista `luvut`, jossa on 5 alkiota.
Jokainen arvo on aluksi 0.

```python
luvut = [0]*5
```

Toinen tapa luoda lista on antaa sen alkiot listana:

```python
luvut = [3,1,5,2,5]
```

Listan alkioita voi käsitellä samaan tapaan kuin tavallisia muuttujia:

```python
luvut[0] = 2
luvut[1] = 5
luvut[2] = luvut[0]+luvut[1]
```

Listan sisällön pystyy tulostamaan helposti:

```python
luvut = [1,2,3]
print(luvut) # [1, 2, 3]
```

## Viittaukset ja kopiointi

Pythonissa kaikki muuttujat ovat viittaustyyppisiä, eli ne osoittavat muistissa olevaan tietoon. Tällä ei ole merkitystä lukujen ja merkkijonojen käsittelyssä, koska niiden sisältö ei voi muuttua, mutta esimerkiksi listojen kanssa voi tulla yllätyksiä.

Seuraavan koodin toiminnassa ei ole mitään yllättävää:

```python
a = 3
b = a
b = 5
print(a) # 3
```

Kuitenkin kun saman koodin toteuttaa listoilla,
tulee yllättävämpi tulos:

```python
a = [1,2,3]
b = a
b[0] = 5
print(a[0]) # 5
```

Tässä `a` ja `b` viittaavat _samaan_ listaan,
eli kun listaa `b` muuttaa, niin muutos heijastuu
myös listaa `a`.
Tämä on yleinen syy bugeihin Python-ohjelmissa.

Jos taulukosta halutaan tehdä aito kopio,
jonka muuttaminen ei vaikuta alkuperäiseen taulukkoon,
yksi tapa on käyttää `[:]`-syntaksia:

```python
a = [1,2,3]
b = a[:]
b[0] = 5
print(a[0]) # 1
```

## Merkkijonot

Toisin kuin monissa kielissä, Pythonissa ei ole erikseen
tyyppejä merkki ja merkkijono, vaan merkki on merkkijono,
jossa on vain yksi merkki.

```python
c = "a" # merkki
s = "apina" # merkkijono
```

Tietyssä kohdassa olevan merkin saa haettua `[]`-syntaksilla:

```python
s = "apina"
print(a[1]) # p
```

Huomaa kuitenkin, että merkkijonoa ei pysty muuttamaan.

Funktio `ord` antaa merkkiä vastaavan merkkikoodin,
ja vastaavasti funktio `chr` antaa merkkikoodia vastaavan merkin.

```python
print(ord("A")) # 65
print(chr(65)) # A
```

Kätevä tapa tuottaa suuria merkkijonoja on käyttää monistamista.
Esimerkiksi seuraava koodi rakentaa merkkijonon,
jossa on miljoona `a`-merkkiä:

```python
s = "a"*10**6
```

## Komentorivin käyttäminen

On hyödyllinen taito osata suorittaa Python-koodi
komentorivillä.
Tällöin ohjelmoijalla on täysi kontrolli asioihin,
toisin kuin IDEä (esim. VS Code) käyttäessä.

Seuraavat esimerkit olettavat, että käytössä on Linux-ympäristö.
Muissa ympäristöissä komentoriviä käytetään melko samalla tavalla.

### Koodin suoritus

Seuraava komento suorittaa tiedostossa `koodi.py` olevan Python-koodin:

```
$ python3 koodi.py
```

Huomaa, että pelkkä komento `python` saattaa suorittaa koodin
Pythonin vanhalla 2-versiolla, joka ei ole yhteensopiva
nykyään käytössä olevan 3-version kanssa.

### Komentoriviparametrit

Moduulin `sys` lista `argv` sisältää ohjelmalle
annetut komentoriviparametrit.
Esimerkiksi seuraava ohjelma tulostaa kaikki parametrinsa:

```python
import sys

for a in sys.argv:
    print(a)
```

Voimme testata ohjelmaa suorittamalla se näin:

```
$ python3 koodi.py apina banaani cembalo
```

Nyt ohjelman tulostus on seuraava:

```
test.py
apina
banaani
cembalo
```

Huomaa, että ensimmäinen parametri on Python-tiedoston nimi.
