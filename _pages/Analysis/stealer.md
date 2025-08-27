---
# Front Matter - Metapodaci o postu
# Popunite ove vrednosti za svaki post.
# Vrednosti su objašnjene u 'posting guide.md'.

title: "Naziv Analize: Dubinska Analiza [Ime Malvera]"
date: "2025-08-27"
tags:
    - [GlavnaKategorija]
    - [Tehnika1]
    - [Platforma]
thumbnail: "https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Fwww.inceptionnet.com%2Fwp-content%2Fuploads%2F2021%2F04%2Fmalware-threats-1200x900.jpeg&f=1&nofb=1&ipt=697ea0455481591af81151ed0d8e5574af052d913b0e160c2ecec90a74250f04"
bookmark: true # Postavite na 'true' da bi se post pojavio u navigaciji sa strane

---

> **Sažetak:** Ovde u 2-3 rečenice opišite ključne nalaze analize.
> Na primer: *Analiza otkriva višestepeni infostealer malver koji koristi [Tehnika] za perzistenciju i komunicira sa C2 serverom preko [Protokol].*

---

# Informacije o Uzorku

| Atribut | Vrednost |
|---|---|
| **MD5** | `[MD5 heš vrednost]` |
| **SHA-256** | `[SHA-256 heš vrednost]` |
| **Tip Fajla** | `[npr. PE32, ELF, .NET Assembly]` |
| **Veličina** | `[npr. 256 KB]` |

---

# Statička Analiza

U ovoj sekciji se opisuju rezultati analize bez pokretanja malvera. Fokus je na dekompilaciji, stringovima, importovanim funkcijama i drugim statičkim artefaktima.

### Korišćeni Alati
* `[Ime alata 1]` - *[Kratak opis namene]*
* `[Ime alata 2]` - *[Kratak opis namene]*

### Ključna Zapažanja
* Pronađeni su sumnjivi stringovi koji ukazuju na `[Funkcionalnost]`.
* Malver importuje funkcije za `[npr. manipulaciju registry ključevima, mrežnu komunikaciju]`.

---

# Dinamička Analiza

Ovde se opisuje ponašanje malvera nakon pokretanja u kontrolisanom okruženju (sandbox).

![Slika analize u alatu](/assets/img/primer-slike.png "Opcioni opis slike")

### Mrežna Aktivnost
* Malver uspostavlja komunikaciju sa **[C2 Domen ili IP Adresa]** na portu `[Broj porta]`.
* Podaci se šalju putem `[HTTP POST / GET]` zahteva.

### Promene na Sistemu
* **Kreirani fajlovi:**
    * `[Putanja do kreiranog fajla 1]`
    * `[Putanja do kreiranog fajla 2]`
* **Registry ključevi (perzistencija):**
    * `[Putanja do registry ključa]`

---

# Primer Koda: YARA Pravilo

```yara
/*
  YARA pravilo za detekciju ovog uzorka.
  Pravilo je bazirano na jedinstvenim stringovima ili bajt sekvencama.
*/
rule DETEKCIJA_[ImeMalvera]
{
    meta:
        author = "3krup"
        date = "2025-08-27"
    strings:
        $hex_string = { E8 [4] FF FF FF 50 E8 [4] FF FF FF }
        $text_string = "JedinstveniStringIzMalvera"
    condition:
        uint16(0) == 0x5a4d and all of them
}
