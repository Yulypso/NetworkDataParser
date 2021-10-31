# RiShark

## Author

[![Linkedin: Thierry Khamphousone](https://img.shields.io/badge/-Thierry_Khamphousone-blue?style=flat-square&logo=Linkedin&logoColor=white&link=https://www.linkedin.com/in/tkhamphousone/)](https://www.linkedin.com/in/tkhamphousone)

---

<br/>

## Setup

```bash
$ git clone https://github.com/Yulypso/RiShark.git
$ cd RiShark
$ chmod +x RiShark.sh
```

---

<br/>

## Start RiShark

```bash
$ bash RiShark.sh -i <input path/to/file.pcap> [-n] [<n° frame selected>] [-d]
```

---

<br/>

## Manual

```bash
-- RiShark arguments--

  -i <input file name>          Input pcap file name
  -n <n° frame selected>        Selected frames to display
  -d                            Debug mode, displays every fields
```

<br/>

### Some examples

```bash
$ bash RiShark.sh -i RiShark.pcap
```
> RiShark will parse RiShark.pcap and displays all frames

<br/>

```bash
$ bash RiShark.sh -i RiShark.pcap -n 1 2 5 256
```
> RiShark will parse RiShark.pcap and displays only frames n°1, 2, 5 and 256

<br/>

```bash
$ bash RiShark.sh -i RiShark.pcap -n 1 2 5 256 -d
```
> RiShark will parse RiShark.pcap and displays every fields (debug mode) only frames n°1, 2, 5 and 256

<p align="center" width="100%">
    <img align="center" width="800" src="https://user-images.githubusercontent.com/59794336/139539028-015d723e-9502-445d-8d52-046f8b7c8d4f.png"/>
</p>

<br/>

---

## Explications des champs affichés (FR)

### Pcap Header
- **File**: Nom du fichier pcap analysé.
- **Data link type**: Type d'interface traité. (Ethernet (1) uniquement dans notre cas)
- **Total frames**: Nombre de frames inclus dans le fichier pcap.

### [Frame Header]
- **Frame length**: Taille de la frame en octets
- **Timestamp**: Date et heure à laquelle la frame a été envoyé dans le réseau.

### [Data Link layer]
- **Destination Mac address**: L'adresse MAC du destinataire.
- **Source Mac address**: L'adresse MAC de l'expéditeur.
- **Ether type**: Indique le protocole encapsulé dans la frame du Data Link layer.

#### [ARP]

### [Network layer]
#### [IPv4]
- **Don't fragment**: Flag permettant de signaler si le datagram doit être fragmenté ou pas.
- **More fragment**: Flag permettant de signaler si le datagram contient d'autres fragments.
- **Fragment offset**: Permet de connaître l'offset des fragments afin de pouvoir les réassembler à la reception.
- **Source Ip Address**: L'adresse IP de l'expéditeur.
- **Destination Ip Address**: L'adresse IP du destinataire.
- **Protocol**: Indique le protocole encapsulé dans le paquet du Network layer.

#### [ICMP]


### [Transport layer]
#### [TCP]
- ****

#### [UDP]
- **Source port**: Port de l'expéditeur.
- **Destination port**: Port du destinataire.

### [Application layer]
#### [DHCP]

#### [DNS]

#### [HTTP]

#### [FTP]
