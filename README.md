# Network Data Parser

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
- **Frame length**: Taille de la frame en octets.
- **Timestamp**: Date et heure à laquelle la frame a été envoyé dans le réseau.

### [Data Link layer]
- **Destination Mac address**: L'adresse MAC du destinataire.
- **Source Mac address**: L'adresse MAC de l'expéditeur.
- **Ether type**: Indique le protocole encapsulé dans la frame du Data Link layer.

#### [ARP]
Étant donné que le protocole ARP permet la résolution d'adresse physique MAC par adresse IP. Nous avons besoin de connaître l'adresse MAC associé à l'adresse IP demandé par la source.
L'émetteur demande qui possède l'adresse IP X.X.X.X et le destinataire qui vérifie la question répond en lui donnant son adresse MAC. 
- **Sender MAC Address**: 
  - Request: L'adresse mac de l'émetteur.
  - Reply: L'adresse mac du destinataire qui répond à l'émetteur pour faire la résolution d'adresse IP/MAC.
- **Sender IP Address**:
  - Request: L'adresse IP de l'émetteur.
  - Reply: L'adresse IP du destinataire qui répond à l'émetteur.
- **Target MAC Address**:
  - Request: L'adresse MAC est initialisé à 0 car on ne connaît pas l'adresse MAC correspondant à l'adresse IP. C'est l'objet de notre question. 
  - Reply: L'adresse MAC de l'émetteur lors de la réponse.
- **Target IP Address**:
  - Request: L'adresse IP demandé par l'émetteur sur le réseau. 
  - Reply: L'adresse IP de l'émetteur.

### [Network layer]
#### [IPv4]
- **Identification**: Valeur unique permettant d'identifier les fragments du datagram.
- **Don't fragment**: Flag permettant de signaler si le datagram doit être fragmenté ou pas.
- **More fragment**: Flag permettant de signaler si le datagram contient d'autres fragments.
- **Fragment offset**: Permet de connaître l'offset des fragments afin de pouvoir les réassembler à la reception.
- **Source Ip Address**: L'adresse IP de l'expéditeur.
- **Destination Ip Address**: L'adresse IP du destinataire.
- **Protocol**: Indique le protocole encapsulé dans le paquet du Network layer.

#### [ICMP]
- **Type & Code**: Permettent généralement de connaître s'il s'agit d'une requête ou d'une réponse mais aussi s'il y a des erreurs.
- **Identifier**: L'identifiant permet de définir et reconnaître l'émetteur.
- **Sequence number**: Le numéro de séquence nous permet de savoir s'il manque un paquet lors des échanges entre émetteurs et récepteurs.
- **Timestamp**: Le timestamp est important car il nous permet de connaître la date et l'heure à laquelle les paquets sont reçus/envoyés.
- **Data**: Le champ data est affiché car il nous permet de voir s'il y a de l'exfiltration de données si un pattern a été choisi lors de la commande ping.

### [Transport layer]
#### [TCP]
- **Source port**: Port de l'expéditeur.
- **Destination port**: Port du destinataire.
- **Window**: Calculée et définie par le destinataire en fonction de la bande passante et du RTT. (round trip time: temps nécessaire pour qu'un signal soit envoyé et acquitté par le recepteur) La Window nous permet donc de calculer par la suite le nombre de Segments de taille maximale 1460 octets (en-tête exclu) à envoyer par l'expéditeur.
- **Sequence number**:
- **Acknowledgment number**:
- **Flag**:
  - **Acknowledgment**: Permet de confirmer la réception de paquets par l'hôte. La valeur du ACK=1 permet de confirmer que la connexion a bien été établie.
  - **Push**: Ce flag permet de prévenir l'hôte qu'il faut immédiatement envoyer la donnée vers la couche applicative. On peut vérifier s'il y a une attaque PUSH+ACK Flood où le flag PUSH force le serveur récepteur à vider sa pile (buffer) et de retourner une réponse ACK. (DDoS)
  - **Reset**: Reset permet de terminer une connexion internet et permet de vérifier s'il y a une attaque TCP reset. L'utilisation du flag reset se fait généralement lorsqu'on sent qu'il y a un probleme avec la connexion TCP où on aurait reçu un paquet non attendu.
  - **Syn**: Premiere étape pour établir une connexion. On peut vérifier s'il y a potentiellement une attaque SYN Flood où on tenterait d'établir plusieurs connexions légitimes d'affilées dans le but de rendre un service non fonctionnel. (DDoS)
  - **Fin**: Le flag Fin permet de terminer une connexion correctement a la fin d'une conversation.

#### [UDP]
- **Source port**: Port de l'expéditeur.
- **Destination port**: Port du destinataire.

### [Application layer]
#### [DHCP]
- **OpCode**: Permet de savoir s'il s'agit d'une requête ou bien d'une réponse.
- **Transaction ID**: Permet de connaître l'identifiant de la requête et de sa réponse.
- **Client MAC address**: L'adresse MAC du client.
- **Client IP address**: L'adresse IP donnée au client.
- **Server IP address**: L'adresse IP du serveur DHCP.
- **DHCP message type**: Permet de connaître le type de message tels que Discover, Offer, Request et ACK et de ce fait, de connaître à quelle étape nous nous situons dans l'adressage dynamique d'adresse IP par DHCP. 
- **IP address Lease time**: Temps accordé à l'utilisation d'une adresse IP par un appareil dans le réseau.
- **Requested IP address**: L'adresse IP demandée au serveur DHCP.

#### [DNS]
- **Transaction ID**: Permet de connaître l'identifiant de la requête et de sa réponse.
- **Queries**: Affiche la liste des questions pour connaître l'adresse ip du nom de domaine demandé.
- **Answer**: Affiche les réponses avec la résolution des nom de domaines. (avec l'adresse ip associé)
- **Authoritative Nameserver**: Affiche le nom de domaine racine auquel le nom de domaine appartient. (ICANN)
- **Additional Records** Affiche les données supplémentaires. (non demandées dans la question) envoyées par le serveur.

#### [HTTP]
- **Verb**: Verbe HTTP utilisé dans la requête.
- **Path**: Le chemin de la ressource demandée.
- **Version**: La version du protocole HTTP utilisé.
- **Data**: Le contenu de la requête HTTP. (header + body)


#### [FTP]
- **Request**:
  - **Request command**: Commande utilisé lors de la requête. (USER, PASSV, etc.)
  - **Request arguments**: Les arguments de la requêtes.
- **Reply**:
  - **Response code**: Le code de la réponse vis-à-vis de la requête. (prêt à recevoir un user par exemple)
  - **Response arguments**: Les arguments de la réponse.
