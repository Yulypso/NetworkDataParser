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
