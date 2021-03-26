# Лабораторная работа 2

**Название:** "Разработка драйверов блочных устройств"

**Цель работы:**   
получить знания и навыки разработки драйверов блочных устройств для операционной системы Linux

## Описание функциональности драйвера

Драйвер блочного устройства создает виртуальный жесткий диск в оперативной памяти с размером 50 Мбайт. Созданный виртуальный диск содержит один первичный раздел размером 30Мбайт и один расширенный раздел, содержащий два логических раздела размером 10Мбайт каждый.

## Инструкция по сборке

Собирается с помощью команды ```make```.

## Инструкция пользователя

Для запуска драйвера необходимо ввести команду ```insmod block_dr.ko``` , которая загружает модуль ядра в систему. Для выгрузки модуля драйвера нужно ввести команду sudo ```rmmod block_dr```.



## Примеры использования

### Вывод разделов виртуального диска

```bash
alex@salix-mint:~/IO/io-labs/lab2$ sudo parted /dev/mydisk
GNU Parted 3.2
Using /dev/mydisk
Welcome to GNU Parted! Type 'help' to view a list of commands.
(parted) unit mib print                                                   
Model: Unknown (unknown)
Disk /dev/mydisk: 50.0MiB
Sector size (logical/physical): 512B/512B
Partition Table: msdos
Disk Flags: 

Number  Start    End      Size     Type      File system  Flags
 1      0.00MiB  30.0MiB  30.0MiB  primary   ext4
 2      30.0MiB  50.0MiB  20.0MiB  extended               lba
 5      30.0MiB  40.0MiB  10.0MiB  logical   ext4
 6      40.0MiB  50.0MiB  10.0MiB  logical   ext4
```

### Форматирование разделов диска с помощью утилиты mkfs.vfat

```bash
alex@salix-mint:~/IO/io-labs/lab2$ sudo mkfs.vfat /dev/mydisk1
mkfs.fat 4.1 (2017-01-24)
vagrant@vagrant:~/IO/io-labs/lab2$ sudo mkfs.vfat /dev/mydisk5
mkfs.fat 4.1 (2017-01-24)
vagrant@vagrant:~/IO/io-labs/lab2$ sudo mkfs.vfat /dev/mydisk6
mkfs.fat 4.1 (2017-01-24)
```

### Измерение скорости передачи данных при копировании файлов между разделами созданного виртуального диска

```bash
alex@salix-mint:~/IO/io-labs/lab2$ sudo dd if=/dev/mydisk1 of=/dev/mydisk5 bs=512 count=20000 oflag=direct
20000+0 records in
20000+0 records out
10240000 bytes (10 MB, 9.8 MiB) copied, 0.255166 s, 40.1 MB/s

alex@salix-mint:~/IO/io-labs/lab2$ sudo dd if=/dev/mydisk1 of=/dev/mydisk6 bs=512 count=20000 oflag=direct
20000+0 records in
20000+0 records out
10240000 bytes (10 MB, 9.8 MiB) copied, 0.252593 s, 40.5 MB/s 

alex@salix-mint:~/IO/io-labs/lab2$ sudo dd if=/dev/mydisk5 of=/dev/mydisk6 bs=512 count=20000 oflag=direct
20000+0 records in
20000+0 records out
10240000 bytes (10 MB, 9.8 MiB) copied, 0.255658 s, 40.1 MB/s
```

### Измерение скорости передачи данных при копировании файлов между разделами виртуального и реального жестких дисков

```bash
alex@salix-mint:~/IO/io-labs/lab2$ sudo dd if=/dev/sda1 of=/dev/mydisk1 bs=512 count=20000 oflag=direct
20000+0 records in
20000+0 records out
10240000 bytes (10 MB, 9.8 MiB) copied, 0.262327 s, 39.0 MB/s

alex@salix-mint:~/IO/io-labs/lab2$ sudo dd if=/dev/sda1 of=/dev/mydisk5 bs=512 count=20000 oflag=direct
20000+0 records in
20000+0 records out
10240000 bytes (10 MB, 9.8 MiB) copied, 0.240079 s, 42.7 MB/s

alex@salix-mint:~/IO/io-labs/lab2$ sudo dd if=/dev/sda1 of=/dev/mydisk6 bs=512 count=20000 oflag=direct
20000+0 records in
20000+0 records out
10240000 bytes (10 MB, 9.8 MiB) copied, 0.250703 s, 40.8 MB/s

alex@salix-mint:~/IO/io-labs/lab2$ sudo dd if=/dev/mydisk1 of=/dev/sda1 bs=512 count=20000 oflag=direct
20000+0 records in
20000+0 records out
10240000 bytes (10 MB, 9.8 MiB) copied, 1.34483 s, 7.6 MB/s

alex@salix-mint:~/IO/io-labs/lab2$ sudo dd if=/dev/mydisk5 of=/dev/sda1 bs=512 count=20000 oflag=direct
20000+0 records in
20000+0 records out
10240000 bytes (10 MB, 9.8 MiB) copied, 1.2951 s, 7.9 MB/s
```