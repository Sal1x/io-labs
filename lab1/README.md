# Лабораторная работа 1

**Название:** "Разработка драйверов символьных устройств"

**Цель работы:** получить знания и навыки разработки драйверов символьных устройств для операционной системы Linux.

## Описание функциональности драйвера

- Драйвер создает символьное устройство `/dev/var3` и интерфейс для получения сведений `/proc/var3`

- При записи в файл `/dev/var3` считывается сумма введеных чисел

- При чтении из `/proc/var3` выводится последовательность всех сумм полученных с момента загрузки модуля

- При чтении из файла символьного устроства в кольцевой буфер ядра выводится последовательность всех сумм полученных с момента загрузки модуля


## Инструкция пользователя

```
$ sudo insmod lab1.ko

$ sudo rmmod lab1
```

## Примеры использования
```
$ echo "123n123" > /dev/var3 && cat /proc/var3 
246
$ echo "1n1n1n2" > /dev/var3 && cat /proc/var3 
246
251
$ echo "1000" > /dev/var3 && cat /proc/var3 
246
251
1251
```
