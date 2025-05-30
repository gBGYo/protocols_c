# Общие сведение

lab1 --- утилита реализующая шифрования файла в соответствие с алгоритмом ГОСТ 34.12-2018 (``Кузнечик'').

Язык программирования: C.
ОС: Linux или WSL.

# Функциональное назначение

Утилита предназначена для осуществления зашифрования конфиденциальных
данных с учетом рекомендаций данных в Р 1323565.1.012-2017.

# Описание логической структуры

Программа осуществляет:
1. Проверку целостности исполняемого файла: int check_exe_integrity(char *exe_path).
2. Разграничение доступа в соответствие с учетной записью пользователя: int check_valid_user(struct passwd *pw).
3. Проверку времени истечения действия ключевой информации: int check_key_expiration(uint8_t key[32]).
4. Чтение и зашифрование информации из первого файла и запись во второй файл: void kuz_ofb_encrypt(FILE *f_in, FILE *f_out, Kuznyechik *kuz).

# Используемые технические средства

1. ОС: Windows 11 WSL2;
2. Процессор: AMD Ryzen 5 5500U;
3. Оперативная память: 16 ГБ DDR4;
4. Компилятор: GCC version 11.4.0.

# Вызов и загрузка

```bash
lab1 </путь/к/входному/файлу> </путь/к/входному/файлу>
```

# Входные данные

Путь к файлу, содержимое которого необходимо зашифровать и
путь к файлу, в который будет записан ШТ

# Выходные данные

ШТ