# Общие сведение

lab4 --- утилита демонстрирующая применения протокола CRISP,
описанного в ГОСТ Р 71252-2024.

Язык программирования: C.
ОС: Linux или WSL.

# Функциональное назначение

Утилита предназначена для локальной демонстрации использования протокола CRISP
с учетом рекомендаций данных в Р 1323565.1.012-2017.

# Описание логической структуры

Программа осуществляет:
1. Проверку целостности исполняемого файла: int check_exe_integrity(char *exe_path).
2. Разграничение доступа в соответствие с учетной записью пользователя: int check_valid_user(struct passwd *pw).
3. Проверку времени истечения действия ключевой информации: int check_key_expiration(uint8_t key[32]).
4. Создание CRISP-сообщения: void crisp_encode(Crisp *crisp, const uint8_t *data, size_t data_size, uint8_t *raw_crisp_message, uint16_t *raw_crisp_message_len).
5. Восстановление полученного CRISP-сообщения: void crisp_decode(Crisp *crisp, const uint8_t *raw_crisp_message, uint16_t raw_crisp_message_len, CrispMessage *crisp_message).
6. Проверка совпадения исходного ОТ и ОТ, полученного после восстановления CRISP-сообщения.

# Используемые технические средства

1. ОС: Windows 11 WSL2;
2. Процессор: AMD Ryzen 5 5500U;
3. Оперативная память: 16 ГБ DDR4;
4. Компилятор: GCC version 11.4.0.

# Вызов и загрузка

```bash
lab4
```