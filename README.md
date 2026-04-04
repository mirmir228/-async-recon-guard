# AsyncReconGuard 🛡️
(dated March 14, 2025)
**AsyncReconGuard** - это высокопроизводительный асинхронный инструмент на Python для автоматизации разведки (reconnaissance) веб-приложений. Разработан для быстрой проверки безопасности заголовков и поиска утечек конфигурационных файлов.

## ⚡ Ключевые особенности
- **Asynchronous Engine:** Использование `aiohttp` позволяет обрабатывать сотни запросов одновременно.
- **Security Audit:** Автоматическая проверка на отсутствие критических заголовков (CSP, HSTS, X-Frame-Options).
- **Leak Detection:** Поиск потенциально опасных файлов в корневых директориях (`.env`, `.git`, и др.).
- **Professional Structure:** Чистый код с использованием асинхронных контекстных менеджеров.

## 🛠 Технологический стек
- Python 3.9+
- Asyncio
- Aiohttp

## 🚀 Установка и запуск
```bash
# Клонировать репозиторий
git clone [https://github.com/mirmir228/async-recon-guard.git](https://github.com/mirmir228/async-recon-guard.git)

# Установить зависимости
pip install -r requirements.txt

# Запустить сканер
python scanner.py
