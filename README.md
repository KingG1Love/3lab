# Лабораторная работа №3 — Работа с уязвимостями

**Проект:** [spring-projects/spring-boot](https://github.com/spring-projects/spring-boot)  
**Дистрибутив:** openSUSE Leap 15.5

---

## Структура репозитория

```
lab3/
├── README.md               
├── requirements.txt        ← зависимости Python
├── run_all.sh              ← запуск всех задач
├── task1/
│   ├── task1_collect_deps.py     ← сбор зависимостей проекта
│   └── result_task_1.json        ← РЕЗУЛЬТАТ
├── task2/
│   ├── task2_check_vulns.py      ← проверка через GHSA GraphQL API
│   └── result_task_2.json        ← РЕЗУЛЬТАТ 
├── task3/
│   ├── task3_analyze.py          ← анализ уязвимостей, таблица
│   ├── result_task_3.json        ← РЕЗУЛЬТАТ
│   └── result_task_3.md          ← РЕЗУЛЬТАТ 
├── task4/
│   ├── task4_inventory_os.py     ← инвентаризация ОС (на openSUSE)
│   └── result_task_4.json        ← РЕЗУЛЬТАТ 
└── task5/
    ├── task5_osv_scan.py         ← osv-scanner workflow (на openSUSE)
    ├── result_task_5.json        ← РЕЗУЛЬТАТ
    └── result_task_5.md          ← РЕЗУЛЬТАТ
```

---

## Требования

```bash
pip3 install requests packaging
```

Для задач 4 и 5 — выполнять **на openSUSE Leap 15.5** с установленным `osv-scanner`.

---

## Задача 1 — Сбор зависимостей проекта

**Инструмент:** парсинг `platform/spring-boot-dependencies/build.gradle` (BOM) и всех `build.gradle` подпроектов.

**Запуск:**
```bash
python3 task1/task1_collect_deps.py
```

**Результат:** `task1/result_task_1.json`

**Итог:** 661 зависимость, экосистема — `maven`.

| Экосистема | Количество |
|------------|-----------|
| maven      | 661       |

**Сложности:**  
- Версии зависимостей в BOM задаются через переменные (`${assertjVersion}`), которые нужно резолвить из `gradle.properties`.
- Некоторые зависимости объявлены без явной версии (используют BOM-управление версиями) — такие собираются из BOM напрямую.

---

## Задача 2 — Проверка уязвимостей через GHSA GraphQL API

**Инструмент:** GitHub Security Advisory API (GraphQL endpoint: `https://api.github.com/graphql`)

**Настройка токена:**

> Перед запуском установите переменную окружения с GitHub токеном:
```bash
export GITHUB_TOKEN=ghp_ТОКЕН
```

Или откройте `task2/task2_check_vulns.py` и замените строку:
```python
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "TOKEN")
```
на:
```python
GITHUB_TOKEN = "ghp_ТОКЕН"
```

**Запуск:**
```bash
export GITHUB_TOKEN=ghp_...
python3 task2/task2_check_vulns.py
```

**Результат:** `task2/result_task_2.json`

**Формат ответа GHSA:**
- Используется GraphQL `securityVulnerabilities` с фильтром по имени пакета и экосистеме (`MAVEN`)
- Диапазоны уязвимых версий в [semver](https://semver.org/lang/ru/): `>= 1.0.0, < 2.0.0`
- `firstPatchedVersion` — первая версия, вышедшая из уязвимого диапазона
- `secure_version` — максимальная из `firstPatchedVersion` по всем применимым уязвимостям

**Сложности:**
- API ограничен rate limit (~5000 запросов/час с токеном), поэтому добавлена задержка 150ms между запросами
- Версии Maven не всегда являются корректным semver (например, `2.6.1.Final`), поэтому используется `packaging.version.Version` с fallback

---

## Задача 3 — Анализ уязвимостей

**Запуск:**
```bash
python3 task3/task3_analyze.py
```

**Результат:** `task3/result_task_3.json`, `task3/result_task_3.md`

Таблица отсортирована по убыванию количества уязвимостей.

**Стратегии устранения:**

| Severity | Стратегия |
|----------|-----------|
| CRITICAL | Немедленное обновление до `secure_version` |
| HIGH | Обновление в ближайшем времени |
| MODERATE | Обновление в следующем релизном цикле |
| LOW | Обновление при следующем крупном апдейте |
| UNKNOWN | Ручной анализ через NVD/OSV |

---

## Задача 4 — Инвентаризация ОС (openSUSE Leap 15.5)

**Запускать на системе с openSUSE Leap 15.5.**

**Запуск:**
```bash
python3 task4/task4_inventory_os.py
```

**Результат:** `task4/result_task_4.json`

**Инструменты:** `rpm -qa --queryformat`, `/etc/os-release`, `platform` (stdlib).  
**Fallback:** `zypper packages --installed-only` если `rpm` недоступен.

**Версионирование пакетов в openSUSE (RPM):**

Формат версии: `epoch:version-release` или просто `version-release`

Примеры:
```
bash: 5.1-150400.3.9.1
  ↑      ↑   ↑
  │      │   └─ release (номер пакета в дистрибутиве)
  │      └──── version (upstream версия)
  └────────── name

openssl: 1.1.1l-150400.7.93.1
  release "150400.7.93.1" означает:
  - 150400 → openSUSE Leap 15.4 (источник пакета)
  - 7.93.1 → номер ревизии пакета в дистрибутиве
```

**Сравнение версий в RPM:**
- Используется алгоритм RPM `rpmvercmp`
- `1.2.3-4` < `1.2.3-5` (более новый release)
- `1.2.3` < `1.2.4` (более новая upstream версия)
- `1.2.3` < `2:1.2.3` (epoch имеет приоритет)

---

## Задача 5 — OSV-scanner (openSUSE Leap 15.5)

**Запускать на системе с openSUSE Leap 15.5.**

### Установка osv-scanner на openSUSE Leap 15.5

```bash
# Скачать бинарник
curl -L https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 \
  -o /usr/local/bin/osv-scanner
chmod +x /usr/local/bin/osv-scanner
osv-scanner --version
```

### Запуск

```bash
# Все шаги последовательно (занимает время из-за обновления системы):
python3 task5/task5_osv_scan.py

# Или по шагам:
python3 task5/task5_osv_scan.py --step 1   # инвентаризация до обновления
python3 task5/task5_osv_scan.py --step 2   # osv-scanner до обновления
python3 task5/task5_osv_scan.py --step 3   # sudo zypper update
python3 task5/task5_osv_scan.py --step 4   # инвентаризация после + osv-scanner
python3 task5/task5_osv_scan.py --step 5   # сравнение результатов
```

**Результат:** `task5/result_task_5.json`, `task5/result_task_5.md`

**Формат SBOM:** CycloneDX 1.6 JSON с `purl` в формате `pkg:rpm/opensuse.leap/{name}@{version}?arch={arch}&distro=leap-15.5`

---

## .gitignore

```gitignore
# Результаты
**/result_task_*.json
**/result_task_*.md
**/sbom_*.json
**/osv_*.json
**/*_before.json
**/*_after.json
```
