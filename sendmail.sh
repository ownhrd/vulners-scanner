#!/bin/bash
# Igor Sidorenko
python /root/vulners-scanner/vulners_over_ssh_scanner.py | mail -s "Отчет об уязвимостях ИС $(date +%d.%m.%Y)" -r "Vulners Scanner <no-reply@example.com>" admins@example.com
