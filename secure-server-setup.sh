#!/usr/bin/env bash
#
# secure-server-setup.sh — готовый скрипт первичной защиты сервера (Ubuntu/Debian)
# Часть курса linuxfullroadmap. Автоматизирует «Раздел 30. База по защите серверов».
#
# ЧТО ДЕЛАЕТ:
#   1. Обновляет систему и включает автоматические security-обновления
#   2. Создаёт обычного пользователя с правами sudo (если его ещё нет)
#   3. Усиливает SSH: вход по ключу, без root, без паролей, на нестандартном порту
#   4. Настраивает файрвол ufw по принципу default-deny
#   5. Ставит и включает fail2ban
#
# КАК ЗАПУСКАТЬ (СНАЧАЛА ПРОЧИТАЙТЕ!):
#   1. Поднимите ВИРТУАЛКУ и обкатайте скрипт на ней, прежде чем трогать боевой сервер.
#   2. У вас УЖЕ должен быть рабочий SSH-ключ, и он должен быть положен новому
#      пользователю (скрипт умеет это сделать из ~/.ssh/authorized_keys текущего root).
#   3. Держите ВТОРОЙ открытый SSH-сеанс во время запуска. Если что-то пойдёт не так —
#      не закрывайте его, пока не убедитесь, что новый вход работает.
#   4. Отредактируйте переменные в блоке НАСТРОЙКИ ниже под себя.
#   5. Запуск:  sudo bash secure-server-setup.sh
#
# ВНИМАНИЕ: скрипт МЕНЯЕТ доступ к серверу. Неправильная настройка может отрезать вас
# от машины. Это учебный шаблон — понимайте каждую строку, а не запускайте вслепую.

set -euo pipefail

# ============================ НАСТРОЙКИ ============================
# Поменяйте под себя ПЕРЕД запуском!

NEW_USER="alex"          # имя обычного пользователя с sudo
SSH_PORT="2222"          # нестандартный порт SSH (1024–65535)
ALLOW_WEB="yes"          # открыть порты 80/443 (yes/no)
SSH_PUBKEY=""            # ОПЦИОНАЛЬНО: вставьте сюда строку публичного ключа (ssh-ed25519 AAAA... )
                         # если пусто — скрипт скопирует ключи root из его authorized_keys

# ==================================================================

# --- проверки перед стартом ---
if [[ $EUID -ne 0 ]]; then
  echo "Запустите от root:  sudo bash $0" >&2
  exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "Этот скрипт рассчитан на Debian/Ubuntu (apt). На вашей системе apt не найден." >&2
  exit 1
fi

echo "==> Цель: пользователь '$NEW_USER', SSH-порт $SSH_PORT. Через 5 секунд начнём (Ctrl+C для отмены)."
sleep 5

# --- 1. Обновления ---
echo "==> [1/5] Обновление системы и автоматические security-обновления"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y
apt-get install -y unattended-upgrades
dpkg-reconfigure -f noninteractive unattended-upgrades || true

# --- 2. Пользователь с sudo ---
echo "==> [2/5] Создание пользователя '$NEW_USER' с правами sudo"
if ! id "$NEW_USER" >/dev/null 2>&1; then
  adduser --disabled-password --gecos "" "$NEW_USER"
fi
usermod -aG sudo "$NEW_USER"

# Перенос SSH-ключа новому пользователю
install -d -m 700 -o "$NEW_USER" -g "$NEW_USER" "/home/$NEW_USER/.ssh"
AUTH_FILE="/home/$NEW_USER/.ssh/authorized_keys"
if [[ -n "$SSH_PUBKEY" ]]; then
  echo "$SSH_PUBKEY" > "$AUTH_FILE"
elif [[ -f /root/.ssh/authorized_keys ]]; then
  cp /root/.ssh/authorized_keys "$AUTH_FILE"
else
  echo "!! Не найден публичный ключ. Задайте SSH_PUBKEY или положите ключ root до запуска." >&2
  echo "!! Чтобы не отрезать себе доступ, SSH пока НЕ будет переведён в режим 'только ключи'." >&2
  SKIP_PASSWORD_OFF="yes"
fi
chmod 600 "$AUTH_FILE" 2>/dev/null || true
chown -R "$NEW_USER:$NEW_USER" "/home/$NEW_USER/.ssh"

# --- 3. Усиление SSH ---
echo "==> [3/5] Настройка SSH (бэкап исходного конфига рядом)"
SSHD=/etc/ssh/sshd_config
cp -n "$SSHD" "${SSHD}.bak.$(date +%Y%m%d%H%M%S)" || true

set_sshd() {  # set_sshd <директива> <значение>
  local key="$1" val="$2"
  if grep -qiE "^#?\s*${key}\b" "$SSHD"; then
    sed -i -E "s|^#?\s*${key}\b.*|${key} ${val}|I" "$SSHD"
  else
    echo "${key} ${val}" >> "$SSHD"
  fi
}

set_sshd "Port" "$SSH_PORT"
set_sshd "PermitRootLogin" "no"
set_sshd "PubkeyAuthentication" "yes"
set_sshd "MaxAuthTries" "3"
set_sshd "ClientAliveInterval" "300"
set_sshd "AllowUsers" "$NEW_USER"
if [[ "${SKIP_PASSWORD_OFF:-no}" != "yes" ]]; then
  set_sshd "PasswordAuthentication" "no"
fi

# Проверяем конфиг ДО перезапуска — иначе можно потерять доступ
if sshd -t; then
  systemctl restart ssh 2>/dev/null || systemctl restart sshd
  echo "   SSH перезапущен. Порт: $SSH_PORT"
else
  echo "!! Ошибка в sshd_config — SSH НЕ перезапущен. Проверьте конфиг вручную." >&2
  exit 1
fi

# --- 4. Файрвол ---
echo "==> [4/5] Файрвол ufw (default-deny)"
apt-get install -y ufw
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow "${SSH_PORT}/tcp"            # СНАЧАЛА свой SSH-порт!
if [[ "$ALLOW_WEB" == "yes" ]]; then
  ufw allow 80,443/tcp
fi
ufw --force enable
ufw status verbose

# --- 5. fail2ban ---
echo "==> [5/5] fail2ban (защита от перебора)"
apt-get install -y fail2ban
# Минимальный jail.local: следим за SSH на нашем порту
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port    = $SSH_PORT
EOF
systemctl enable --now fail2ban
systemctl restart fail2ban
fail2ban-client status sshd || true

# --- Итог ---
echo
echo "============================================================"
echo " ГОТОВО. Базовая защита применена."
echo "------------------------------------------------------------"
echo " ВАЖНО: НЕ закрывая текущий сеанс, проверьте новый вход:"
echo "    ssh -p $SSH_PORT $NEW_USER@<IP-сервера>"
echo " Если вход работает — можно закрывать старую сессию."
echo
echo " Чек-лист для самопроверки — в README, раздел 30."
echo "============================================================"
