## RUS
### Скрипт поиска уязвимых пакетов на *nix хостах (Ubuntu 14.04/16.04, CentOS 6/7, Debian 8). Берет список установленных пакетов по ssh и выполняет проверку. Так же отправляет метрики в Zabbix.
**Установка:**
* Скопировать скрипты в `/root/vulners-scanner`
* Создать директорию с ключами `mkdir /root/vulners-scanner/vulners-key`
* Сгенерировать ключ `ssh-keygen`
```
$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): /root/vulners-scanner/vulners-key/vulners_key
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /root/vulners-scanner/vulners-key/vulners_key.
Your public key has been saved in /root/vulners-scanner/vulners-key/vulners_key.pub.
The key fingerprint is:
SHA256:PREggK5EdKt6/y/nfZwYtg1M35HAL/vry+mBanHWMY4 root@localhost.localdomain
The key's randomart image is:
+---[RSA 2048]----+
|.. o... ....     |
| .o .  .   .o    |
|.. .      .  o . |
| .o      .... *  |
|.o      Soo. B + |
|o         *.E.+  |
|. .      . @.o.  |
| . .  . ..+.=..o |
|    ...=o.o. oBo |
+----[SHA256]-----+
```
* `chmod 600 /root/vulners-scanner/vulners-key/vulners_key*`
* Добавить 2 задания в `/etc/cron.d`:

**check_vulners**
```
# start check vulners daily at 8am
55 7 * * * root bash /root/vulners-scanner/get_vulners_db.sh &> /var/log/get_vulners_db_debug
00 8 * * * root bash /root/vulners-scanner/sendmail.sh &> /var/log/vulners_debug
```
**check_vulners_hourly** 

```
# start check vulners hourly
0 * * * * root bash /root/vulners-scanner/get_vulners_db.sh &> /var/log/get_vulners_db_debug
0 * * * * root python /root/vulners-scanner/vulners_over_ssh_scanner.py &> /var/log/zbx_vulners_debug
```
* Импортировать `Template_App_Vulners_Trap.xml` в **Zabbix**
* Список проверяемых хостов: `hosts`
* Установить необходимые модули для Python ` yum install python-paramiko epel-release python-pip && pip install py-zabbix executor`
* Добавление пользователя для сканирования:
```
useradd vulners-scanner
mkdir -p -m 700 /home/vulners-scanner/.ssh
echo "ssh-rsa XXX" >> /home/vulners-scanner/.ssh/authorized_keys
chown -R vulners-scanner:vulners-scanner /home/vulners-scanner/
chmod 600 /home/vulners-scanner/.ssh/authorized_keys
echo "vulners-scanner:password" | chpasswd
```

## ENG
