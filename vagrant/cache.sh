apt-get install -y redis-server

echo "bind 127.0.0.1 192.168.56.12" >> /etc/redis/redis.conf
systemctl restart redis