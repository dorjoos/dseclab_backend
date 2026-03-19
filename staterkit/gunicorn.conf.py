import multiprocessing

bind = "127.0.0.1:8003"
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "eventlet"
timeout = 120
keepalive = 5
max_requests = 1000
max_requests_jitter = 50
accesslog = "/var/log/dseclab/access.log"
errorlog = "/var/log/dseclab/error.log"
loglevel = "info"
