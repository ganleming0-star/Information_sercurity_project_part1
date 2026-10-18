from py_http_server.middlewares import CompressMiddleware, DefaultMiddleware
from py_http_server.routers import FileRouter
from py_http_server.networking import TCPAddress
from py_http_server import app_main

app_main(
    handler_chain=DefaultMiddleware(CompressMiddleware(FileRouter("/home/user/docroot"))),
    http_listeners=[
        TCPAddress("127.0.0.1", 80),
        TCPAddress("::1", 80),
    ],
)
