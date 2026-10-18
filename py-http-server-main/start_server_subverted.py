from py_http_server.middlewares import CompressMiddleware, DigestAuthSubvertedMiddleware, DefaultMiddleware
from py_http_server.routers import FileRouter
from py_http_server.networking import TCPAddress
from py_http_server import app_main

app_main(
    handler_chain=DefaultMiddleware(
        DigestAuthSubvertedMiddleware(
            next=FileRouter("."),
            pwdfile="passwords.txt"
        )
    ),
    http_listeners=[
        TCPAddress("127.0.0.1", 8080),
        TCPAddress("::1", 8080),
    ]
)
