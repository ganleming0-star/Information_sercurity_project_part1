from .middlewares import CompressMiddleware, DefaultMiddleware
from .networking import TCPAddress
from .routers import FileRouter
from .main import app_main

app_main(
    handler_chain=DefaultMiddleware(CompressMiddleware(FileRouter("."))),
    http_listeners=[
        TCPAddress("127.0.0.1", 80),
        TCPAddress("::1", 80),
    ],
)
