# py-http-server

## About
This project implements an HTTP(S) server supporting HTTP versions 1.0 and 1.1.

## Configuration Examples
To configure the server, `py_http_server.app_main()` can be called from a Python script with custom arguments.

The argument `handler_chain` can be constructed using user-defined classes or built-in components like below.

### Serving the current working directory
```python
from py_http_server.middlewares import CompressMiddleware, DefaultMiddleware
from py_http_server.routers import FileRouter
from py_http_server.networking import TCPAddress
from py_http_server import app_main

app_main(
    handler_chain=DefaultMiddleware(CompressMiddleware(FileRouter("."))),
    http_listeners=[
        TCPAddress("127.0.0.1", 80),
        TCPAddress("::1", 80),
    ],
)
```

### Reverse proxy
```python
from py_http_server.middlewares import (
    DefaultMiddleware,
    CompressMiddleware,
    RewriteRedirectsMiddleware,
)
from py_http_server.routers import ReverseProxyRouter
from py_http_server.networking import TCPAddress
from py_http_server import app_main

app_main(
    handler_chain=DefaultMiddleware(
        CompressMiddleware(
            RewriteRedirectsMiddleware(
                # "set_proxy_headers=False" makes the proxy transparent
                ReverseProxyRouter("http://localhost:8080", set_proxy_headers=False),
                {"localhost:8080": "localhost"},
            )
        )
    ),
    http_listeners=[
        TCPAddress("127.0.0.1", 80),
        TCPAddress("::1", 80),
    ],
)
```

### Forward proxy
```python
from py_http_server.routers import ForwardProxyRouter
from py_http_server.networking import TCPAddress
from py_http_server import app_main

app_main(
    handler_chain=ForwardProxyRouter(),
    http_listeners=[
        TCPAddress("127.0.0.1", 80),
        TCPAddress("::1", 80),
    ],
)
```

### Middlewares
1. **BasicAuthMiddleware**  
   Enforces basic HTTP authentication for all requests.

2. **CompressMiddleware**  
   Compresses responses based on client's `Accept-Encoding` value, supports `gzip`, `brotli`, `zstd` and `deflate`.

3. **DefaultMiddleware**  
   Adds default headers `Server` and `Date` to all responses.

4. **VirtualHostMiddleware**  
   Forwards the request to different handler chains based on the `Host` header's value.

5. **MinimizeMiddleware**  
   Minimizes HTML, CSS, JS and JSON responses. Not recommended for production use.

5. **EnforceHTTPSMiddleware**  
   Redirects all HTTP requests to HTTPS URLs, optionally adds HSTS header to all responses.

5. **RewriteRedirectsMiddleware**  
   Rewrites the Location, Content-Location and URI headers using the provided alias map.

### Routers

> [!NOTE]
> `CodeRouter` is a base class and cannot be used on its own.
1. **CodeRouter**  
   Auto-discovers route handlers using a `@route(path)` decorator for mapping paths to handler functions. Calls `default_route` for any non-handled route.

2. **DebugRouter**  
   Provides predefined routes for debugging:
   - `/`: Displays request details in HTML.
   - `/json`: Displays request details in JSON.
   - `/error`: Raises an error in the route handler.

3. **FileRouter**  
   Serves static files from a specified directory. Supports `ETag`, `Last-Modified` headers, and generated directory index pages.

4. **ReverseProxyRouter**  
   Proxies requests to the specified host. Supports `X-Forwarded-{For, Host, Proto}` and `Forwarded` headers and can preserve `Host` header.

> [!NOTE]
> `ForwardProxyRouter` allows any destination host by default. Specify the `allowed_hosts` parameter to change this behavior.
5. **ForwardProxyRouter**  
   Proxies requests to any host. Supports `CONNECT` and HTTP proxying and can be used as HTTP or HTTPS proxy server.
