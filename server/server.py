from fastapi import FastAPI
from starlette.responses import Response
import uvicorn


class Server:
    def __init__(self, host: str = "localhost", port: int = 8080):
        self.host = host
        self.port = port
        self.network_peers = {} # <id : host:port>
        self.app = FastAPI()

    def run(self):
        uvicorn.run(self.app, host=self.host, port=self.port)


if __name__ == '__main__':
    server = Server()
    server.run()

