"""
Server over here will be used to store hubs information
Hubs are those types of nodes, that decide to sacrifice their anonymity
and allow other users to connect to others via them
"""

import random

from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn


class Item(BaseModel):
    id: str
    host: str
    port: int


app = FastAPI()

hubs = {} # str : item

@app.post("/")
async def send_data(item: Item):
    hubs[item.id] = item
    return {
        item.id: item.model_dump()
    }


@app.get("/connect/")
async def connect():
    if not hubs:
        return {"error" : "No hubs available"}

    random_hub_id = random.choice(list(hubs.keys()))
    hub = hubs[random_hub_id]
    return {
        "id" : hub.id,
        "host" : hub.host,
        "port" : hub.port
    }


def run(host: str = "127.0.0.1", port: int = 8080):
    uvicorn.run(app, host=host, port=port)


if __name__ == '__main__':
    run()
