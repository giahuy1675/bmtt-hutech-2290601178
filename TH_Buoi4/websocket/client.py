import tornado.ioloop
import tornado.websocket
from tornado.concurrent import Future
from tornado import gen

class WebSocketClient:
    def __init__(self, io_loop):
        self.connection = None
        self.io_loop = io_loop

    @gen.coroutine
    def connect_and_read(self):
        try:
            print("Connecting to server...")
            self.connection = yield tornado.websocket.websocket_connect(
                url="ws://localhost:8888/websocket/",
                ping_interval=10,
                ping_timeout=30,
            )
            print("Connected. Waiting for messages...")
            while True:
                message = yield self.connection.read_message()
                if message is None:
                    print("Connection closed by server. Reconnecting...")
                    yield gen.sleep(1)
                    yield self.connect_and_read()
                    break
                print(f"Received word from server: {message}")
        except Exception as e:
            print(f"Connection error: {e}. Retrying in 3s...")
            yield gen.sleep(3)
            yield self.connect_and_read()

    def start(self):
        self.io_loop.add_callback(self.connect_and_read)

    def stop(self):
        self.io_loop.stop()


def main():
    io_loop = tornado.ioloop.IOLoop.current()
    client = WebSocketClient(io_loop)
    client.start()
    io_loop.start()

if __name__ == "__main__":
    main()
