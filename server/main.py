from port_retriever import PortRetriever
from server import Server


def main():
    try:
        server_host = 'localhost'  # I set this deterministically
        port = PortRetriever().get_port()
        server = Server(server_host, port)
        server.start()

    except Exception as e:
        print('An error occurred:', e)


if __name__ == '__main__':
    main()
