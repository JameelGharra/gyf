class PortRetriever:
    """
    PortRetriever is a singleton class that retrieves a port number from a file
    or returns a default port if the file is not found or contains invalid data.

    This class ensures that only one instance of PortRetriever is created
    throughout the application, following the Singleton design pattern.
    """
    _instance = None

    def __new__(cls):
        # the goal is to not create a new instance if one already exists
        if cls._instance is None:
            cls._instance = super(PortRetriever, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, 'initialized'):
            self.DEFAULT_PORT = 1256  # Default port value if file read fails
            self.initialized = True

    def get_port(self):
        try:
            with open('port.info', 'r') as file:
                port = int(file.read())

        except (FileNotFoundError, ValueError):
            port = self.DEFAULT_PORT
            print('Retrieving data from port.info failed, port is', self.DEFAULT_PORT)
        return port
