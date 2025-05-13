from http.server import SimpleHTTPRequestHandler, HTTPServer

class MyHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        # Print the port number when a request is made
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"Hello from server on port 6000!")

def run():
    # Set up the HTTP server to listen on port 6000
    server_address = ('0.0.0.0', 6000)
    httpd = HTTPServer(server_address, MyHandler)
    print("Server running on port 6000")
    httpd.serve_forever()

if __name__ == '__main__':
    run()
