# A test TCP/UDP provider in FakeNet-NG's format: replies with the data uppercased
def HandleTcp(sock):
    while True:
        data = sock.recv(1024)
        if not data:
            break
        sock.sendall(b"PROVIDER:" + data.upper())


def HandleUdp(sock, data, addr):
    sock.sendto(b"PROVIDER:" + data.upper(), addr)
