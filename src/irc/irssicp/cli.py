import zmq
import sys
import readline

tys = sys.argv[1].lower() # such westerners, damn python
if tys == 'sub':
    ty = zmq.SUB
elif tys == 'req':
    ty = zmq.REQ

c=zmq.Context()
s=c.socket(ty)
s.connect(sys.argv[2])
if ty == zmq.SUB:
    s.setsockopt(zmq.SUBSCRIBE, sys.argv[3])

while True:
    if ty == zmq.REQ:
        s.send(raw_input("command: "))
    print(s.recv())

