A common CRC bruteforce challenge. Use pngcheck to confirm that the width and height of the image was wrong.
First find the checksum value: 0x1763adc8.Then, brute the dimensions that match the checksum value.A simple bruteforce script :-

```python
from zlib import crc32  
data = open("./file.png",'rb').read()
index = 12
ihdr = bytearray(data[index:index+17])
width_index = 7
height_index = 11

for x in range(1,1000):
    height = bytearray(x.to_bytes(2,'big'))
    for y in range(1,1000):
        width = bytearray(y.to_bytes(2,'big'))
        for i in range(len(height)):
            ihdr[height_index - i] = height[-i -1]
        for i in range(len(width)):
            ihdr[width_index - i] = width[-i -1]
        if hex(crc32(ihdr)) == '0x1763adc8':
            print("width: {} height: {}".format(width.hex(),height.hex()))
    for i in range(len(width)):
            ihdr[width_index - i] = bytearray(b'\x00')[0]
```

Run the script,find the dimensions and get the image.After that use stegsolve to change the RGB channels and get the flag.
