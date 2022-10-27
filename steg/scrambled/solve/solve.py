from PIL import Image
import numpy as np

SCRAMBLED = {}
UNSCRAMBLED = {}

def prng():
    seed = 0
    mul = 272
    inc = 26
    prime = 1009

    prng_list = []
    count = 0 
    while (count<600):
        i = (seed*mul+inc)%prime
        seed = i
        if(i not in prng_list and i<600):
            prng_list.append(i)
            count+=1
        else:
            continue

    return prng_list


def form_parts(pixel):
    for k in range(30):
        for l in range(20):
            part = Image.new("RGB",(60,60))
            for i in range(60):
                for j in range(60):
                    part.putpixel((j,i),tuple(pixel[i+60*l,j+60*k]))
            SCRAMBLED[l*30+k] = part
            path = "./temp/scrambled_parts/scr_img"+str(l*30+k)+".png"

img = Image.open("../files/scrambled.png")
pixel = np.array(img)

final_image = Image.new("RGB",(1800,1200))

form_parts(pixel)
random_parts = prng()

for i in range(600):
    UNSCRAMBLED[random_parts[i]] = SCRAMBLED[i]


for i in range(30):
    for j in range(20):
        final_image.paste(UNSCRAMBLED[j*30+i],(i*60,j*60,(i+1)*60,(j+1)*60))

final_image.save("./final_image.png")