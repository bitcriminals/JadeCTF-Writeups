First of all the challenge was based upon a real incident that occured in spain.In case you are interested you can read about it.

https://www.xataka.com/seguridad/discos-duros-villarejo-parecen-inexpugnables-desempolvan-misterio-truecrypt-su-supuesta-inseguridad

First question is that how we can understand that it is a truecrypt or veracrypt container.You can see the file size(always constant like 100 MB or 200 MB) or see the file signature. and entropy.All these are just parameters that  might help you in detecting the file.To know more you can read about it in the blog given below.

https://www.raedts.biz/forensics/detecting-truecrypt-veracrypt-volumes/

Now, To be 100% sure you can use truecrypt2john to get some hashes and put it in hashcat.

Now, you had to know the right mode and the password.In this case , the default algo was used that is AES + SHA-512.

To help people find the password a hint was given that the password is small.
Thus, you can bruteforce it with hashcat.

To decrypt it,first find the encrypted key which is first 512 byte of the file.You can use dd command for this.

```
dd.exe if=truth of=truth.tc bs=512 count=1
```

Then, you can use hashcat to decrypt the encrypted key.

```
hashcat -a 3 -w 1 -m 13721 truth.tc ?d?d?d?d
```
This will give you the password.
Use the password and mount the container.Inside the container,you will find a txt file and a an image.
The image hinted towards stegsnow and password for stegsnow was in the metadata of the image.
Use stegsnow and find the flag.
