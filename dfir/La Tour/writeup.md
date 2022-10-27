It was clearly mentioned  in the prompt that the flag was hidden somewhere in the internet.Also,if you see the running processes,you can clearly see that firefox and internet explorer was running.

If you look for the browser history of firefox and internet explorer then, you will find a pastebin link in internet explorer history.But, the pastebin was password encrypted.

To help you find the password, a file named hint.txt was there in desktop in which the word "hash"
was repeatedly used.

This indicated that  the password was stored in  form of a hash.

To find the hash you can use the hashdump plugin which dumps all the user hash.

After, getting the NTML hash you can crack it by simply putting it on crackstation and get the password.Then,use the password and open the pastebin link and you will get the flag.


