# NetEncryptor
Encryptor of CSharp binary, raw shellcode and any strings with AES or XOR. Built for the combined usage of NetLoader to provide enchanced obfuscation.
Default using AES encryption to encrypt CSharp binary using key "Passw0rd", salt "salt" and iv "iv".

# Usage

You can simply input the CSharp binary with argument -file and encrypt with default settings:
```texinfo
C:\Users\VoldeSec\Desktop\NetEncryptor.exe -file Rubeus.exe
[+] Key for AES encryption: Passw0rd
[+] Salt for AES encryption: salt
[+] IV for AES encryption: iv
[+] AES encrypting...
[+] Encrypted file output to C:\Users\VoldeSec\Desktop\R-u-b-e-u-s_enc.txt
```
NetEncryptor also supports different modes and encryptions:
```texinfo
Usage:

        NetEncryptor.exe -file <CSharp binary>

Options:
        -mode string
                [*] cs - Encrypt CSharp binary and output HEX to new text file.
                [*] bin - Encrypt raw shellcode file binary and output to new bin file.
                [*] string - Encrypt string and output to current console.
        -en string
                [*] AES - AES encryption.
                [*] XOR - XOR encryption.
        -file string
                The file/path to a CSharp binary/raw shellcode.
        -key string
                The key for AES/XOR encryption.
        -salt string
                The salt for AES encryption only.
        -iv string
                The iv for AES encryption only.
        -random
                Random the key, salt and iv.
        -s string
                String to encrypt in string mode.
```

## AES encryption with manual key, salt and iv:
```texinfo
C:\Users\VoldeSec\Desktop\NetEncryptor.exe -mode cs -en AES -key voldesec -salt voldesec -iv voldesec -file Rubeus.exe
[+] Key for AES encryption: voldesec
[+] Salt for AES encryption: voldesec
[+] IV for AES encryption: voldesec
[+] AES encrypting...
[+] Encrypted file output to C:\Users\VoldeSec\Desktop\R-u-b-e-u-s_enc.txt
```

## Raw shellcode AES encryption with random key:
```texinfo
C:\Users\VoldeSec\Desktop\NetEncryptor.exe -mode bin -en AES -file raw.bin --random
[+] Key for AES encryption: voldesec
[+] Salt for AES encryption: voldesec
[+] IV for AES encryption: voldesec
[+] AES encrypting...
[+] Encrypted file output to C:\Users\VoldeSec\Desktop\R-u-b-e-u-s_enc.txt
```
## String AES encryption:
```texinfo
C:\Users\VoldeSec\Desktop\NetEncryptor.exe -mode string -s Voldesec
[+] Key for AES encryption: Passw0rd
[+] Salt for AES encryption: salt
[+] IV for AES encryption: iv
[+] AES encrypting string: Voldesec
[+] Encrypted String:
byte[] Voldesec_enc = new byte[16] {
0x99, 0x0e, 0xde, 0x23, 0x5d, 0xff, 0xc8, 0x77, 0xb2, 0x37, 0x03, 0x89, 0x75, 0xc5, 0xad, 0x93
};
```
# Credits
NetLoader - <https://github.com/Flangvik/NetLoader>

Sektor7 RTO Malware Development Essentials - <https://institute.sektor7.net/red-team-operator-malware-development-essentials>
