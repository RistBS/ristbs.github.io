---
layout:     post
title:      "Deep dive into ASREP Roasting"
date:       2023-01-22 01:37:00 +0300
---


Currently, I am developing a script that uses the impacket library. This script is for targeted ASREPRoasting. I learned a lot while doing this script, particularly how kerberos really works and more specifically when sending an AS-REQ message.

To give a quick reminder, the ASREProasting attack consists of requesting a TGT from the KDC for a user who does not have preauth enabled. To do this, we need to craft the AS-REQ message to request a TGT from the KDC. Once the request is sent, we get the AS-REP response which contains the TGT and the session key encrypted with the user's NT hash. We can crack this session key offline. We will start by talking about the script in general and then we will see what the AS-REQ message is composed of with wireshark and print() :D

> Note that my script version for asreproasting does not support passwords.


Let's start by talking about the libs used that allowed me to craft the AS-REQ message:

![image](https://user-images.githubusercontent.com/75935486/213896700-ab288c75-2dfd-4d2f-af52-3ef2ef3f845b.png)

on the side of impacket we import all that comes from kerberos version 5 like constants, Functions, Errors. Then we will use pyasn1 which plays a more than important role, this lib implements the ASN.1 standard in its entirety. For those who don't know, ASN.1 (Abstract Syntax Notation 1) is a notation used to describe data structures, for example:
```python
Record ::= SEQUENCE {
  id        INTEGER,
  room  [0] INTEGER OPTIONAL,
  house [1] INTEGER DEFAULT 0
}
```
This notation has several encoding rules for the data described by the ASN.1 like DER (Distinguished Encoding Rules) for the elaborated encoding rules or BER (Basic Encoding Rules) in our case we will use DER for data uniqueness. we also import NoValue from pyasn1, it's just a proper type of ASN.1.
- https://github.com/etingof/pyasn1

we will also import `hexlify` from binascii which will allow us to split a string composed of hex-tuples into distinct bytes. For random and datetime, we'll talk about them later.

Before building the package we have to declare some information that will be useful later on:
```python
domain = "SPOOKYSEC.LOCAL"
userName = "svc-admin"
clientName = Principal(userName, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
serverName = Principal('krbtgt/%s' % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
asReq = AS_REQ()
```
we declare clientName based on the user svc-admin and which will be built with the class `Principal()` with the constant `NT_PRINCIPAL` which corresponds to the name of the principal and which has a value of 1. For the serverName, we will have to concatenate the account krbtgt and the domain, because as you know the account **KRBTGT acts as a service account for the KDC**. Finally we will start the construction of our `AS-REQ` message with the class `AS_REQ()` which inherits from the `KDC_REQ` class.

![image](https://user-images.githubusercontent.com/75935486/213896717-29dc0c5c-d778-48f9-b02c-ed559685542b.png)

we can see 2 very important parts of the AS-REQ, `PA_DATA` and `REQ_BODY`, PADATA will contain all the data related to the pre-authentication and `REQ_BODY` it's a bit the body of the request. 

To start with we will have to define if the KDC determines that the returned ticket contains a PAC based on `include-pac` with `KERB_PA_PAC_REQUEST`:

![image](https://user-images.githubusercontent.com/75935486/213896730-75e0da95-7cdf-4749-92ea-6aa541479c99.png)

to do this we must include a bool in the field `include-pac`, I the value is set to True in the variable `requestPAC`, we can see the class `KERB_PA_PAC_REQUEST` below:

![image](https://user-images.githubusercontent.com/75935486/213896736-0cc4e721-8749-414f-926b-28b8b852137b.png)

once pacRequest is encoded with the DER rule we get this: `x30\x05\x0\x03\x01\xff`

we can now start to build the AS-REQ message using the information defined above plus other additional information:

![image](https://user-images.githubusercontent.com/75935486/213896744-312bd750-7f41-4a19-b80a-8568bf065fca.png)

`pvno` represents the version of kerberos, in this case we use the version 5, the field `msg-type` allows to know which type of message it is, we it is a message AS-REQ therefore we use its constant which is equal to 10:
```python
class ApplicationTagNumbers(Enum):
    AS_REQ         = 10
    AS_REP         = 11
    TGS_REQ        = 12
    TGS_REP        = 13
    AP_REQ         = 14
    AP_REP         = 15
```


2 fields of `padata` have the type `noValue` of the standard ASN.1, the 2 other fields (`padata-type` & `padata-value`) contain complementary information on the PAC extension that we were able to define a little before, `padata-type` contains the constant `PA_PAC_REQUEST` which is equal to 128, `padata-value` contains the encoded value of `pacRequest`.

![image](https://user-images.githubusercontent.com/75935486/213896755-59b47de4-2df0-432b-a1ea-9d2c1ce855cd.png)


Now we will talk about the options in the field `kdc-options`:

![image](https://user-images.githubusercontent.com/75935486/213896805-12be1b1a-62c0-45a3-b180-413530d23e3e.png)

we create a list with 3 values, `[1, 8, 3]` which correspond to the options of the `KDCOptions` class
```python
class KDCOptions(Enum):
		forwardable = 0x1
    proxiable   = 0x3
    renewable   = 0x8
```
a **forwardable ticket** allows a TGT to be forwarded to another machine, while a **proxiables ticket** tells the KDC that it can issue a new ticket to a different network address, based on the original ticket. With proxiables tickets, **a password is not required.** As for the renewable ticket, it is useful when a service wishes to have the ticket valid for an extended period of time by expanding the time available before expiration.

The binary value of `kdc-options` is *`0101000010000000000000000000000000000000`* because it is the addition of each option that is either 0 (False) or 1 (True). But impacket interprets the addition of the flags in decimal, i.e. the value of `kdc-options` is *1,350,565,888*, whereas wireshark interprets it in hexadecimal, so the value is `0x50800000`:

![image](https://user-images.githubusercontent.com/75935486/213896641-04b81d53-d2bd-4cbf-8cc0-14e64b5775af.png)

> we can see that there are many other options but we won't talk about them here. 

here we will add 2 fields, `sname` and `cname` which correspond to the server name (krbtgt/SPOOKYSEC.LOCAL) and client name (svc-admin).

![image](https://user-images.githubusercontent.com/75935486/213896785-ea7d4435-2ae5-419c-9f51-a88ecad733fe.png)

```python
cname=PrincipalName:
   name-type=1
   name-string=SequenceOf:
    svc-admin
....
sname=PrincipalName:
   name-type=1
   name-string=SequenceOf:
    krbtgt    SPOOKYSEC.LOCAL
```
> `name-string` & `name-type` is used to comply with the ASN.1 standard


let's continue with the `REQ-BODY` part by adding the realm, the timestamp and the nonce:

![image](https://user-images.githubusercontent.com/75935486/213896819-ab0f098c-d0d0-4b90-8bdb-a71f5a1be0fa.png)

basically the realm is the domain (SPOOKYSEC.LOCAL), the `till` field contains the expiration date, the `rtime` field contains the desired expiration time for the ticket, for `till` and `rtime` we'll use `datetime `adding 1 day more. `nonce` is a randomly generated number, you should know that security solutions are based on some of this information as nonce or till to detect a malicious tool, for example, for mimikatz, the value of the field till is `20370913024805Z` and the value of the field nonce is `12381973`but in our case we use the `getrandbits` function of random to generate random bits.

to finish with the AS-REQ we will add the `etype` field in `REQ_BODY`, this field will contain the encryption that will be used:

![image](https://user-images.githubusercontent.com/75935486/213896825-99b4bf78-df05-47e6-91a4-31338abe42b6.png)

- small reminder of the types available for a TGT:

| DES | RC4 | AES128 | AES128 |
|-----------|-----------|-----------|-----------|
| Key derived from the user's password | Key is equal to NT Hash | Key derived from the user's password (with salt) | Key derived from the user's password (with salt) |

in our case we will use the constant `rc4_hmac` which has the value 23:
```python
class EncryptionTypes(Enum):
    des_cbc_crc                  = 1
    des_cbc_md4                  = 2
    des_cbc_md5                  = 3
    aes128_cts_hmac_sha1_96      = 17
    aes256_cts_hmac_sha1_96      = 18
    rc4_hmac                     = 23
```

### REQ_BODY Content

![image](https://user-images.githubusercontent.com/75935486/213896833-b707538d-8b02-4dff-a6bd-cc2f78c73179.png)

### Complete AS-REQ message
```python
AS_REQ:
 pvno=5
 msg-type=10
 padata=SequenceOf:
  PA_DATA:
   padata-type=128
   padata-value=0x3005a0030101ff

 req-body=KDC_REQ_BODY:
  kdc-options=1350565888
  cname=PrincipalName:
   name-type=1
   name-string=SequenceOf:
    svc-admin

  realm=SPOOKYSEC.LOCAL
  sname=PrincipalName:
   name-type=1
   name-string=SequenceOf:
    krbtgt    SPOOKYSEC.LOCAL

  till=20220629232749Z
  rtime=20220629232749Z
  nonce=733933218
  etype=SequenceOf:
   23
```

## Recovering AS-REP

you must now send the AS-REQ and receive the AS-REP:

![image](https://user-images.githubusercontent.com/75935486/213896857-4eb323bc-7cc4-4fa7-adba-507155b08fd8.png)

the `sendReceive()` function will take care of sending the AS-REQ and receiving the AS-REP by taking as parameters the message (AS-REQ), the domain (SPOOKYSEC.LOCAL) and the kdchost. Then we decode the response to obtain the AS-REP message. 

To get the hash, we have to parse the AS-REP response and more precisely the `cipher` field in `enc-part`, for my part, it's under the hashcat format so I have to get also the etype which is 23.

![image](https://user-images.githubusercontent.com/75935486/213896868-91893b96-10ce-436e-bdef-8f834668ce1b.png)


Finally we will talk about the hash (edata) and what it contains. Below you can see what the hash contains globally:
```python
EncKDCRepPart  ::= SEQUENCE {
          key            [0] EncryptionKey,
          last-req        [1] LastReq,
          nonce          [2] UInt32,
          key-expiration  [3] KerberosTime OPTIONAL,
          flags          [4] TicketFlags,
          authtime        [5] KerberosTime,
          starttime      [6] KerberosTime OPTIONAL,
          endtime        [7] KerberosTime,
          renew-till      [8] KerberosTime OPTIONAL,
          srealm          [9] Realm,
          sname          [10] PrincipalName,
          caddr          [11] HostAddresses OPTIONAL
  }
```
the hash has several delimiters: `$krb5asrep$%d$%s@%s:%s$%s` this is what the hash is made of with the hashcat format:

![image](https://user-images.githubusercontent.com/75935486/213896888-7ae9a1fb-ffd4-435a-af6e-3d33299501fb.png)


### Useful resources

- [MIT Kerberos Documentation](http://web.mit.edu/kerberos/krb5-current/doc/index.html)
- [RFC 4120 - The Kerberos Network Authentication Service (V5)](https://datatracker.ietf.org/doc/html/rfc4120)
