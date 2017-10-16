---
title: "Gentle usage of DBMS_CRYPTO"
layout: post
date: 2017-10-14 20:50
headerImage: false
tag:
- DATABASE
- AES ENCRYPTION ALGORITHM
category: blog
author: kunalrmhatre
description: Simple demonstration of DBMS_CRYPTO package present in Oracle Database 11g
---

Seriously, I never did encryption or hashing of data at the database layer. While developing backend APIs, I always encrypted or hashed data before storing it in the database, but yes, then I came to know about [DBMS_CRYPTO](https://docs.oracle.com/cd/B19306_01/appdev.102/b14258/d_crypto.htm) package which is available in Oracle Database 11g. 

DBMS_CRYPTO package allows us to encrypt and decrypt data at the database layer. The best thing is, it supports NIST approved **AES** encryption algorithm along with **3DES (2-Key and 3-Key)**, also supports hashing algorithms like **SHA-1**, **MD5**, and **MD4**, along with **HMAC-MD5** and **HMAC-SHA1**.

AES being my preferred encryption algorithm all the time, I gave it a shot. Creating UDFs for encryption and decryption using DBMS_CRYPTO is quite easy, *thanks to Oracle*. 

Let's see some of the significant DBMS_CRYPTO functions that we will be using to create our simple encrypt and decrypt UDFs for AES algorithm. I assume you are familiar with PL/SQL - Function.

If you are logged in as SYS (as SYSDBA) you are good to go, but if you are logged in as a normal user, you need to have **EXECUTE ON** privilege for DBMS_CRYPTO package. The following query should be executed as SYS:

{% highlight sql %}

GRANT EXECUTE ON DBMS_CRYPTO TO USER;

{% endhighlight %}

## DBMS_CRYPTO.ENCRYPT()

It takes 4 arguments in total, one is optional.  

**SRC** => Input data (or string) in RAW format. Before converting our input which would be in VARCHAR2 into RAW, we need to convert VARCHAR2 which is in the current database character set to VARCHAR2 in the **AL32UTF8** database character set. To achieve that, Oracle provides a function called [UTL_I18N.STRING_TO_RAW()](https://docs.oracle.com/cd/B19306_01/appdev.102/b14258/u_i18n.htm#i1001698). It takes 2 arguments, the string as a first argument and the database character set as a second argument, in return it gives the string in RAW format.

**TYP** => Type of encryption. Which is stated by adding appropriate PLS_INTEGER variables required for defining the encryption algorithm under subject. So, if we want AES256 with CBC mode, that would be, **DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC**. If PKCS#5 padding is required, then we can add **DBMS_CRYPTO.PAD_PKCS5** along with the previous value.

**KEY** => Takes encryption or decryption key in RAW format. For AES128, a key of length 16 bytes is required, for AES192 => 24 bytes and 32 bytes key for AES256. DBMS_CRYPTO provides a function called [RANDOMBYTES](https://docs.oracle.com/cd/B19306_01/appdev.102/b14258/d_crypto.htm#i1000605), which can be used to generate keys in RAW format.

**IV** => This argument is optional and should be used in case you will be using the same key to encrypt your recurring non-unique data, in short, each message or string will be encrypted with the same key but different IVs. Which gives you unique cipher blocks (for same messages or strings) hence decreasing the predictability by an attacker. If you are using CBC or CFC mode then make sure the length of the IV is same as the block size, which is always 16 bytes for all AES bit lengths (AES128, AES192, and AES256). If you are interested in reading more about IV, check the reference section at the end of the post.

After we get RAW encrypted data we can use [UTL_ENCODE.BASE64_ENCODE()](https://docs.oracle.com/cd/B19306_01/appdev.102/b14258/u_encode.htm#i999460) which converts RAW data into BASE64 encoded string preserving the RAW form, which indeed makes encrypted data (in RAW format) suitable to be stored in VARCHAR2. 

## DBMS_CRYPTO.DECRYPT()

It takes 4 arguments like DBMS_CRYPTO.ENCRYPT(). IV is optional here, but if you provide IV while encrypting a particular string or message then you must provide the same IV to this function while decrypting the same string or message. The only difference in here is, SRC argument will take BASE64 encoded RAW encrypted data, which will be decoded to get only RAW encrypted data using [UTL_ENCODE.BASE64_DECODE()](https://docs.oracle.com/cd/B19306_01/appdev.102/b14258/u_encode.htm#CACECFHF). This function will return decrypted data in RAW format and so we need to convert it from RAW to VARCHAR2 in the AL32UTF8 database character set and then to VARCHAR2 in the current database character set using [UTL_I18N.RAW_TO_CHAR()](https://docs.oracle.com/cd/B19306_01/appdev.102/b14258/u_i18n.htm#i998567).

## UDF for encryption

In this function we will be taking two arguments, the bit length for encryption and the data to encrypt. In declaration section, I have hard-coded the keys for demo purpose, although this should be not followed while creating functions for production use. Instead, store your keys in some secured wallet or vault and access them with a proper security mechanism for the process of encryption as well as decryption. So here I will be having 3 keys and 3 PLS_INTEGER variables, each for different bit length. 

{% highlight sql %}

CREATE OR REPLACE FUNCTION AES_ENCRYPT_VARCHAR2 (BIT_LENGTH IN VARCHAR2, INPUT_STRING IN VARCHAR2)

RETURN RAW

AS

	RAW_ENCRYPTED_STRING RAW(2000);

	-- Already generated keys (not recommended to hard-code keys in function for production use - as mentioned in post)

	RAW_KEY_BYTES_16 RAW(16) := '1D96A875D460C21A21539A3C4C0EA56E';
	RAW_KEY_BYTES_24 RAW(24) := '79BFB77B1A319D82169D4F6445C649218FD62A604207CE7C';
	RAW_KEY_BYTES_32 RAW(32) := '42B4F559DADB8E31D688BA973F6420F40D54DBDE4BBDC6167E282F0CB60BE76F';

	AES128 PLS_INTEGER := DBMS_CRYPTO.ENCRYPT_AES128+DBMS_CRYPTO.CHAIN_CBC+DBMS_CRYPTO.PAD_PKCS5;
	AES192 PLS_INTEGER := DBMS_CRYPTO.ENCRYPT_AES192+DBMS_CRYPTO.CHAIN_CBC+DBMS_CRYPTO.PAD_PKCS5;
	AES256 PLS_INTEGER := DBMS_CRYPTO.ENCRYPT_AES256+DBMS_CRYPTO.CHAIN_CBC+DBMS_CRYPTO.PAD_PKCS5;

BEGIN

	IF BIT_LENGTH = 'AES128' THEN
		
		-- AES128 ENCRYPTION
		-- For generating key of 16 Bytes in RAW format - skipped for now, as I have already declared the key
		-- RAW_KEY_BYTES_16 := DBMS_CRYPTO.RANDOMBYTES(BIT_LENGTH);
		
		RAW_ENCRYPTED_STRING := DBMS_CRYPTO.ENCRYPT 
		(
			SRC => UTL_I18N.STRING_TO_RAW(INPUT_STRING, 'AL32UTF8'),
			TYP => AES128,
			KEY => RAW_KEY_BYTES_16
		);

		-- BASE64 ENCODING - Makes RAW encrypted data to be suitable with VARCHAR2 storage

		RETURN UTL_ENCODE.BASE64_ENCODE(RAW_ENCRYPTED_STRING);

	ELSIF BIT_LENGTH = 'AES192' THEN
		
		-- AES192 ENCRYPTION
		-- For generating key of 24 Bytes in RAW format - skipped for now, as I have already declared the key
		-- RAW_KEY_BYTES_24 := DBMS_CRYPTO.RANDOMBYTES(BIT_LENGTH);
		
		RAW_ENCRYPTED_STRING := DBMS_CRYPTO.ENCRYPT 
		(
			SRC => UTL_I18N.STRING_TO_RAW(INPUT_STRING, 'AL32UTF8'),
			TYP => AES192,
			KEY => RAW_KEY_BYTES_24
		);

		-- BASE64 ENCODING - Makes RAW encrypted data to be suitable with VARCHAR2 storage

		RETURN UTL_ENCODE.BASE64_ENCODE(RAW_ENCRYPTED_STRING);

	ELSIF BIT_LENGTH = 'AES256' THEN
		
		-- AES256 ENCRYPTION
		-- For generating key of 32 Bytes in RAW format - skipped for now, as I have already declared the key
		-- RAW_KEY_BYTES_32 := DBMS_CRYPTO.RANDOMBYTES(BIT_LENGTH);
		
		RAW_ENCRYPTED_STRING := DBMS_CRYPTO.ENCRYPT 
		(
			SRC => UTL_I18N.STRING_TO_RAW(INPUT_STRING, 'AL32UTF8'),
			TYP => AES256,
			KEY => RAW_KEY_BYTES_32
		);

		-- BASE64 ENCODING - Makes RAW encrypted data to be suitable with VARCHAR2 storage

		RETURN UTL_ENCODE.BASE64_ENCODE(RAW_ENCRYPTED_STRING);

	ELSE

		-- INVALID BIT LENGTH
		
		RAISE_APPLICATION_ERROR (-20001,'Invalid Bit Length: Supported are AES128, AES192 and AES256.');

	END IF;

END AES_ENCRYPT_VARCHAR2;
/

{% endhighlight %}

## UDF for decryption

I feel function is self-explanatory.

{% highlight sql %}

CREATE OR REPLACE FUNCTION AES_DECRYPT_VARCHAR2 (BIT_LENGTH IN VARCHAR2, BASE64_RAW_ENCRYPTED_STRING IN RAW)

RETURN VARCHAR2

AS 
	
	RAW_DECRYPTED_STRING RAW(2000);

	-- Already generated keys (not recommended to hard-code keys in function for production use - as mentioned in post)

	RAW_KEY_BYTES_16 RAW(16) := '1D96A875D460C21A21539A3C4C0EA56E';
	RAW_KEY_BYTES_24 RAW(24) := '79BFB77B1A319D82169D4F6445C649218FD62A604207CE7C';
	RAW_KEY_BYTES_32 RAW(32) := '42B4F559DADB8E31D688BA973F6420F40D54DBDE4BBDC6167E282F0CB60BE76F';

	AES128 PLS_INTEGER := DBMS_CRYPTO.ENCRYPT_AES128+DBMS_CRYPTO.CHAIN_CBC+DBMS_CRYPTO.PAD_PKCS5;
	AES192 PLS_INTEGER := DBMS_CRYPTO.ENCRYPT_AES192+DBMS_CRYPTO.CHAIN_CBC+DBMS_CRYPTO.PAD_PKCS5;
	AES256 PLS_INTEGER := DBMS_CRYPTO.ENCRYPT_AES256+DBMS_CRYPTO.CHAIN_CBC+DBMS_CRYPTO.PAD_PKCS5;

BEGIN

	IF BIT_LENGTH = 'AES128' THEN

		-- AES128 DECRYPTION

		RAW_DECRYPTED_STRING := DBMS_CRYPTO.DECRYPT 
		(
			SRC => UTL_ENCODE.BASE64_DECODE(BASE64_RAW_ENCRYPTED_STRING),
			TYP => AES128,
			KEY => RAW_KEY_BYTES_16
		);

		RETURN UTL_I18N.RAW_TO_CHAR(RAW_DECRYPTED_STRING, 'AL32UTF8');

	ELSIF BIT_LENGTH = 'AES192' THEN
		
		-- AES192 DECRYPTION

		RAW_DECRYPTED_STRING := DBMS_CRYPTO.DECRYPT 
		(
			SRC => UTL_ENCODE.BASE64_DECODE(BASE64_RAW_ENCRYPTED_STRING),
			TYP => AES192,
			KEY => RAW_KEY_BYTES_24
		);

		RETURN UTL_I18N.RAW_TO_CHAR(RAW_DECRYPTED_STRING, 'AL32UTF8');

	ELSIF BIT_LENGTH = 'AES256' THEN
		
		-- AES256 DECRYPTION

		RAW_DECRYPTED_STRING := DBMS_CRYPTO.DECRYPT 
		(
			SRC => UTL_ENCODE.BASE64_DECODE(BASE64_RAW_ENCRYPTED_STRING),
			TYP => AES256,
			KEY => RAW_KEY_BYTES_32
		);

		RETURN UTL_I18N.RAW_TO_CHAR(RAW_DECRYPTED_STRING, 'AL32UTF8');

	ELSE

		-- INVALID BIT LENGTH
		
		RAISE_APPLICATION_ERROR (-20001,'Invalid Bit Length: Supported are AES128, AES192 and AES256.');

	END IF;

END AES_DECRYPT_VARCHAR2;
/

{% endhighlight %}

## Usage

{% highlight sql %}

SELECT AES_ENCRYPT_VARCHAR2('AES256','Privacy') AS ENCRYPTED FROM DUAL;
SELECT AES_DECRYPT_VARCHAR2('AES256','6279515877733457532B7759766B4771776B422B74513D3D') AS DECRYPTED FROM DUAL;

{% endhighlight %}

## Wrap-up

As you can see, this is not a production ready function yet. There should be length validation along with secure key management or repository set up and some more in depth analysis to make it robust enough to put on production. I hope this article was somewhat useful for people who are dealing with Oracle's DBMS_CRYPTO package for the first time. Have fun encrypting.

## References
- [DBMS_CRYPTO](https://docs.oracle.com/cd/B19306_01/appdev.102/b14258/d_crypto.htm)
- [Encrypting using AES-256, can I use 256 bits IV?](https://security.stackexchange.com/a/90850)
- [What size of initialization vector (IV) is needed for AES encryption?](https://crypto.stackexchange.com/a/50786)