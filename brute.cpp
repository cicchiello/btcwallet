/*
Copyright (c) 2017 Joe Cicchiello.  All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal with the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimers.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimers in the
     documentation and/or other materials provided with the distribution.
  3. Neither the names of <NAME OF DEVELOPMENT GROUP>, <NAME OF
     INSTITUTION>, nor the names of its contributors may be used to endorse
     or promote products derived from this Software without specific prior
     written permission.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
WITH THE SOFTWARE.
*/

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

#include <string>
#include <map>
#include <vector>

#include "eccrypto.h"
#include "oids.h"
#include "integer.h"

int SHA256_Final(unsigned char *md, SHA256_CTX *c);

#define RIPEMD160_DIGEST_LENGTH 20
#define ADDRESS_LENGTH 25
const unsigned char *ripemd160Hash(unsigned char *buf, const unsigned char *data, int length);

bool b58enc(char *b58, size_t *b58sz, const void *data, size_t binsz);


#define BUF_SEGMENT 65536
#define BUF_LEN (65536*4)
#define BUF_WATERMARK (65536*3)
unsigned char buf[BUF_LEN]; int f; int bufpos, buffill;
unsigned long long fpos, ftotallen, fnextcp;
int num_recovered, num_pend_pub, num_pend_pub_comp, num_pend_priv, num_dups;

static void show_progress(void) {
	printf("INFO:show_progress: %4.1f%% done, %i keys recovered, %i %i %i pend\n",
		100.0*(fpos-buffill+bufpos)/ftotallen, num_recovered, num_pend_pub, num_pend_pub_comp, num_pend_priv);
	fflush(stdout);
}

static int refill_buf(void) {
	int ret;
	if(bufpos > BUF_WATERMARK) {
		memcpy(buf, buf + BUF_SEGMENT, BUF_LEN-BUF_SEGMENT);
		buffill -= BUF_SEGMENT;
		bufpos -= BUF_SEGMENT;
	}
	if(buffill < BUF_LEN) {
		ret = read(f, buf+buffill, BUF_LEN-buffill);
		if(ret < 0) {
			perror("Device read");
			exit(1);
		}
		if (ret > 0) {
		  printf("TRACE:refill_buf; Read %i bytes\n", ret);
		  fflush(stdout);
		}
		buffill += ret;
		fpos += ret;
		if(fpos > fnextcp) {
			show_progress();
			fnextcp = fpos + (ftotallen/1024);
		}
		return ret;
	} else {
		return -1;
	}
}

static const unsigned char *fromHexString(unsigned char *buf, const char *hexString, int len) {
  int i = 0, bufi = 0;
  for(i = 0; i < len; i += 2) {
    unsigned char b = 0;
    char c = hexString[i];
    if ((c >= 'a') && (c <= 'f')) c = c - 'a' + 10;
    if ((c >= 'A') && (c <= 'F')) c = c - 'A' + 10;
    if ((c >= '0') && (c <= '9')) c = c - '0';
    b += c * 16;
    c = hexString[i+1];
    if ((c >= 'a') && (c <= 'f')) c = c - 'a' + 10;
    if ((c >= 'A') && (c <= 'F')) c = c - 'A' + 10;
    if ((c >= '0') && (c <= '9')) c = c - '0';
    b += c;
    buf[bufi++] = b;
  }
  return buf;
}

static const char *toHexString(char *buf, const unsigned char *data, int len) {
  int i;
  for(i = 0; i < len; i++) {
    sprintf(buf+i*2,"%02x", data[i]);
  }
  buf[len*2] = 0;
  return buf;
}

static const char *toBase58String(char *buf, const unsigned char *data, int len) {
  size_t rlen;
  bool stat = b58enc(buf, &rlen, data, len);
  if (!stat) {
    printf("ERROR:toBase58String: b58enc returned failure status\n");
    return 0;
  }
  buf[rlen] = 0;
  return buf;
}

static void dump_hex(unsigned char* data, int len) {
	int i;
	for(i = 0; i < len; i++) {
		printf("%02x", data[i]);
	}
	printf("\n");
	fflush(stdout);
}

static const unsigned char *pubFromPriv(unsigned char *pubkeyBuf, const unsigned char *privkey) {
  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::PrivateKey privateKey;
  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::PublicKey publicKey;
  CryptoPP::Integer pkey_i(privkey, 32);
  privateKey.Initialize( CryptoPP::ASN1::secp256k1(), pkey_i );
  privateKey.MakePublicKey(publicKey);
  const CryptoPP::ECP::Point& q = publicKey.GetPublicElement();
  q.x.Encode(pubkeyBuf, 32);
  q.y.Encode(pubkeyBuf+32, 32);
  
  return pubkeyBuf;
}




static const unsigned char *SHA256Hash(unsigned char *buf, const unsigned char *pubkey, int len) {
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, pubkey, len);
  SHA256_Final(buf, &sha256);

  return buf;
}


static const unsigned char *addressFromPub(unsigned char *addressBuf, const unsigned char *pubkey, int len) {
  unsigned char sha256Buf[SHA256_DIGEST_LENGTH+1];
  
  unsigned char epubkey[len+1];
  epubkey[0] = 0x04;
  memcpy(epubkey+1, pubkey, len);
  const unsigned char *sha256 = SHA256Hash(sha256Buf, epubkey, len+1);

  unsigned char extendedRipemd160Buf[RIPEMD160_DIGEST_LENGTH+2];
  unsigned char *ripemd160Buf = extendedRipemd160Buf+1;
  // first byte will be hardcoded 0, per:
  // https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
  
  extendedRipemd160Buf[0] = 0;
  
  const unsigned char *ripemd160 = ripemd160Hash(ripemd160Buf, sha256, SHA256_DIGEST_LENGTH);
  const unsigned char *eripemd160 = ripemd160-1;

  unsigned char eripemd160_sha256Buf[SHA256_DIGEST_LENGTH+1];
  const unsigned char *eripemd160_sha256 = SHA256Hash(eripemd160_sha256Buf, eripemd160, RIPEMD160_DIGEST_LENGTH+1);

  unsigned char eripemd160_sha256_sha256Buf[SHA256_DIGEST_LENGTH+1];
  const unsigned char *eripemd160_sha256_sha256 = SHA256Hash(eripemd160_sha256_sha256Buf, eripemd160_sha256, SHA256_DIGEST_LENGTH);

  unsigned char checksum[4];
  checksum[0] = eripemd160_sha256_sha256[0];
  checksum[1] = eripemd160_sha256_sha256[1];
  checksum[2] = eripemd160_sha256_sha256[2];
  checksum[3] = eripemd160_sha256_sha256[3];

  memcpy(addressBuf, eripemd160, RIPEMD160_DIGEST_LENGTH+1);
  memcpy(addressBuf+RIPEMD160_DIGEST_LENGTH+1, checksum, 4);
  return addressBuf;
}



//static const char *expectedPubkeyStr = "f0640a42e8a5f63d7ad19c3d3385b958b5e8f99bbd05d355071f724ae9789299713c9dd4d1fa29a7ac6f52eb55c1d44c17f226de1ba38e3e1246c3cfce76f2df";
static const unsigned char defaultExpectedPubkey[] = {
  0xf0,0x64,0x0a,0x42, 0xe8,0xa5,0xf6,0x3d,
  0x7a,0xd1,0x9c,0x3d, 0x33,0x85,0xb9,0x58,
  0xb5,0xe8,0xf9,0x9b, 0xbd,0x05,0xd3,0x55,
  0x07,0x1f,0x72,0x4a, 0xe9,0x78,0x92,0x99,
  0x71,0x3c,0x9d,0xd4, 0xd1,0xfa,0x29,0xa7,
  0xac,0x6f,0x52,0xeb, 0x55,0xc1,0xd4,0x4c,
  0x17,0xf2,0x26,0xde, 0x1b,0xa3,0x8e,0x3e,
  0x12,0x46,0xc3,0xcf, 0xce,0x76,0xf2,0xdf
};
static const unsigned char *expectedPubkey = defaultExpectedPubkey;


static void tryCandidate(unsigned char *pprivkey, int bufpos) {
  unsigned char ppubkeyBuf[65];
  const unsigned char *ppubkey = pubFromPriv(ppubkeyBuf, pprivkey);

  if ((ppubkey[0] == expectedPubkey[0]) &&
      (ppubkey[1] == expectedPubkey[1]) &&
      (ppubkey[2] == expectedPubkey[2]) &&
      (ppubkey[3] == expectedPubkey[3]) &&
      (ppubkey[4] == expectedPubkey[4]) &&
      (ppubkey[5] == expectedPubkey[5]) &&
      (ppubkey[6] == expectedPubkey[6]) &&
      (ppubkey[7] == expectedPubkey[7])) {
    num_recovered++;
    char ppubkeyStrBuf[129];
    const char *ppubkeyStr = toHexString(ppubkeyStrBuf, ppubkey, 64);
    
    unsigned char addressBuf[ADDRESS_LENGTH+1];
    const unsigned char *address = addressFromPub(addressBuf, ppubkey, 64);
    
    char addressBase58Buf[50]; // will be something less than 25 characters
    const char *addressBase58 = toBase58String(addressBase58Buf, address, 25);
    
    char hexBuf[32*2+1];
    const char *pprivkeyStr = toHexString(hexBuf, pprivkey, 32);
    printf("CSV,%d,%s,%s,%s\n", bufpos, pprivkeyStr, ppubkeyStr, addressBase58);
  }
}


static void do_scan(void) {
  int flg = 1, cnt = 0;
  while(flg || bufpos < buffill) {
    flg = refill_buf();
    if (bufpos < buffill-32) {
      //printf("INFO: trying; bufpos: %d, buffill: %d\n", bufpos, buffill);
      tryCandidate(&buf[bufpos], cnt);
    }
    bufpos++;
    if (++cnt % 5000 == 0) printf("INFO: byte cnt: %d\n", cnt);
    refill_buf();
  }
}

static void usage(const char **argv) {
  printf("%s v1.0\n", argv[0]);
  printf("(C) 2017 Joe Cicchiello. All rights reserved.\n");
  printf("loosely derived from the work of Aidan Thornton.\n");
  printf("See LICENSE.txt for full copyright and licensing information\n");
  printf("\n");
  printf("Usage: %s <file> {<pubkey>}\n", argv[0]);
  fflush(stdout);
}

int main(int argc, const char** argv) {
	printf("CSV,position,privkey,pubkey,address\n");
	
	num_recovered = num_pend_pub = num_pend_pub_comp = num_pend_priv = num_dups = 0;
	if (argc < 2) {
	  usage(argv);
	  exit(1);
	}

	bufpos = 0; buffill = 0;
	f = open(argv[1], O_RDONLY);
	if(f < 0) {
		perror("Opening input");
		exit(1);
	}
	ftotallen = lseek(f, 0, SEEK_END);
	fpos = fnextcp = 0;
	lseek(f, 0, SEEK_SET);
	//printf("DEBUG: f = %i\n", f);

	unsigned char targetPubkeyBuf[64];
	if (argc > 2) {
	  if (strlen(argv[2]) != 128) {
	    printf("ERROR:main: supplied pubkey must be 128 characters (64 bytes)\n");
	    usage(argv);
	    exit(1);
	  }
	  expectedPubkey = fromHexString(targetPubkeyBuf, argv[2], 128);
	}
	
	do_scan();
	
	//printf("INFO:main: Done - %i cases found, num_pend_pub: %i, num_pend_pub_comp: %i, num_pend_priv: %i, num_dups: %i\n",
	//	num_recovered, num_pend_pub, num_pend_pub_comp, num_pend_priv, num_dups);
	printf("INFO:main: Done - %i cases found\n", num_recovered);
	fflush(stdout);
	if(num_recovered <= 0) {
		printf("INFO:main: Sorry, nothing definite found :-(\n");
	} else {
		printf("INFO:main: If this helped, feel free to make a donation to the author at:\n");
		printf("INFO:main:     *** www.paypal.me/JFCEnterprises ***\n");
		printf("INFO:main: Please backup your wallet regularly and securely!\n\n");
	}
	fflush(stdout);
	return 0;
}
