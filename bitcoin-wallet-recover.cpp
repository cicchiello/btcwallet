/*
Copyright (c) 2011 Aidan Thornton.  All rights reserved.

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

#include <db.h>

#include <string>
#include <map>
#include <vector>

#include "eccrypto.h"
#include "oids.h"
#include "integer.h"

struct key_info {
	std::vector<unsigned char> privkey;
	std::vector<unsigned char> pubkey;
	std::vector<unsigned char> pubkey_comp;
	int found_priv:1;
	int found_pub:1;
	int found_pub_comp:1;
	int recovered:1;
	int recovered_comp:1;

	key_info() : found_priv(0), found_pub(0), found_pub_comp(0), 
		     recovered(0), recovered_comp(0) {} 
};

int SHA256_Final(unsigned char *md, SHA256_CTX *c);

#define RIPEMD160_DIGEST_LENGTH 20
#define ADDRESS_LENGTH 25
const unsigned char *ripemd160Hash(unsigned char *buf, const unsigned char *data, int length);

bool b58enc(char *b58, size_t *b58sz, const void *data, size_t binsz);

//"\x01\x03\x6B\x65\x79\x41\x04"

#define STATE_FOUND_PUBKEY 6
#define STATE_FOUND_PUBKEY_COMP 7
#define STATE_FOUND_PUBKEY_2 13
#define STATE_FOUND_PRIVKEY 10
#define STATE_FOUND_PUBKEY_J 19

static const short statemap[][12] = {
	{ 0x00, 15, 0x01, 1, 0x03, 11, -1, 0 }, // 0
	{ 0x00, 15, 0x03, 2, 0x01, 8, -1, 0 }, // 1: 01
	{ 0x00, 15, 0x6b, 3, 0x42, 12, 0x01, 1, 0x03, 11, -1, 0 }, // 2: 01 03
	{ 0x00, 15, 0x65, 4, 0x01, 1, 0x03, 11, -1, 0 }, // 3: 01 03 6b
	{ 0x00, 15, 0x79, 5, 0x01, 1, 0x03, 11, -1, 0 }, // 4: 01 03 6b 65
	{ 0x00, 15, 0x41, 6, 0x21, 7, 0x01, 1, 0x03, 11, -1, 0 }, // 5: 01 03 6b 65 79
	{ 0x00, 15, 0x01, 1, 0x03, 11, -1, 0 }, // 6: 01 03 6b 65 79 41 <pubkey>
	{ 0x00, 15, 0x01, 1, 0x03, 11, -1, 0 }, // 7: 01 03 6b 65 79 21 <comp pubkey>
	{ 0x00, 15, 0x01, 8, 0x03, 2, 0x04, 9, -1, 0}, // 8: 01 01
	{ 0x00, 15, 0x20, 10, 0x01, 1, 0x03, 11, -1, 0}, // 9: 01 01 04
	{ 0x00, 15, 0x01, 1, 0x03, 11, -1, 0 }, // 10: 01 01 04 20 <privkey>
	{ 0x00, 15, 0x42, 12, 0x01, 1, 0x03, 11, -1, 0}, // 11: 03
	{ 0x00, 13, 0x01, 1, 0x03, 11, -1, 0}, // 12: 03 42
	{ 0x00, 16, 0x01, 1, 0x03, 11, -1, 0}, // 13: 03 42 00  <pubkey>
	{ }, // unused
	{ 0x00, 16, 0x01, 1, 0x03, 11, -1, 0 }, // 15: 00
	{ 0x00, 17, 0x01, 1, 0x03, 11, -1, 0 }, // 16: 00 00	
	{ 0x00, 17, 0x01, 1, 0x03, 11, 0x41, 18, -1, 0 }, // 17: 00 00 00 
	{ 0x00, 15, 0x01, 1, 0x03, 11, 0x04, 19, -1, 0 }, // 18: 00 00 00 41
	{ 0x00, 15, 0x01, 1, 0x03, 11, -1, 0 }, // 19: 00 00 00 41 04
};


std::map<std::vector<unsigned char>, key_info* > pubkey_map;
std::map<std::vector<unsigned char>, key_info* > privkey_map;

typedef std::map<std::vector<unsigned char>, key_info* >::iterator keymap_iter;

#define BUF_SEGMENT 65536
#define BUF_LEN (65536*4)
#define BUF_WATERMARK (65536*3)
unsigned char buf[BUF_LEN]; int f; int bufpos, buffill;
unsigned long long fpos, ftotallen, fnextcp;
int num_recovered, num_pend_pub, num_pend_pub_comp, num_pend_priv, num_dups;

DB *dbp;

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

// structure of a private key: 
// "308201130201010420" + private key (32 bytes) + "a081a53081a2020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f300604010004010704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101a14403420004" + public key (64 bytes)

// structure of compressed private key
// "3081D30201010420" + private key (32 bytes) + "a08185308182020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f300604010004010704210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101a124032200" + compressed public key (33 bytes)

static void save_recovered_key(unsigned char* pubkey, unsigned char* privkey, bool compressed)
{
	DBT key, data; int ret;
	unsigned char keybuf[70],  valbuf[300];
	if(dbp == NULL) return;
	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));

	if(compressed) {
		memcpy(keybuf, "\x03key\x21", 5);
		memcpy(keybuf+5, pubkey, 33);
		key.data = keybuf;
		key.size = 33+5;

		memcpy(valbuf,"\xd6",1); // length
		memcpy(valbuf+1, "\x30\x81\xD3\x02\x01\x01\x04\x20", 8);
		memcpy(valbuf+9, privkey, 32);
		memcpy(valbuf+41, "\xa0\x81\x85\x30\x81\x82\x02\x01\x01\x30\x2c\x06\x07\x2a\x86\x48\xce\x3d\x01\x01\x02\x21\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xfc\x2f\x30\x06\x04\x01\x00\x04\x01\x07\x04\x21\x02\x79\xbe\x66\x7e\xf9\xdc\xbb\xac\x55\xa0\x62\x95\xce\x87\x0b\x07\x02\x9b\xfc\xdb\x2d\xce\x28\xd9\x59\xf2\x81\x5b\x16\xf8\x17\x98\x02\x21\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xba\xae\xdc\xe6\xaf\x48\xa0\x3b\xbf\xd2\x5e\x8c\xd0\x36\x41\x41\x02\x01\x01\xa1\x24\x03\x22\x00", 141);
		memcpy(valbuf+182, pubkey, 33);
		data.data = valbuf;
		data.size = 215;
	} else {
		memcpy(keybuf, "\x03key\x41\x04", 6);
		memcpy(keybuf+6, pubkey, 64);
		key.data = keybuf;
		key.size = 64+6;

		memcpy(valbuf,"\xfd\x17\x01",3); // length
		memcpy(valbuf+3, "\x30\x82\x01\x13\x02\x01\x01\x04\x20", 9);
		memcpy(valbuf+12, privkey, 32);
		memcpy(valbuf+44, "\xa0\x81\xa5\x30\x81\xa2\x02\x01\x01\x30\x2c\x06\x07\x2a\x86\x48\xce\x3d\x01\x01\x02\x21\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xfc\x2f\x30\x06\x04\x01\x00\x04\x01\x07\x04\x41\x04\x79\xbe\x66\x7e\xf9\xdc\xbb\xac\x55\xa0\x62\x95\xce\x87\x0b\x07\x02\x9b\xfc\xdb\x2d\xce\x28\xd9\x59\xf2\x81\x5b\x16\xf8\x17\x98\x48\x3a\xda\x77\x26\xa3\xc4\x65\x5d\xa4\xfb\xfc\x0e\x11\x08\xa8\xfd\x17\xb4\x48\xa6\x85\x54\x19\x9c\x47\xd0\x8f\xfb\x10\xd4\xb8\x02\x21\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xba\xae\xdc\xe6\xaf\x48\xa0\x3b\xbf\xd2\x5e\x8c\xd0\x36\x41\x41\x02\x01\x01\xa1\x44\x03\x42\x00\x04",174);
		memcpy(valbuf+218, pubkey, 64);
		data.data = valbuf;
		data.size = 279+3;
	}

	ret = dbp->put(dbp, NULL, &key, &data, DB_NOOVERWRITE);
	if(ret == DB_KEYEXIST) {
		printf("INFO:save_recovered_key: Skipping DB write, key already exists\n");
		fflush(stdout);
	} else if(ret != 0) {
		fprintf(stderr, "Error:save_recovered_key: DB write failed!\n");
		dbp->close(dbp, 0);
		exit(1);
	}
}

#ifdef USE_PYTHON
static const char *pubFromPrivPython(char *pubkeyBuf, int pubkeyBuflen, const char *privkeyStr) {
  if (pubkeyBuflen < 129) {
    printf("ERROR:pubFromPrivPython: pubkeyBuflen must be at least 129!\n");
    return 0;
  }
  
  int entry = 1;
  char line[200];
  char cmd[200];
  sprintf(cmd, "./pub-from-priv.py %s", privkeyStr);
  FILE* output = popen(cmd, "r");
  while ( fgets(line, 199, output) )
  {
    if (strlen(line) == 129) {
      memcpy(pubkeyBuf, line, 128);
      pubkeyBuf[128] = 0;
      return pubkeyBuf;
    } else {
      printf("line %5d; len %lu; %s ", entry++, strlen(line), line);
    }
  }
  printf("ERROR:pubFromPrivPython: Didn't get expected response from pub-from-priv.py\n");
  return 0;
}
#endif


static const char *pubFromPriv(char *pubkeyBuf, int pubkeyBuflen, const unsigned char *privkey) {
  if (pubkeyBuflen < 129) {
    printf("ERROR:pubFromPriv: pubkeyBuflen must be at least 129!\n");
    return 0;
  }
  
  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::PrivateKey privateKey;
  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::PublicKey publicKey;
  CryptoPP::Integer pkey_i(privkey, 32);
  privateKey.Initialize( CryptoPP::ASN1::secp256k1(), pkey_i );
  privateKey.MakePublicKey(publicKey);
  
  const CryptoPP::ECP::Point& q = publicKey.GetPublicElement();
  std::vector<unsigned char> gen_pubkey(64);
  q.x.Encode(&gen_pubkey[0], 32);
  q.y.Encode(&gen_pubkey[32], 32);
  
  const char *pubkeyStr = toHexString(pubkeyBuf, &gen_pubkey[0], 64);
  return pubkeyStr;
}


#ifdef REFERENCE
// https://stackoverflow.com/questions/2262386/generate-sha256-with-openssl-and-c
int calc_sha256 (char* path, char output[65])
{
    FILE* file = fopen(path, "rb");
    if(!file) return -1;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    const int bufSize = 32768;
    char* buffer = (char*) malloc(bufSize);
    int bytesRead = 0;
    if(!buffer) return -1;
    while((bytesRead = fread(buffer, 1, bufSize, file)))
    {
        SHA256_Update(&sha256, buffer, bytesRead);
    }
    SHA256_Final(hash, &sha256);

    sha256_hash_string(hash, output);
    fclose(file);
    free(buffer);
    return 0;
}
#endif


static const unsigned char *SHA256Hash(unsigned char *buf, const unsigned char *pubkey, int len) {
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
//  unsigned char prefix[] = {0x04};
//  SHA256_Update(&sha256, prefix, 1);
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


static void dumpPotentialPrivkey(unsigned char* pprivkey) {
  char hexBuf[32*2+1], ppubkeyStrBuf[129];
  const char *pprivkeyStr = toHexString(hexBuf, pprivkey, 32);
  const char *ppubkeyStr = pubFromPriv(ppubkeyStrBuf, 129, pprivkey);
  
#ifdef USE_PYTHON  
  char ppubkey3StrBuf[129];
  const char *ppubkey3Str = pubFromPrivPython(ppubkeyStrBuf, 129, pprivkeyStr);
  if ((strlen(ppubkeyStr) != strlen(ppubkey3Str)) || (strcmp(ppubkey3Str, ppubkeyStr) != 0)) {
    printf("ERROR:dumpPotentialPrivkey: the 2 pubkey generation approaches returned different pubkeys!?!?\n");
    printf("ppubkey3Str : %s\n", ppubkey3Str);
    printf("ppubkeyStr: %s\n", ppubkeyStr);
    exit(-1);
  }
#endif
  
  unsigned char ppubkeyBuf[65];
  const unsigned char *ppubkey = fromHexString(ppubkeyBuf, ppubkeyStr, 128);
  
  unsigned char addressBuf[ADDRESS_LENGTH+1];
  const unsigned char *address = addressFromPub(addressBuf, ppubkey, 64);

  char addressBase58Buf[50]; // will be something less than 25 characters
  const char *addressBase58 = toBase58String(addressBase58Buf, address, 25);
  
  printf("RESULT:dumpPotentialPrivkey: privkey,pubkey,address = %s,%s,%s\n",pprivkeyStr, ppubkeyStr, addressBase58);
}

static void dumpPotentialPubkey(const unsigned char* ppubkey) {
  char ppubkeyStrBuf[64+1];
  const char *ppubkeyStr = toHexString(ppubkeyStrBuf, ppubkey, 64);
  
  unsigned char addressBuf[ADDRESS_LENGTH+1];
  const unsigned char *address = addressFromPub(addressBuf, ppubkey, 64);

  char addressBase58Buf[50]; // will be something less than 25 characters
  const char *addressBase58 = toBase58String(addressBase58Buf, address, 25);
  
  printf("RESULT:dumpPotentialPubkey: privkey,pubkey,address = UNKNOWN,%s,%s\n", ppubkeyStr, addressBase58);
}


// really dirty hack to force a rescan at next startup
static void invalidate_best_block() {
	DBT key, data; int ret;
	if(dbp == NULL) return;
	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));
	
	key.data = (void*)("\x09" "bestblock");
	key.size = 10;
	data.data = (void*)"\x00\x00\x00\x00\x00";
	data.size = 5;
	ret = dbp->put(dbp, NULL, &key, &data, 0);
	if(ret != 0) {
		fprintf(stderr, "Error:invalidate_best_block: DB write failed!\n");
		dbp->close(dbp, 0);
		exit(1);
	}
}

static void try_recover_key(key_info *kinfo) {
	if(kinfo->found_pub && kinfo->found_priv && !kinfo->recovered) {
		printf("INFO:try_recover_key: pubkey = "); dump_hex(&kinfo->pubkey[0], 64);
		dumpPotentialPubkey(&kinfo->pubkey[0]);
		printf("INFO:try_recover_key: privkey = "); dump_hex(&kinfo->privkey[0], 32);
		dumpPotentialPrivkey(&kinfo->privkey[0]);
		save_recovered_key(&kinfo->pubkey[0], &kinfo->privkey[0], false);
		kinfo->recovered = 1;
		num_recovered++; num_pend_pub--; 
		if(!kinfo->recovered_comp) {
		    num_pend_priv--;
		} else {
//		    printf("TRACE:try_recover_key(1): num_pend_priv key: "); dump_hex(&kinfo->privkey[0], 32);
		}
	} else if(kinfo->found_pub_comp && kinfo->found_priv && !kinfo->recovered_comp) {
		printf("INFO:try_recover_key: pubkey_comp = "); dump_hex(&kinfo->pubkey_comp[0], 33);
		printf("INFO:try_recover_key: privkey = "); dump_hex(&kinfo->privkey[0], 32);
		dumpPotentialPrivkey(&kinfo->privkey[0]);
		save_recovered_key(&kinfo->pubkey_comp[0], &kinfo->privkey[0], true);
		kinfo->recovered_comp = 1;
		num_recovered++; num_pend_pub_comp--;
		if(!kinfo->recovered) {
		    num_pend_priv--;
		} else {
		    printf("TRACE:try_recover_key(2): num_pend_priv key: "); dump_hex(&kinfo->privkey[0], 32);
		}
	} else {
//	  printf("TRACE:try_recover_key(3): num_pend_priv key: "); dump_hex(&kinfo->privkey[0], 32);
	}
	show_progress();
}

static void do_recover_privkey(int keypos) {
	std::vector<unsigned char> privkey(32);
	std::vector<unsigned char> gen_pubkey(64);
	if(buffill - keypos < 32) {
		fprintf(stderr, "Error:do_recovery_privkey: Not enough data in buffer to recover key!\n");
		return;
	}
	memcpy(&privkey[0], buf+keypos, 32);
	dumpPotentialPrivkey(buf+keypos);

	keymap_iter iter = privkey_map.find(privkey);
	if(iter != privkey_map.end()) {
		printf("INFO:do_recover_privkey: Duplicate potential private key, skipping\n");
		fflush(stdout);
		num_dups++;
		show_progress();
		return;
	} else {
		CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::PrivateKey privateKey;		
		CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::PublicKey publicKey;
		CryptoPP::Integer pkey_i(&privkey[0], 32);
		privateKey.Initialize( CryptoPP::ASN1::secp256k1(), pkey_i );
		privateKey.MakePublicKey(publicKey);

		const CryptoPP::ECP::Point& q = publicKey.GetPublicElement();
		q.x.Encode(&gen_pubkey[0], 32); q.y.Encode(&gen_pubkey[32], 32);
		dumpPotentialPubkey(&gen_pubkey[0]);

		key_info* kinfo;
		iter = pubkey_map.find(gen_pubkey);
		if(iter != pubkey_map.end()) {
			kinfo = iter->second;
			//printf("TRACE:do_recover_privkey: Found potential pubkey: "); dump_hex(&gen_pubkey[0], 64);
		} else {
			kinfo = new key_info();
			kinfo->pubkey = gen_pubkey;
			kinfo->found_pub = 0;
			pubkey_map[gen_pubkey] = kinfo;
			//printf("TRACE:do_recover_privkey: derived potential pubkey: "); dump_hex(&gen_pubkey[0], 64);
		}

		kinfo->found_priv = 1; 
		kinfo->privkey = privkey;
		privkey_map[privkey] = kinfo;
		num_pend_priv++;
		//printf("TRACE:do_recover_privkey: Found potential privkey: "); dump_hex(&privkey[0], 32);
		//dumpPotentialPrivkey(&privkey[0]);
		try_recover_key(kinfo);
	}
}

static void do_recover_pubkey_uncomp(int keypos) {
	std::vector<unsigned char> pubkey(64);
	if(buffill - keypos < 64) {
		fprintf(stderr, "Error:do_recover_pubkey_uncomp: Not enough data in buffer to recover key!\n");
		return;
	}
	memcpy(&pubkey[0], buf+keypos, 64);
	dumpPotentialPubkey(buf+keypos);

	key_info* kinfo;
	keymap_iter iter = pubkey_map.find(pubkey);
	if(iter != pubkey_map.end()) {
		kinfo = iter->second;
		if(kinfo->found_pub) {
		        //printf("INFO:do_recover_pubkey_uncomp: Duplicate potential public key, skipping; dup pubkey = "); dump_hex(buf+keypos, 64);
		  
			num_dups++;
			show_progress();
			return;
		}
	} else {
		kinfo = new key_info();
		kinfo->pubkey = pubkey;
		pubkey_map[pubkey] = kinfo;
	}

	kinfo->found_pub = 1; 
	kinfo->pubkey = pubkey;
	num_pend_pub++;

	printf("TRACE:do_recover_pubkey_uncomp: Found potential pubkey: "); dump_hex(buf+keypos, 64);
	try_recover_key(kinfo);
}

static void do_recover_pubkey_comp(int keypos) {
	std::vector<unsigned char> pubkey_comp(33);
	std::vector<unsigned char> gen_pubkey(64);
	if(buffill - keypos < 33) {
		fprintf(stderr, "Error:do_recover_pubkey_comp: Not enough data in buffer to recover key!\n");
		return;
	}
	memcpy(&pubkey_comp[0], buf+keypos, 33);

	CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::PublicKey publicKey;
 	publicKey.AccessGroupParameters().Initialize( CryptoPP::ASN1::secp256k1() );
	CryptoPP::ECP::Point q;
	try {
		publicKey.GetGroupParameters().GetCurve().DecodePoint(q,&pubkey_comp[0],33);
	} catch(CryptoPP::Exception& e) {
		printf("Error:do_recover_pubkey_comp: CryptoPP exception decompressing pubkey: %s\n", e.what());
		fflush(stdout);
		return;
	}
	publicKey.SetPublicElement(q);
	q.x.Encode(&gen_pubkey[0], 32); q.y.Encode(&gen_pubkey[32], 32);
	dumpPotentialPubkey(&gen_pubkey[0]);
	
	key_info* kinfo;
	keymap_iter iter = pubkey_map.find(gen_pubkey);
	if(iter != pubkey_map.end()) {
		kinfo = iter->second;
		if(kinfo->found_pub_comp) {
		        //printf("INFO:do_recover_pubkey_comp: Duplicate potential compressed public key, skipping; uncompressed dup pubkey = "); dump_hex(&gen_pubkey[0], 32);
			num_dups++;
			show_progress();
			return;
		}
	} else {
		kinfo = new key_info();
		kinfo->pubkey = gen_pubkey;
		pubkey_map[gen_pubkey] = kinfo;
	}

	kinfo->found_pub_comp = 1; 
	kinfo->pubkey = gen_pubkey;
	kinfo->pubkey_comp = pubkey_comp;
	num_pend_pub_comp++;

//	printf("TRACE:do_recover_pubkey_comp: Found potential compressed pubkey: "); dump_hex(&pubkey_comp[0], 33);
	try_recover_key(kinfo);
}


static void do_recover_pubkey() {
	if(buffill - bufpos < 1)
		return;

	if(buf[bufpos] == 0x04) {
		do_recover_pubkey_uncomp(bufpos+1);
	} else if(buf[bufpos] == 0x02 || buf[bufpos] == 0x03) {
		do_recover_pubkey_comp(bufpos);
	}
}

// nasty hack to try and recover BitcoinJ public+private keys
// probably quite unreliable
static void do_recover_pubkey_j() {
	std::vector<unsigned char> pubkey(64);
	if(buffill - bufpos < 64 || bufpos < 64) {
		fprintf(stderr, "Error:do_recovery_pubkey_j: Not enough data in buffer to recover potential BitcoinJ key!\n");
		return;
	}

	int bufpos_priv = -1;
	for(int i = bufpos-64; i < bufpos-37; i++) {
		if(memcmp(buf+i, "\x00\x00\x00\x20", 4) == 0) {
			bufpos_priv = i+4; break;
		}
	}
	if(bufpos_priv < 0) 
		return;

	do_recover_pubkey_uncomp(bufpos);
	do_recover_privkey(bufpos_priv);
}

static void do_scan(void) {
	int flg = 1; 
	int stateid = 0;
	while(flg || bufpos < buffill) {
		const short *next_tbl = statemap[stateid];
		flg = refill_buf();
		for(;;) {
			if(next_tbl[0] < 0 || next_tbl[0] == buf[bufpos]) {
				stateid = next_tbl[1]; break;
			}
			next_tbl += 2;
		}
		bufpos++;
		if(stateid == STATE_FOUND_PUBKEY) {
			printf("TRACE:do_scan: Found potential PUBKEY key!\n");
			fflush(stdout);
			refill_buf();
			do_recover_pubkey();
		} else if(stateid == STATE_FOUND_PUBKEY_2) {
			printf("TRACE:do_scan: Found potential PUBKEY_2 key!\n");
			fflush(stdout);
			refill_buf();
			do_recover_pubkey();
		} else if (stateid == STATE_FOUND_PUBKEY_COMP) {
			printf("TRACE:do_scan: Found potential PUBKEY_COMP key!\n");
			fflush(stdout);
			refill_buf();
			do_recover_pubkey();
		} else if(stateid == STATE_FOUND_PUBKEY_J ) {
			printf("TRACE:do_scan: Found potential PUBKEY_J key!\n");
			fflush(stdout);
			refill_buf();
			do_recover_pubkey_j();			
		} else if(stateid == STATE_FOUND_PRIVKEY) {
			printf("TRACE:do_scan: Found potential PRIVKEY key!\n");
			fflush(stdout);
			refill_buf();
			do_recover_privkey(bufpos);
		}
	}
}


static void tests() {
  // using a known value to confirm working
  // from: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
  const char *privkeyStr = "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725";
  const char *expectedPubkeyStr = "50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6";
  const char *expectedSHA256Str =                   "600ffe422b4e00731a59557a5cca46cc183944191006324a447bdb2d98d4b408";
  const char *expectedRipemd160Str  =   "010966776006953d5567439e5e39f86a0d273bee";
  const char *expectedERipemd160Str = "00010966776006953d5567439e5e39f86a0d273bee";
  const char *expectedERipemd160_sha256_Str        = "445c7a8007a93d8733188288bb320a8fe2debd2ae1b47f0f50bc10bae845c094";
  const char *expectedERipemd160_sha256_sha256_Str = "d61967f63c7dd183914a4ae452c9f6ad5d462ce3d277798075b107615c1a8a30";
  const char *expectedChecksumStr = "d61967f6";
  const char *expectedAddressStr = "00010966776006953d5567439e5e39f86a0d273beed61967f6";
  const char *expectedBase58Str = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM";
  
  const unsigned char privkey[] = {
    0x18,0xE1,0x4A,0x7B, 0x6A,0x30,0x7F,0x42,
    0x6A,0x94,0xF8,0x11, 0x47,0x01,0xE7,0xC8,
    0xE7,0x74,0xE7,0xF9, 0xA4,0x7E,0x2C,0x20,
    0x35,0xDB,0x29,0xA2, 0x06,0x32,0x17,0x25
  };
  const unsigned char pubkey[] = {
    0x50,0x86,0x3a,0xd6, 0x4a,0x87,0xae,0x8a,
    0x2f,0xe8,0x3c,0x1a, 0xf1,0xa8,0x40,0x3c,
    0xb5,0x3f,0x53,0xe4, 0x86,0xd8,0x51,0x1d,
    0xad,0x8a,0x04,0x88, 0x7e,0x5b,0x23,0x52,
    0x2c,0xd4,0x70,0x24, 0x34,0x53,0xa2,0x99,
    0xfa,0x9e,0x77,0x23, 0x77,0x16,0x10,0x3a,
    0xbc,0x11,0xa1,0xdf, 0x38,0x85,0x5e,0xd6,
    0xf2,0xee,0x18,0x7e, 0x9c,0x58,0x2b,0xa6
  };
  const unsigned char ripemd160[] = {
    0x01,0x09,0x66,0x77, 0x60,0x06,0x95,0x3D,
    0x55,0x67,0x43,0x9E, 0x5E,0x39,0xF8,0x6A,
    0x0D,0x27,0x3B,0xEE
  };
  const unsigned char eripemd160[] = {
    0x00,0x01,0x09,0x66, 0x77,0x60,0x06,0x95,
    0x3D,0x55,0x67,0x43, 0x9E,0x5E,0x39,0xF8,
    0x6A,0x0D,0x27,0x3B, 0xEE
  };
  const unsigned char eripemd160_sha256[] = {
    0x44,0x5C,0x7A,0x80, 0x07,0xA9,0x3D,0x87,
    0x33,0x18,0x82,0x88, 0xBB,0x32,0x0A,0x8F,
    0xE2,0xDE,0xBD,0x2A, 0xE1,0xB4,0x7F,0x0F,
    0x50,0xBC,0x10,0xBA, 0xE8,0x45,0xC0,0x94
  };
  const unsigned char eripemd160_sha256_sha256[] = {
    0xD6,0x19,0x67,0xF6, 0x3C,0x7D,0xD1,0x83,
    0x91,0x4A,0x4A,0xE4, 0x52,0xC9,0xF6,0xAD,
    0x5D,0x46,0x2C,0xE3, 0xD2,0x77,0x79,0x80,
    0x75,0xB1,0x07,0x61, 0x5C,0x1A,0x8A,0x30
  };
  const unsigned char address[] = {
    0x00,0x01,0x09,0x66, 0x77,0x60,0x06,0x95,
    0x3D,0x55,0x67,0x43, 0x9E,0x5E,0x39,0xF8,
    0x6A,0x0D,0x27,0x3B, 0xEE,0xD6,0x19,0x67,
    0xF6
  };
  const unsigned char checksum[] = {
    0xD6,0x19,0x67,0xF6
  };
  
  printf("INFO:tests: SHA256_DIGEST_LENGTH = %i\n", SHA256_DIGEST_LENGTH);
  
  char hexTestBuf[65];
  const char *hexTestStr = toHexString(hexTestBuf, privkey, 32);
  if ((strlen(hexTestStr) != 64) || (strcmp(hexTestStr, privkeyStr) != 0)) {
    printf("hexTestStr: %s\n", hexTestStr);
    printf("privkeyStr: %s\n", privkeyStr);
    printf("ERROR:tests: test of toHexString returned unexpected result!\n");
    printf("\n");
    exit(-1);
  }

#ifdef USE_PYTHON  
  char pubkeyStrBuf[129];
  const char *pubkeyStr = pubFromPrivPython(pubkeyStrBuf, 129, privkeyStr);
  if (pubkeyStr == 0) {
    printf("ERROR:tests: test of pub-from-priv.py failed!\n");
    printf("ERROR:tests: Please make sure the python program called pub-from-priv.py is in pwd\n");
    printf("ERROR:tests: Please make sure that pub-from-priv.py is executable (chmod a+x pub-from-priv.py)\n");
    printf("\n");
    exit(-1);
  }
  
  if ((strlen(pubkeyStr) != strlen(expectedPubkeyStr)) || (strcmp(pubkeyStr, expectedPubkeyStr) != 0)) {
    printf("pubkeyStr  : %s\n", pubkeyStr);
    printf("expected: %s\n", expectedPubkeyStr);
    printf("ERROR:tests: test of pub-from-priv.py returned unexpected result!\n");
    printf("ERROR:tests: Please make sure the python program called pub-from-priv.py is in pwd\n");
    printf("ERROR:tests: Please make sure that pub-from-priv.py is executable (chmod a+x pub-from-priv.py)\n");
    printf("\n");
    exit(-1);
  }

  unsigned char pubkeyHex[65];
  pubkeyHex[64] = 0x7f;
  const unsigned char *pubkeyTest = fromHexString(pubkeyHex, pubkeyStr, 128);
  if (pubkeyHex[64] != 0x7f) {
    printf("ERROR:tests: fromHexString overwrote the supplied buffer\n");
    exit(-1);
  }
  if (memcmp(pubkeyTest, pubkey, 64) != 0) {
    printf("ERROR:tests: fromHexString returned unexpected data\n");
    exit(-1);
  }
#endif
  
  char cryptoStrBuf[130];
  cryptoStrBuf[129] = 0x7f;
  const char *cryptoStr = pubFromPriv(cryptoStrBuf, 129, privkey);
  if (cryptoStrBuf[129] != 0x7f) {
    printf("ERROR:tests: pubFromPriv overwrote the supplied buffer\n");
    exit(-1);
  }
  if ((strlen(cryptoStr) != strlen(expectedPubkeyStr)) || (strcmp(cryptoStr, expectedPubkeyStr) != 0)) {
    printf("pubkeyStr  : %s\n", expectedPubkeyStr);
    printf("cryptoStr: %s\n", cryptoStr);
    printf("ERROR:tests: test of crypto-based pubkey from privkey returned unexpected result!\n");
    printf("\n");
    exit(-1);
  }

  unsigned char epubkey[65];
  epubkey[0] = 0x04;
  memcpy(epubkey+1, pubkey, 64);
  
  unsigned char sha256Buf[SHA256_DIGEST_LENGTH+2];
  sha256Buf[SHA256_DIGEST_LENGTH+1] = 0xcc;
  const unsigned char *sha256 = SHA256Hash(sha256Buf, epubkey, 65);
  if (sha256Buf[SHA256_DIGEST_LENGTH+1] != 0xcc) {
    printf("ERROR:tests: SHA256Hash overwrote the supplied buffer\n");
    exit(-1);
  }
  char sha256StrBuf[SHA256_DIGEST_LENGTH*2+2];
  sha256StrBuf[SHA256_DIGEST_LENGTH*2+1] = 0x7f;
  const char *sha256Str = toHexString(sha256StrBuf, sha256, SHA256_DIGEST_LENGTH);
  if (sha256StrBuf[SHA256_DIGEST_LENGTH*2+1] != 0x7f) {
    printf("ERROR:tests: toHexString of sha256 overwrote the supplied buffer\n");
    exit(-1);
  }
  if (strcmp(sha256Str, expectedSHA256Str) != 0) {
    printf("sha256Str        : %s\n", sha256Str);
    printf("expectedSHA256Str: %s\n", expectedSHA256Str);
    printf("ERROR:tests: test of SHA256 generation from pubkey returned unexpected result!\n");
    printf("\n");
    exit(-1);
  }

  {
    unsigned char ripemd160Buf[RIPEMD160_DIGEST_LENGTH+2];
    ripemd160Buf[RIPEMD160_DIGEST_LENGTH+1] = 0xcc;
    const unsigned char *ripemd160Test = ripemd160Hash(ripemd160Buf, sha256, SHA256_DIGEST_LENGTH);
    if (ripemd160Buf[RIPEMD160_DIGEST_LENGTH+1] != 0xcc) {
      printf("ERROR:tests: ripemd160Hash sha256 overwrote the supplied buffer\n");
      exit(-1);
    }
    if (memcmp(ripemd160, ripemd160Test, RIPEMD160_DIGEST_LENGTH) != 0) {
      printf("ERROR:tests: ripemd160Hash returned unexpected data\n");
      exit(-1);
    }
    char ripemd160StrBuf[RIPEMD160_DIGEST_LENGTH*2+2];
    ripemd160StrBuf[RIPEMD160_DIGEST_LENGTH*2+1] = 0x7f;
    const char *ripemd160Str = toHexString(ripemd160StrBuf, ripemd160Test, RIPEMD160_DIGEST_LENGTH);
    if (ripemd160StrBuf[RIPEMD160_DIGEST_LENGTH*2+1] != 0x7f) {
      printf("ERROR:tests: toHexString of ripemd160Test overwrote the supplied buffer\n");
      exit(-1);
    }
    if (strcmp(ripemd160Str, expectedRipemd160Str) != 0) {
      printf("ripemd160Str        : %s\n", ripemd160Str);
      printf("expectedRipemd160Str: %s\n", expectedRipemd160Str);
      printf("ERROR:tests: test of ripemd160 generation from sha256 returned unexpected result!\n");
      printf("\n");
      exit(-1);
    }
  }

  {
    unsigned char eripemd160Buf[RIPEMD160_DIGEST_LENGTH+3];
    unsigned char *ripemd160Buf = eripemd160Buf + 1;
    eripemd160Buf[0] = 0;
    ripemd160Buf[RIPEMD160_DIGEST_LENGTH+1] = 0xcc;
    ripemd160Hash(ripemd160Buf, sha256, SHA256_DIGEST_LENGTH);
    unsigned char *eripemd160Test = eripemd160Buf;
    if (eripemd160Buf[0] != 0) {
      printf("ERROR:tests: ripemd160Hash sha256 underwrote the supplied buffer\n");
      exit(-1);
    }
    if (ripemd160Buf[RIPEMD160_DIGEST_LENGTH+1] != 0xcc) {
      printf("ERROR:tests: ripemd160Hash sha256 overwrote the supplied buffer\n");
      exit(-1);
    }
    if (memcmp(eripemd160, eripemd160Test, RIPEMD160_DIGEST_LENGTH+1) != 0) {
      printf("ERROR:tests: ripemd160Hash returned unexpected data for the network prepend case\n");
      exit(-1);
    }
    char eripemd160StrBuf[(RIPEMD160_DIGEST_LENGTH+1)*2+2];
    eripemd160StrBuf[(RIPEMD160_DIGEST_LENGTH+1)*2+1] = 0x7f;
    const char *eripemd160Str = toHexString(eripemd160StrBuf, eripemd160Test, RIPEMD160_DIGEST_LENGTH+1);
    if (eripemd160StrBuf[(RIPEMD160_DIGEST_LENGTH+1)*2+1] != 0x7f) {
      printf("ERROR:tests: toHexString of eripemd160Test overwrote the supplied buffer\n");
      exit(-1);
    }
    if (strcmp(eripemd160Str, expectedERipemd160Str) != 0) {
      printf("eripemd160Str        : %s\n", eripemd160Str);
      printf("expectedERipemd160Str: %s\n", expectedERipemd160Str);
      printf("ERROR:tests: test of ripemd160 generation from sha256 for network prepend case returned unexpected result!\n");
      printf("\n");
      exit(-1);
    }
    
    unsigned char eripemd160_sha256Buf[SHA256_DIGEST_LENGTH+2];
    eripemd160_sha256Buf[SHA256_DIGEST_LENGTH+1] = 0xcc;
    const unsigned char *eripemd160_sha256Test = SHA256Hash(eripemd160_sha256Buf, eripemd160Test, RIPEMD160_DIGEST_LENGTH+1);
    if (eripemd160_sha256Buf[SHA256_DIGEST_LENGTH+1] != 0xcc) {
      printf("ERROR:tests: SHA256Hash overwrote the supplied buffer for eripemd160_sha256\n");
      exit(-1);
    }
    if (memcmp(eripemd160_sha256Test, eripemd160_sha256, SHA256_DIGEST_LENGTH) != 0) {
      printf("ERROR:tests: SHA256Hash returned unexpected data for eripemd160\n");
      exit(-1);
    }
    char eripemd160_sha256_StrBuf[SHA256_DIGEST_LENGTH*2+2];
    eripemd160_sha256_StrBuf[SHA256_DIGEST_LENGTH*2+1] = 0x7f;
    const char *eripemd160_sha256_Str = toHexString(eripemd160_sha256_StrBuf, eripemd160_sha256Test, SHA256_DIGEST_LENGTH);
    if (strcmp(eripemd160_sha256_Str, expectedERipemd160_sha256_Str) != 0) {
      printf("eripemd160_sha256_Str        : %s\n", eripemd160_sha256_Str);
      printf("expectedERipemd160_sha256_Str: %s\n", expectedERipemd160_sha256_Str);
      printf("ERROR:tests: test of sha256 generation from eripemd160 returned unexpected result!\n");
      printf("\n");
      exit(-1);
    }
    
    unsigned char eripemd160_sha256_sha256Buf[SHA256_DIGEST_LENGTH+2];
    eripemd160_sha256_sha256Buf[SHA256_DIGEST_LENGTH+1] = 0xcc;
    const unsigned char *eripemd160_sha256_sha256Test = SHA256Hash(eripemd160_sha256_sha256Buf, eripemd160_sha256Test, SHA256_DIGEST_LENGTH);
    if (eripemd160_sha256_sha256Buf[SHA256_DIGEST_LENGTH+1] != 0xcc) {
      printf("ERROR:tests: SHA256Hash overwrote the supplied buffer for eripemd160_sha256_sha256\n");
      exit(-1);
    }
    if (memcmp(eripemd160_sha256_sha256Test, eripemd160_sha256_sha256, SHA256_DIGEST_LENGTH) != 0) {
      printf("ERROR:tests: SHA256Hash returned unexpected data for ripemd160_sha256\n");
      exit(-1);
    }
    char eripemd160_sha256_sha256_StrBuf[SHA256_DIGEST_LENGTH*2+2];
    eripemd160_sha256_sha256_StrBuf[SHA256_DIGEST_LENGTH*2+1] = 0x7f;
    const char *eripemd160_sha256_sha256_Str = toHexString(eripemd160_sha256_sha256_StrBuf, eripemd160_sha256_sha256Test, SHA256_DIGEST_LENGTH);
    if (strcmp(eripemd160_sha256_sha256_Str, expectedERipemd160_sha256_sha256_Str) != 0) {
      printf("eripemd160_sha256_sha256_Str        : %s\n", eripemd160_sha256_sha256_Str);
      printf("expectedERipemd160_sha256_sha256_Str: %s\n", expectedERipemd160_sha256_sha256_Str);
      printf("ERROR:tests: test of sha256 generation from sha256 of ripemd160 returned unexpected result!\n");
      printf("\n");
      exit(-1);
    }

    unsigned char checksumTest[4];
    checksumTest[0] = eripemd160_sha256_sha256Test[0];
    checksumTest[1] = eripemd160_sha256_sha256Test[1];
    checksumTest[2] = eripemd160_sha256_sha256Test[2];
    checksumTest[3] = eripemd160_sha256_sha256Test[3];
    if (memcmp(checksum, checksumTest, 4) != 0) {
      printf("ERROR:tests: checksum is wrong\n");
      exit(-1);
    }
    char checksumStrBuf[10];
    const char *checksumStr = toHexString(checksumStrBuf, checksumTest, 4);
    if (strcmp(checksumStr, expectedChecksumStr) != 0) {
      printf("checksumStr: %s\n", checksumStr);
      printf("expectedChecksumStr: %s\n", expectedChecksumStr);
      printf("ERROR:tests: checksum is wrong\n");
      exit(-1);
    }
    
    unsigned char addressTest[ADDRESS_LENGTH+1];
    addressTest[ADDRESS_LENGTH] = 0xcc;
    memcpy(addressTest, eripemd160Test, RIPEMD160_DIGEST_LENGTH+1);
    memcpy(addressTest+RIPEMD160_DIGEST_LENGTH+1, checksum, 4);
    if (addressTest[ADDRESS_LENGTH] != 0xcc) {
      printf("ERROR:tests: assembly of the address overwrote the buffer\n");
      exit(-1);
    }
    if (memcmp(addressTest, address, ADDRESS_LENGTH) != 0) {
      printf("ERROR:tests: address is wrong\n");
      exit(-1);
    }
    char address_StrBuf[ADDRESS_LENGTH*2+2];
    address_StrBuf[ADDRESS_LENGTH*2+1] = 0x7f;
    const char *addressStr = toHexString(address_StrBuf, addressTest, ADDRESS_LENGTH);
    if (strcmp(addressStr, expectedAddressStr) != 0) {
      printf("addressStr        : %s\n", addressStr);
      printf("expectedAddressStr: %s\n", expectedAddressStr);
      printf("ERROR:tests: test of address assembly returned unexpected result!\n");
      printf("\n");
      exit(-1);
    }
  }

  unsigned char addressBuf[ADDRESS_LENGTH+2];
  addressBuf[ADDRESS_LENGTH+1] = 0xcc;
  const unsigned char *addressTest = addressFromPub(addressBuf, pubkey, 64);
  if (addressBuf[ADDRESS_LENGTH+1] != 0xcc) {
    printf("ERROR:tests: generation of the address overwrote the buffer\n");
    exit(-1);
  }
  if (memcmp(addressTest, address, ADDRESS_LENGTH) != 0) {
    printf("ERROR:tests: address is wrong\n");
    exit(-1);
  }
  char address_StrBuf[ADDRESS_LENGTH*2+2];
  address_StrBuf[ADDRESS_LENGTH*2+1] = 0x7f;
  const char *addressStr = toHexString(address_StrBuf, addressTest, ADDRESS_LENGTH);
  if (strcmp(addressStr, expectedAddressStr) != 0) {
    printf("addressStr        : %s\n", addressStr);
    printf("expectedAddressStr: %s\n", expectedAddressStr);
    printf("ERROR:tests: test of address assembly returned unexpected result!\n");
    printf("\n");
    exit(-1);
  }

  char base58StrBuf[50]; // shouldn't need that many bytes, but the exact number isn't known yet
  const char *base58Str = toBase58String(base58StrBuf, addressTest, ADDRESS_LENGTH);
  if (strcmp(base58Str, expectedBase58Str) != 0) {
    printf("base58Str: %s\n", base58Str);
    printf("expectedBase58Str: %s\n", expectedBase58Str);
    printf("ERROR:tests: conversion to base58 returned unexpected result!\n");
    printf("\n");
    exit(-1);
  }
  
}


int main(int argc, char** argv) {
	tests();
	printf("INFO:main: all preliminary tests passed; continuing!\n\n");
	
	u_int32_t flags; int ret;
	num_recovered = num_pend_pub = num_pend_pub_comp = num_pend_priv = num_dups = 0;
	if(argc < 2 || argc > 3) {
		printf("bitcoin-wallet-recover v1.5d\n");
		printf("(C) 2011-2012 Aidan Thornton. All rights reserved.\n");
		printf("(C) 2017 Joe Cicchiello; modified to be much more verbose\n");
		printf("See LICENSE.txt for full copyright and licensing information\n");
		printf("\n");
		printf("Usage: %s <file> [<new wallet>]\n", argv[0]);
		fflush(stdout);
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

	if(argc >= 3) {
		ret = db_create(&dbp, NULL, 0);
		if (ret != 0) {
			fprintf(stderr, "Error:main: couldn't create DB to open output wallet\n");
			exit(1);
		}
		flags = DB_CREATE;
		ret = dbp->open(dbp,
				NULL, // transaction pointer
				argv[2],
				"main", // logical database name
				DB_BTREE,
				flags,
				0); 
		if (ret != 0) {
			fprintf(stderr, "Error:main: couldn't open output wallet\n");
			exit(1);
		}
	} else {
		dbp = NULL;
	}
	
	do_scan();
	if(dbp && num_recovered > 0)
		invalidate_best_block();
	if(dbp)
		dbp->close(dbp, 0);
	//printf("INFO:main: Done - %i keys recovered, num_pend_pub: %i, num_pend_pub_comp: %i, num_pend_priv: %i, num_dups: %i\n",
	//	num_recovered, num_pend_pub, num_pend_pub_comp, num_pend_priv, num_dups);
	printf("INFO:main: Done - %i keys recovered\n", num_recovered);
	fflush(stdout);
	if(num_recovered <= 0) {
		printf("INFO:main: Sorry, nothing definite found :-(\n");
	} else {
		if(dbp) {
			printf("WARN:main: recovered addresses won't be listed under 'Receive coins' in the client\n\n");
		}
		printf("INFO:main: If this helped, feel free to make a donation to the author at:\n");
		printf("INFO:main:     *** 1CxDtwy7SAYHu7RJr5MFFUwtn8VEotTj8P ***\n");
		printf("INFO:main:               -- and -- \n");
		printf("INFO:main:     *** www.paypal.me/JFCEnterprises ***\n");
		printf("INFO:main: Please backup your wallet regularly and securely!\n\n");
		if(dbp) {
			printf("INFO:main: After running the client and confirming your coins are all there, please either:\n");
			printf("INFO:main:  * Send all your coins to a new wallet that's securely backed up in one big transaction, or\n");
			printf("INFO:main:  * Stop the client and take a backup of your wallet before making any transactions\n");
			printf("INFO:main: I'd also recommend using the -upgradewallet option, though it's not required\n\n");
		}
	}
	fflush(stdout);
	return 0;
}
