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

#include <string>
#include <cstring>


#define BUF_SEGMENT 65536
#define BUF_LEN (65536*4)
#define BUF_WATERMARK (65536*3)

static unsigned char buf[BUF_LEN];
static int f;
static int bufpos, buffill;
static unsigned long long fpos, ftotallen, fnextcp;
static int num_recovered = 0;

static int refill_buf(long filepos) {
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
		  printf("TRACE:refill_buf; Read %i bytes; Filepos %ld\n", ret, filepos);
		  fflush(stdout);
		}
		buffill += ret;
		fpos += ret;
		if(fpos > fnextcp) {
			fnextcp = fpos + (ftotallen/1024);
		}
		if (ret == 0)
		  printf("INFO: I thikn it's done\n");
		return ret;
	} else {
		return -1;
	}
}

static const char *toHexString(char *buf, const unsigned char *data, int len) {
  int i;
  for(i = 0; i < len; i++) {
    sprintf(buf+i*2,"%02x", data[i]);
  }
  buf[len*2] = 0;
  return buf;
}





static void usage(const char **argv) {
  printf("\n");
  printf("%s v1.0\n", argv[0]);
  printf("\n");
  printf("Usage: %s [-s[tart-byte] <#b>] [-window <w>] -h[ay] <haystack-file> -n[eedles] <n1> [<n2>...]\n", argv[0]);
  printf("\n");
  printf("Where: -s[tart-byte] <#b>        number of bytes into the file to start (to help restart large searches)\n");
  printf("       -w[indow] <w>             number of bytes to report before and after any occurances (default: 5)\n");
  printf("       -h[ay] <haystack-file>    any file or device to search\n");
  printf("       -n[eedles] <n1> {<n2>...} one or more exact strings to look for.  Hex encoding is supported with \x12 \n");
  printf("\n");
  printf("Examples: \n");
  printf("   > %s -s 1000 -window 10 -hay /dev/usba -needles Joe joe j0e\n", argv[0]);
  printf("   > %s -h some-image-file -n J\\\\x6fe joe j0e\n", argv[0]);
  printf("\n");
  printf("   Both of those commands will search for the same strings.  The first defines both a non-default \n");
  printf("   window and a starting point (rather than starting at byte 0).  Note the need for 2 back slashes as \n");
  printf("   escape character for the hexidecimal character.\n");
  printf("\n");
  printf("This program scans the given file (haystack), looking for given strings (needles). \n");
  printf("When any occurances are found, it will print out a window of hex bytes around the \n");
  printf("needle.\n");
  printf("\n");
  printf("(C) 2017 Joe Cicchiello. All rights reserved.\n");
  printf("See LICENSE.txt for full copyright and licensing information\n");
  printf("\n");
  fflush(stdout);
  exit(-1);
}

static long start_byte = 0;
static int window = 5;
static const char **needles = 0;
static int numNeedles = 0;
static const char *path = 0;


static void do_scan(void) {
  int flg = 1;
  long cnt = 0;
  while (flg && start_byte > 0) {
    flg = refill_buf(cnt);
    start_byte--;
    cnt++;
    //if (++cnt % 5000 == 0) printf("INFO: byte cnt: %ld\n", cnt);
  }

  while(flg || bufpos < buffill) {
    flg = refill_buf(cnt);
    for (int i = 0; i < numNeedles; i++) {
      const char *p = needles[i];
      int j = 0;
      while (*p && (*p == buf[bufpos+j])) {
	p++; j++;
      }
      if (!*p) {
	// found one!
	int l = strlen(needles[i]), k = 0;
	char buf1[2*(l+2*window)+1];
	char buf2[l+2*window+1];
	const char *hexStr = toHexString(buf1, buf+bufpos-window, l+2*window);
	for (; k < l+2*window; k++) {
	  if (isprint(buf[bufpos-window+k]))
	    buf2[k] = buf[bufpos-window+k];
	  else
	    buf2[k] = '.';
	}
	buf2[k] = 0;
	printf("bufpos: %d\n", bufpos);
	printf("CSV, %ld, %s, %s\n", cnt, hexStr, buf2);
	num_recovered++;
      }
    }
    bufpos++;
    cnt++;
    //if (++cnt % 5000 == 0) printf("INFO: byte cnt: %ld\n", cnt);
    flg = refill_buf(cnt);
  }
}


static void processArgs(int argc, const char **argv) {
  if (argc < 2) {
    usage(argv);
  }
  
  int ai = 1;
  while (ai < argc) {
    if (((strcmp(argv[ai], "-start-byte") == 0) || (strcmp(argv[ai], "-s") == 0)) && (ai+1 < argc)) {
      int c = sscanf(argv[ai+1], "%ld", &start_byte);
      if (c != 1) {
	printf("ERROR: invalid value for -s[tart-byte]: %s\n", argv[ai+1]);
	usage(argv);
      }
      ai++;
    } else if (((strcmp(argv[ai], "-window") == 0) || (strcmp(argv[ai], "-w") == 0)) && (ai+1 < argc)) {
      int c = sscanf(argv[ai+1], "%d", &window);
      if (c != 1) {
	printf("ERROR: invalid value for -w[indow]: %s\n", argv[ai+1]);
	usage(argv);
      }
      ai++;
    } else if (((strcmp(argv[ai], "-hay") == 0) || (strcmp(argv[ai], "-h") == 0)) && (ai+1 < argc)) {
      path = argv[ai+1];
      ai++;
    } else if (((strcmp(argv[ai], "-needles") == 0) || (strcmp(argv[ai], "-n") == 0)) && (ai+1 < argc)) {
      ai++;
      int num = argc - ai;
      needles = new const char *[num+1];
      while (ai < argc) {
	needles[numNeedles] = argv[ai++];
	const char *str = needles[numNeedles];
	bool foundSomething = true;
	while (foundSomething) {
	  foundSomething = false;
	  for (int i = 0, l = strlen(str); i < l && !foundSomething; i++) {
	    if ((str[i] == '\\') && (str[i+1] == 'x') && (i+3 < l)) {
	      char *newStr = (char *) malloc(strlen(str));
	      strncpy(newStr, str, i);
	      unsigned char b = 0;
	      if (str[i+2] >= 'A' && str[i+2] <= 'F') {
		b = 16 * (str[i+2] - 'A' + 10);
	      } else if (str[i+2] >= 'a' && str[i+2] <= 'f') {
		b = 16 * (str[i+2] - 'a' + 10);
	      } else if (str[i+2] >= '0' && str[i+2] <= '9') {
		b = 16 * (str[i+2] - '0');
	      } else {
		printf("ERROR: Invalid format for hex byte in needle: %s\n", str);
		usage(argv);
	      }
	      if (str[i+3] >= 'A' && str[i+3] <= 'F') {
		b += (str[i+2] - 'A' + 10);
	      } else if (str[i+3] >= 'a' && str[i+3] <= 'f') {
		b += (str[i+3] - 'a' + 10);
	      } else if (str[i+3] >= '0' && str[i+3] <= '9') {
		b += (str[i+3] - '0');
	      } else {
		printf("ERROR: Invalid format for hex byte in needle: %s\n", str);
		usage(argv);
	      }
	      newStr[i] = (char) b;
	      strncpy(newStr+i+1, str+i+4, l-i-4);
	      str = newStr;
	      foundSomething = true;
	    }
	  }
	}
	needles[numNeedles] = str;
	numNeedles++;
      }
      needles[numNeedles] = 0;
    } else {
      printf("ERROR: unrecognized command line argument: %s\n", argv[ai]);
      usage(argv);
    }
    ai++;
  }
  if (path == 0) {
    printf("ERROR: no -h[ay] argument supplied\n");
    usage(argv);
  }
  if (needles == 0) {
    printf("ERROR: no -n[eedles] argument supplied\n");
    usage(argv);
  }

  printf("INFO: Using %ld for start-byte\n", start_byte);
  printf("INFO: Using %d for window\n", window);
  printf("INFO: Using %s for hayfile\n", path);
  for (int i = 0; i < numNeedles; i++)
    printf("INFO: needle[%d] == %s\n", i, needles[i]);
}


int main(int argc, const char** argv) {

  processArgs(argc, argv);
  
	printf("CSV,position,hex-window,ascii-window\n");

	bufpos = 0; buffill = 0;
	f = open(path, O_RDONLY);
	if(f < 0) {
		perror("Opening input");
		exit(1);
	}
	ftotallen = lseek(f, 0, SEEK_END);
	fpos = fnextcp = 0;
	lseek(f, 0, SEEK_SET);

	do_scan();
	
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
