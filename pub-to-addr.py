#! /usr/bin/env python
# python 2.x

from bitcoin import *

if __name__ == "__main__":
  addrStr = pubtoaddr(sys.argv[1])
  print addrStr
                
