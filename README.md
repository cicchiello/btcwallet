# code to help recover lost btc wallet keys, assuming very old (0.4) versions of the db file available

Dependencies:
   db-4.8.30:
      source: http://www.oracle.com/technetwork/products/berkeleydb/downloads/index-082944.html
      place in cwd
   cryptopp:
      source: https://github.com/weidai11/cryptopp
      place in cwd
   openssl:
      source: https://medium.com/@zlwaterfield/openssl-with-el-capitan-456bf68bf43a

build (once dependencies are available):
   make

run:
   > ./recover-wallet <file-or-dev> {<recovered-file>} > lots-of-log-to-review.log

analysis:
  assuming a clean run, the most interesting info will be found via:
     > grep dumpPotential lots-of-log-to-review.log

