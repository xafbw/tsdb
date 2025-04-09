# TSDB

This is the implementation of our paper: Practical Verifiable Multi-predicate Range Query over Time-Series Database. The testing is performed on Ubuntu 22.04.2 LTS. 

## Main Phases

1. **Init**: 
   - The client sends parameters to two servers, including identifier, window size, and the number of buckets. 
   - Each server initializes its value list and table index based on the received parameters.
2. **Append**: 
   - The client computes and sends value shares and table shares to two servers separately. 
   - Each server updates its table shares (shared one-hot index) to store records.
3. **AggQuery**: 
   - The client queries with multiple predicates and interacts with two servers. 
   - Each server returns the shares of statistical result, which the client can then combine to obtain the final result.

## Main Functions

```
TSDB/
├── client					// client-side codes
│	├── AddValList()				// compute value shares and send to servers
│	├── AddSPPTable()				// compute table shares(shared one-hot index) and send to servers
│	├── AggQuery()					// query with multiple predicates
│	├── Hint()				   ───	
│	├── Query()					 	
│	├── Answer()				─┤  // SimPraPir
│	├── Verify()				 
│	└── refresh()			           ───
├── server					// server-side codes
│	├── AddValList()				// initialize value list
│	├── ValListUpdate()				// update value shares
│	├── AddSPPTable()				// initialize table index
│	├── SPPUpdate()					// update table shares(shared one-hot index)
│	├── AggFilterQuery()			// eval filter
│	├── GetZshare()					// 2-party multiply MPC
│	└── Aggregate()					// return the shares of statistical result
├── config					// input parameters
├── results					// output test results
└── README.md				// introduction
```

## Installation

The project requires a C++ compiler with C++14 support. The CMake version used is 3.22.1. 

[gRPC](https://grpc.io/) is a modern open source high performance Remote Procedure Call (RPC) framework that can run in any environment. [This guide](https://grpc.io/docs/languages/cpp/quickstart/) gets you started with [gRPC](https://github.com/grpc/grpc) (tested on versions 1.48.1) in C++ with a simple working example.

[CryptoTools](https://github.com/ladnir/cryptoTools/tree/master) is a portable c++14 library containing a collection of tools for building cryptographic protocols. It includes asynchronous networking, fast cryptographic primitives and several other utilities tailored for implementing protocols.

There are several other library dependencies including [Boost](https://www.boost.org/) (tested on versions 1.74.0), [Relic](https://github.com/relic-toolkit/relic) (tested on versions 0.6.0; the `-DMULTI=OPENMP` flag should be used with `cmake`) and [OpenSSl](https://www.openssl.org/) (tested on versions 1.1.1u). 

## Building

1. Build libOTe and libPSI

```
cd XX/tsdb

cd fss-core/libOTe
cmake . -DENABLE_RELIC=ON -DENABLE_NP=ON -DENABLE_KKRT=ON
make -j

cd ../libPSI
cmake . -DENABLE_RELIC=ON -DENABLE_DRRN_PSI=ON -DENABLE_KKRT_PSI=ON
make -j
```

2. Build network

```
cd ../../network
cmake .
make
```

3. Build tsdb

```
cd ..
cmake .
make
```

## Running

1. Open three terminal windows and make sure the current path is `xx/tsdb`.

   ```
   cd tsdb
   ```

2. In the first terminal window, start server 0 by running the following command. Note that `sudo` command requires a password.

   ```
   sudo ./build/bin/query_server config/server0.config
   ```

3. In the second terminal window, start server 1 in a similar way.

   ```
   sudo ./build/bin/query_server config/server1.config
   ```

4. Wait for the "DONE WITH SETUP" message in each server terminal window before proceeding to the next step.

5. In the third terminal window, start client and run as follows.

   ```
   sudo ./build/bin/bench config/client.config
   ```

NOTE: Parameters of the client can be modified in the `tsdb/config/client.config` file.

## Contact Us

1. Xuan Jing, [xjing_2@stu.xidian.edu.cn](mailto:xjing_2@stu.xidian.edu.cn)
2. Fei Xiao, [fxiao@stu.xidian.edu.cn](mainto:fxiao@stu.xidian.edu.cn)
3. Jianfeng Wang, [jfwang@xidian.edu.cn](mailto:jfwang@xidian.edu.cn)

