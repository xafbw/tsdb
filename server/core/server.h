#ifndef _SERVER_H_
#define _SERVER_H_

#include <grpcpp/grpcpp.h>
#include "../../network/core/query.grpc.pb.h"
#include "../../network/core/query.pb.h"
#include "../libPSI/libPSI/PIR/BgiPirClient.h"
#include "../libPSI/libPSI/PIR/BgiPirServer.h"
#include "../../secure-indices/core/DCFTable.h"
#include "../../secure-indices/core/DPFTable.h"
#include "../../secure-indices/core/AggTree.h"
#include "../../secure-indices/core/common.h"
#include "server.h"
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/TestCollection.h>
#include <map>
#include <string>
#include <vector>
#include <mutex>
#include <condition_variable>

using namespace osuCrypto;
using namespace std;
using namespace dorydb;
using dbquery::Aggregate;
using dbquery::CombinedFilter;
using dbquery::InitSystemRequest;
using dbquery::InitSystemResponse;
using dbquery::MultRequest;
using dbquery::MultResponse;
using grpc::ServerAsyncResponseWriter;
using grpc::ServerCompletionQueue;
using grpc::ServerContext;

enum RpcType {INIT, MULT};

struct RespPS {
    uint128_t Pj;
    uint128_t Pj_;
};

// 全局变量声明
extern RespPS* resPS;

// 初始化与释放
void init_resps_globals();
void free_resps_globals();

class QueryServer
{
public:
    QueryServer(string addrs[], int serverID, int cores, bool malicious);
    void StartSystemInit(string addrs[]);
    void FinishSystemInit(const uint8_t *key);
    void FinishMultiply(const uint128_t *shares0, const uint128_t *shares1, int len);
    void AddValList(string id, uint32_t windowSize);
    void ValListUpdate(string id, uint32_t loc, uint128_t val0);
    void AddSPPTable(string id, uint32_t windowSize, uint32_t numBuckets, bool malicious);
    void SPPUpdate(string id, uint32_t loc, const uint128_t *data0, uint128_t a, uint128_t b, uint128_t ab);
    void AggFilterQuery(string aggID, const CombinedFilter &filterSpec, uint128_t **d_i, uint128_t **e_i, int *len);
    void EvalFilter(uint128_t **filter0, uint128_t **filter1, const CombinedFilter &filterSpec);
    void AndFilters(uint128_t *shares_out0, uint128_t *shares_out1, uint128_t *shares_x0, uint128_t *shares_y0, int len);
    void OrFilters(uint128_t *shares_out0, uint128_t *shares_out1, uint128_t *shares_x0, uint128_t *shares_y0, int len);
    void Multiply(uint128_t *shares_out0, uint128_t *shares_out1, uint128_t *shares_x0, uint128_t *shares_y0, int len);
    void DEshare(const uint128_t *d1, const uint128_t *e1, int n, int len, uint128_t **d_j, uint128_t **e_j);
    void GetZshare(const uint128_t *d1, const uint128_t *e1, int len, uint128_t **dv_i, uint128_t **ev_i, string aggID);
    void Aggregate(const uint128_t *d1, const uint128_t *e1, int len, uint128_t *res);

    typedef struct Data data[36];
    void Answer1(vector<int> S_l, vector<int> S_h, int N, Data *temp);

    Aggregate::AsyncService *service;
    ServerCompletionQueue *cq;
    bool malicious;
    int cores;

private:
    uint128_t prfKey0;
    uint128_t prfKey1;
    uint128_t prfCounter;
    map<string, DPFTableServer *> SPPTables;
    map<string, vector<uint128_t>> ValLists;
    vector<uint128_t> list_a;
    vector<uint128_t> list_b;
    vector<uint128_t> list_ab;
    map<string, int> ValListWindowPtrs;
    map<string, int> SPPTableWindowPtrs;

    unique_ptr<dbquery::Query::Stub> nextServerStub;
    unique_ptr<dbquery::Aggregate::Stub> multStub;
    int serverID;
    mutex multLock;
    condition_variable multCV;
    condition_variable orderCV;
    uint128_t *multReceivedShares0;
    uint128_t *multReceivedShares1;
    uint128_t **res_g;
    uint128_t **tb;

    uint64_t gout_bitsize = 125;
    uint128_t one = 1;
    uint128_t group_mod = one << gout_bitsize;
};

class CallData
{
public:
    CallData(QueryServer &server, Aggregate::AsyncService *service, ServerCompletionQueue *cq, RpcType type);
    void Proceed();

private:
    Aggregate::AsyncService *service;
    ServerCompletionQueue *cq;
    ServerContext ctx;
    MultRequest reqMult;
    MultResponse respMult;
    ServerAsyncResponseWriter<MultResponse> responderMult;
    InitSystemRequest reqInit;
    InitSystemResponse respInit;
    ServerAsyncResponseWriter<InitSystemResponse> responderInit;
    enum CallStatus
    {
        CREATE,
        PROCESS,
        FINISH
    };
    CallStatus status;
    RpcType type;
    QueryServer &server;
};

#endif
