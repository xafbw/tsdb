#ifndef CLIENT_H
#define CLIENT_H
#define UPDATE_CHUNK_SZ 10000

#include <grpcpp/grpcpp.h>
#include "../../network/core/query.grpc.pb.h"
#include "../libPSI/libPSI/PIR/BgiPirClient.h"
#include "../libPSI/libPSI/PIR/BgiPirServer.h"
#include "../../secure-indices/core/DCFTable.h"
#include "../../secure-indices/core/DPFTable.h"
#include "../../secure-indices/core/AggTree.h"
#include "../../secure-indices/core/common.h"
#include "query.h"
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/TestCollection.h>
#include <map>
#include <string>
#include <vector>

using namespace osuCrypto;
using namespace std;
using namespace dorydb;
using dbquery::Query;
using dbquery::Aggregate;
using dbquery::CombinedFilter;
using dbquery::BaseFilter;
using dbquery::InitSPPRequest;
using dbquery::UpdateSPPRequest;
using dbquery::UpdateListRequest;
using grpc::Channel;
using grpc::ClientContext;
typedef unsigned __int128 bgi_uint128_t;


int removeElement(vector<int>& nums, int val);  
void Hint (uint128_t M, int N, uint64_t *X, uint64_t *X_);  
void Query (int x, uint128_t M, int N); 
int Answer (int Pj, int Pj_, int x, uint128_t M, int N, uint64_t *X);  
int Verify (int x, int N, uint128_t M, uint64_t *X, uint128_t Pj); 
void Refresh (int x, uint128_t M, int N, int B); 
uint64_t primaryNumParam(double Q, double ChunkSize, double target); 
void Answer1 (int x, int N, uint128_t M);        
    
 
class QueryClient
{
public:
    QueryClient(vector<shared_ptr<grpc::Channel>> channels, bool malicious = false);

    void AddValList(string id, uint32_t windowSize, vector<uint128_t> &data);
    void ValListUpdate(string id, uint32_t idx, uint128_t val, UpdateListRequest *reqs[]);
    void AddSPPTable(string id, uint32_t windowSize, uint32_t numBuckets, vector<uint32_t> &data);
    void SPPUpdate(string id, uint32_t idx, uint32_t val, UpdateSPPRequest *reqs[]);
    uint128_t AggQuery(string agg_id, QueryObj &query);
    void GenerateCombinedFilter(Expression *expr, CombinedFilter *filters[]);
    void GenerateBaseFilter(Condition *cond, BaseFilter *filters[]);
    void GenerateSPPFilter(string table_id, uint32_t x, BaseFilter *filters[]);
    void RunSPPUpdate(string id, uint32_t idx, uint32_t val);
    uint128_t GetMACAlpha();
    

private:
    vector<unique_ptr<dbquery::Query::Stub>> queryStubs;
    vector<unique_ptr<dbquery::Aggregate::Stub>> aggStubs;
    PRNG *prng;
    uint128_t modulus;
    bool malicious;
    uint128_t alpha;
    map<string, DPFTableClient*> SPPTables;

    uint8_t *RunCondition(Condition *cond, size_t ret_len);
    uint8_t *RecurseExpression(Expression *expr, size_t ret_len);
    uint128_t *d;
    uint128_t *e;
    uint128_t *d0;
    uint128_t *e0;
    uint128_t *d1;
    uint128_t *e1;
    uint128_t *Vd;
    uint128_t *Ve;
    int length;
    vector<uint128_t> list_a;
    vector<uint128_t> list_b;

};

#endif
