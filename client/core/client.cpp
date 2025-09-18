#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <string>
#include <math.h>
#include <assert.h>
#include "client.h"
#include "query.h"
#include "../../secure-indices/core/DPFTable.h"
#include "../../network/core/query.grpc.pb.h"
#include "../../network/core/query.pb.h"
#include "../../secure-indices/core/common.h"

using dbquery::Aggregate;
using dbquery::AggRequest;
using dbquery::AggResponse;
using dbquery::BaseFilter;
using dbquery::BatchedUpdateListRequest;
using dbquery::BatchedUpdateListResponse;
using dbquery::BatchedUpdateSPPRequest;
using dbquery::BatchedUpdateSPPResponse;
using dbquery::CombinedFilter;
using dbquery::DEshareRequest;
using dbquery::DEshareResponse;
using dbquery::InitListRequest;
using dbquery::InitListResponse;
using dbquery::InitSPPRequest;
using dbquery::InitSPPResponse;
using dbquery::Query;
using dbquery::QueryAggRequest;
using dbquery::QueryAggResponse;
using dbquery::UpdateListRequest;
using dbquery::UpdateListResponse;
using dbquery::UpdateSPPRequest;
using dbquery::UpdateSPPResponse;
using dbquery::ZshareRequest;
using dbquery::ZshareResponse;
using grpc::Channel;
using grpc::ClientAsyncResponseReader;
using grpc::ClientContext;
using grpc::CompletionQueue;
using grpc::Status;
using namespace dorydb;
using namespace osuCrypto;
using namespace std;

#define M_SIZE 1920 
#define N_SIZE 16   
#define WS 16       

QueryClient::QueryClient(vector<shared_ptr<grpc::Channel>> channels, bool malicious)
{
    for (int i = 0; i < NUM_SERVERS; i++)
    {
        queryStubs.push_back(Query::NewStub(channels[i]));
        aggStubs.push_back(Aggregate::NewStub(channels[i]));
    }
    block seed = toBlock(rand(), rand());
    prng = new PRNG(seed);
    this->malicious = malicious;
}

void QueryClient::AddValList(string id, uint32_t windowSize, vector<uint128_t> &data)
{
    /* Initialize list at servers. */
    for (int i = 0; i < NUM_SERVERS; i++)
    {
        InitListRequest req;
        InitListResponse resp;
        ClientContext ctx;
        req.set_id(id);
        req.set_window_size(windowSize);
        // cout << "Doing queryStubs[" << i << "]->SendListInit..." << endl;
        queryStubs[i]->SendListInit(&ctx, req, &resp);
    }

    /* Load data. */
    BatchedUpdateListRequest reqs[NUM_SERVERS];
    assert(data.size() >= windowSize); 
    for (int batch = 0; batch < windowSize / UPDATE_CHUNK_SZ + 1; batch++) {
        for (int i = 0; i < UPDATE_CHUNK_SZ && batch * UPDATE_CHUNK_SZ + i < windowSize; i++) {
            int idx = batch * UPDATE_CHUNK_SZ + i;
            UpdateListRequest *tmp_reqs[NUM_SERVERS];
            for (int j = 0; j < NUM_SERVERS; j++) {
                tmp_reqs[j] = reqs[j].add_updates();
            }
            this->ValListUpdate(id, idx, data[idx], tmp_reqs);
        }

        for (int i = 0; i < NUM_SERVERS; i++) {
            BatchedUpdateListResponse resp;
            ClientContext ctx;
            cout << "Doing queryStubs[" << i << "]->SendListBatchedUpdate..." << endl;
            queryStubs[i]->SendListBatchedUpdate(&ctx, reqs[i], &resp);
        }
    }
}

void QueryClient::ValListUpdate(string id, uint32_t idx, uint128_t val, UpdateListRequest *reqs[])
{
    uint128_t shares[2];
    splitIntoSingleArithmeticShares(prng, val, shares);
    // cout << "val " << idx << " " << shares[0] << " " << shares[1] << " " << shares[0] + shares[1] << endl;

    for (int i = 0; i < NUM_SERVERS; i++)
    {
        reqs[i]->set_id(id);
        reqs[i]->set_val(idx);
        reqs[i]->set_share0((char *)&shares[i], sizeof(uint128_t));
    }
}


T* t = nullptr;
T_* t_ = nullptr;
Hj hj;
R* r = nullptr;
DataS* dataS = nullptr;
RespP* resP = nullptr;


struct GlobalsManager {
    GlobalsManager() { init_globals(); }
    ~GlobalsManager() { free_globals(); }
} _globals_manager;

void init_globals() {
    t    = new T[M_SIZE];
    t_   = new T_[M_SIZE];
    r    = new R[M_SIZE];
    dataS = new DataS[N_SIZE * N_SIZE];
    resP  = new RespP[2];

    for (size_t i = 0; i < M_SIZE; ++i) {
        r[i].res0 = new uint128_t[N_SIZE];
        r[i].random_index = new int[N_SIZE];
    }

    for (size_t i = 0; i < 2; ++i) {
        resP[i].Pj  = new uint128_t[WS];
        resP[i].Pj_ = new uint128_t[WS];
    }
}

void free_globals() {
    for (size_t i = 0; i < M_SIZE; ++i) {
        delete[] r[i].res0;
        delete[] r[i].random_index;
    }
    delete[] r;

    for (size_t i = 0; i < 2; ++i) {
        delete[] resP[i].Pj;
        delete[] resP[i].Pj_;
    }
    delete[] resP;

    delete[] t;
    delete[] t_;
    delete[] dataS;
}


void QueryClient::AddSPPTable(string id, uint32_t windowSize, uint32_t numBuckets, vector<uint32_t> &data)
{
    int numBucketsLog = getDepth(numBuckets);
    SPPTables[id] = new DPFTableClient(id, numBucketsLog, windowSize, malicious);
    alpha = SPPTables[id]->alpha;

    /* Initialize table at servers. */
    for (int i = 0; i < NUM_SERVERS; i++)
    {
        InitSPPRequest req;
        InitSPPResponse resp;
        ClientContext ctx;
        req.set_id(id);
        req.set_window_size(windowSize);
        // hj.Window_Size = windowSize;                                    
        req.set_num_buckets(numBuckets);
        req.set_malicious(malicious);
        // cout << "Doing queryStubs[" << i << "]->SendSPPInit..." << endl;
        queryStubs[i]->SendSPPInit(&ctx, req, &resp);
    }

    /* Load data. */
    for (int batch = 0; batch < windowSize / UPDATE_CHUNK_SZ + 1; batch++)
    { // UPDATE_CHUNK_SZ=10000
        BatchedUpdateSPPRequest reqs[NUM_SERVERS];
        assert(data.size() >= windowSize);
        // printf("batch = %d/%d\n", batch, windowSize / UPDATE_CHUNK_SZ);
        for (int i = 0; i < UPDATE_CHUNK_SZ && batch * UPDATE_CHUNK_SZ + i < windowSize; i++)
        {
            int idx = batch * UPDATE_CHUNK_SZ + i;
            UpdateSPPRequest *tmp_reqs[NUM_SERVERS];
            for (int j = 0; j < NUM_SERVERS; j++)
            {
                tmp_reqs[j] = reqs[j].add_updates();
            }
            this->SPPUpdate(id, idx, data[idx], tmp_reqs);
        }

        for (int i = 0; i < NUM_SERVERS; i++)
        {
            BatchedUpdateSPPResponse resp;
            ClientContext ctx;
            // cout << "Doing queryStubs[" << i << "]->SendSPPBatchedUpdate..." << endl;
            queryStubs[i]->SendSPPBatchedUpdate(&ctx, reqs[i], &resp);
        }
    }
}

void QueryClient::SPPUpdate(string id, uint32_t idx, uint32_t val, UpdateSPPRequest *reqs[])
{
    uint128_t *raw_data = createIndicatorVector(val, SPPTables[id]->numBuckets); // the val-th position in column idx is 1
    uint128_t *data[2];
    data[0] = (uint128_t *)malloc(SPPTables[id]->numBuckets * sizeof(uint128_t));
    data[1] = (uint128_t *)malloc(SPPTables[id]->numBuckets * sizeof(uint128_t));
    splitIntoArithmeticShares(prng, raw_data, SPPTables[id]->numBuckets, data);

    uint128_t R_a = randFieldElem(prng);
    uint128_t R_b = randFieldElem(prng);
    uint128_t R_ab = R_a * R_b;
    // cout << "ab: " << R_ab << endl;
    uint128_t a[2];
    uint128_t b[2];
    uint128_t ab[2];
    a[0] = randFieldElem(prng);
    b[0] = randFieldElem(prng);
    ab[0] = randFieldElem(prng);
    a[1] = R_a - a[0];
    b[1] = R_b - b[0];
    ab[1] = R_ab - ab[0];
    // cout << "val " << idx << "  ab0: " << ab[0] << "  ab1: " << ab[1] << endl;

    list_a.push_back(R_a);
    list_b.push_back(R_b);

    for (int i = 0; i < NUM_SERVERS; i++)
    {
        UpdateSPPRequest req;
        UpdateSPPResponse resp;
        ClientContext ctx;

        reqs[i]->set_id(id);
        reqs[i]->set_val(idx);
        reqs[i]->set_data0((char *)data[i], sizeof(uint128_t) * SPPTables[id]->numBuckets);
        reqs[i]->set_a((char *)&a[i], sizeof(uint128_t));
        reqs[i]->set_b((char *)&b[i], sizeof(uint128_t));
        reqs[i]->set_ab((char *)&ab[i], sizeof(uint128_t));
    }

    for (int i = 0; i < SPPTables[id]->numBuckets; i++)
    {
        // for (int i = 0; i < N_SIZE * N_SIZE; i++) {
        dataS[i].D[0] = data[0][i];
        dataS[i].D[1] = data[1][i];
    }

    free(raw_data);
    free(data[0]);
    free(data[1]);
}

void QueryClient::RunSPPUpdate(string id, uint32_t idx, uint32_t val)
{
    uint128_t *raw_data = createIndicatorVector(val, SPPTables[id]->numBuckets); // the val-th position in column idx is 1
    uint128_t *data[2];
    data[0] = (uint128_t *)malloc(SPPTables[id]->numBuckets * sizeof(uint128_t));
    data[1] = (uint128_t *)malloc(SPPTables[id]->numBuckets * sizeof(uint128_t));
    splitIntoArithmeticShares(prng, raw_data, SPPTables[id]->numBuckets, data);

    uint128_t R_a = randFieldElem(prng);
    uint128_t R_b = randFieldElem(prng);
    uint128_t R_ab = R_a * R_b;
    // cout << "ab: " << R_ab << endl;
    uint128_t a[2];
    uint128_t b[2];
    uint128_t ab[2];
    a[0] = randFieldElem(prng);
    b[0] = randFieldElem(prng);
    ab[0] = randFieldElem(prng);
    a[1] = R_a - a[0];
    b[1] = R_b - b[0];
    ab[1] = R_ab - ab[0];
    // cout << "val " << idx << "  ab0: " << ab[0] << "  ab1: " << ab[1] << endl;

    list_a.push_back(R_a);
    list_b.push_back(R_b);

    for (int i = 0; i < NUM_SERVERS; i++)
    {
        UpdateSPPRequest req;
        UpdateSPPResponse resp;
        ClientContext ctx;

        req.set_id(id);
        req.set_val(idx);
        req.set_data0((char *)data[i], sizeof(uint128_t) * SPPTables[id]->numBuckets);
        req.set_a((char *)&a[i], sizeof(uint128_t));
        req.set_b((char *)&b[i], sizeof(uint128_t));
        req.set_ab((char *)&ab[i], sizeof(uint128_t));
        queryStubs[i]->SendSPPUpdate(&ctx, req, &resp);
    }

    for (int i = 0; i < SPPTables[id]->numBuckets; i++)
    {
        // for (int i = 0; i < N_SIZE * N_SIZE; i++) {
        dataS[i].D[0] = data[0][i];
        dataS[i].D[1] = data[1][i];
    }

    free(raw_data);
    free(data[0]);
    free(data[1]);
}

int removeElement(vector<int> &nums, int val)
{
    int length = 0;
    for (int i = 0; i < (nums.size() - length); i++)
        if (nums[i] == val)
        {
            nums[i--] = nums[nums.size() - ++length];
        }
    return nums.size() - length;
}

void Hint(int M, int N, uint64_t *X, uint64_t *X_)
{
    string str0 = "select";
    static uint128_t **InAr;
    static uint128_t **V;
    InAr = new uint128_t *[M];
    V = new uint128_t *[M];
    // int cnt=0;
    for (int j = 0; j < M; j++)
    {
        InAr[j] = new uint128_t[N];
        // res0[j] = new   uint128_t [N];
        V[j] = new uint128_t[N];
        // e[j] = 0;
        t[j].e = 0;
        // random_index[j] = new int [N];
        int kcnt = 0;
        for (int k = 0; k < N; k++)
        {
            string str1 = std::to_string(j);
            string str2 = std::to_string(k);
            string str = str0 + str1 + str2;

            InAr[j][k] = 0;
            r[j].res0[k] = 0;
            V[j][k] = 0;
            r[j].random_index[k] = 0;

            // std::cout << " str0 " << str0 << " str1 " << str1 << " str2 " << str2 << " str " << str << std::endl;
            // cout << str << endl;
            InAr[j][k] = stringTouint128(str);
            str = "";
            str = int128Toustring(InAr[j][k]);
            // cout << str << endl;

            block seed = toBlock(rand(), rand());
            PRNG prng(seed);
            uint64_t prfKey0 = prng.get<uint64_t>();
            r[j].res0[k] = prfFieldElem(prfKey0, InAr[j][k]);
            // std::cout << " res0 " << " j= " << j << " k= " << k << " : " << r[j].res0[k] << std::endl;

            V[j][k] = r[j].res0[k];

            // data[cnt].D = rand() % N;
            // cnt++;

            r[j].random_index[k] = rand() % N;
            kcnt++;
        }
        sort(V[j], V[j] + kcnt);
        if (kcnt % 2 == 0)
        {
            t[j].median = V[j][kcnt / 2 - 1] + 1;
            t_[j].median_ = V[j][kcnt / 2 - 1] + 1;
        }
        else
        {
            t[j].median = V[j][kcnt / 2];
            t_[j].median_ = V[j][kcnt / 2];
        }
        // std::cout << "median" << " j=" << j << "：" << t[j].median << std::endl;
    }

    // generate e[j]
    for (int j = 0; j < M; j++)
    {
        for (int k = 0; k < N; k++)
        {
            if (r[j].res0[k] > t[j].median)
            {
                t[j].e = r[j].random_index[k] + k * N;
                break;
            }
        }
        // std::cout << " j=" << j << " e[j]=" << t[j].e << std::endl;
    }

    for (int j = 0; j < M; j++)
    {
        string resultX = int64Toustring(X[j]);
        string resultX_ = int64Toustring(X_[j]);

        uint128_t tmpp = 0;
        string f_tmp1 = int128Toustring(tmpp);
        string f_tmp2 = int128Toustring(tmpp);

        for (int i = 0; i < resultX.length(); i++)
        {
            resultX[i] ^= f_tmp1[i];
        }
        t[j].F = stringTouint128(resultX);
        for (int i = 0; i < resultX_.length(); i++)
        {
            resultX_[i] ^= f_tmp2[i];
        }
        t_[j].F_ = stringTouint128(resultX_);

        t[j].P = 0;
        t_[j].P_ = 0;
        for (int k = 0; k < N; k++)
        {
            int i = r[j].random_index[k] + k * N;
            // std::cout << " random_index " << " j= " << j << " k= " << k << ": " << r[j].random_index[k] << std::endl;
            //  int d = data[i].D;
            uint128_t d = dataS[i].D[0] + dataS[i].D[1];
            if (j < M && r[j].res0[k] < t[j].median)
            {
                // std::cout << " res0 " << " j= " << j << " k= " << k << " : " << r[j].res0[k] << std::endl;
                // std::cout << "median" << " j=" << j << ": " << t[j].median << std::endl;
                t[j].h = j;
                t[j].P = t[j].P + d;
                // std::cout << " j=" << j << " P[j]=" << t[j].P << std::endl;

                string result0 = std::to_string(i);
                string resultd1 = int128Toustring(d);
                for (int i = 0; i < result0.length(); i++)
                {
                    result0[i] ^= resultd1[i];
                }
                t[j].F = t[j].F + stringTouint128(result0);

                // std::cout << " j=" << j << " F[j]=" << t[j].F << std::endl;
            }
            else if (r[j].res0[k] > t_[j].median_)
            {

                // std::cout << " res0 " << " j= " << j << " k= " << k << " : " << r[j].res0[k] << std::endl;
                t_[j].h_ = j;
                t_[j].P_ = t_[j].P_ + d;

                string result0_ = std::to_string(i);
                string resultd1_ = int128Toustring(d);
                for (int i = 0; i < result0_.length(); i++)
                {
                    result0_[i] ^= resultd1_[i];
                }
                t_[j].F_ = t_[j].F_ + stringTouint128(result0_);

                // std::cout << " j=" << j << " P_[j]=" << t_[j].P_ << std::endl;
                // std::cout << " j=" << j << " F_[j]=" << t_[j].F_ << std::endl;
            }
            if (floor(t[j].e / N) == k)
            {
                // std::cout << " j=" << j << " floor(e[j]/N)=" << floor(t[j].e/N) << std::endl;
                // std::cout << " j=" << j << " t[j].e=" << t[j].e << std::endl;
                //  t[j].P = t[j].P + data[t[j].e].D;
                t[j].P = t[j].P + dataS[t[j].e].D[0] + dataS[t[j].e].D[1];
                // std::cout << " j=" << j << " P[j]=" << t[j].P << std::endl;

                string result0 = std::to_string(t[j].e);
                string resultd1 = int128Toustring(dataS[t[j].e].D[0] + dataS[t[j].e].D[1]);
                for (int i = 0; i < result0.length(); i++)
                {
                    result0[i] ^= resultd1[i];
                }
                t[j].F = t[j].F + stringTouint128(result0);

                // std::cout << " j=" << j << " P[j]=" << t[j].P << std::endl;
                // std::cout << " j=" << j << " F[j]=" << t[j].F << std::endl;
            }
        }
    }
}

void Query(int x, int M, int N)
{
    // x = 8;
    int l = floor(x / N);
    hj.j = 0;
    for (int j = 0; j < M; j++)
    {
        if (r[j].res0[l] < t[j].median && r[j].random_index[l] == x % N)
        {
            // std::cout << std::endl;
            // std::cout << " r[j].res0[l]=" << r[j].res0[l] << std::endl;
            // std::cout << " r[j].random_index[l]=" << r[j].random_index[l] << std::endl;
            for (int k = 0; k < N; k++)
            {
                if (r[j].res0[k] < t[j].median)
                {
                    r[j].S_l.push_back(r[j].random_index[k] + k * N);
                    // std::cout << r[j].S_l[k] << "-------------------" <<  std::endl;
                }
                else if (floor(t[j].e / N) == k)
                {
                    r[j].S_l.push_back(t[j].e);
                    // std::cout << r[j].S_l[k] << "-------------------" <<  std::endl;
                }
                else
                {
                    r[j].S_h.push_back(r[j].random_index[k] + k * N);
                    // std::cout << r[j].S_h[k] << "-------------------" <<  std::endl;
                }
            }
            hj.j = j;
            // std::cout << "--------hj.j-----------" << hj.j  <<  std::endl;
            break;
        }
        else
        {
            // std::cout << " r[j].res0[l]=" << r[j].res0[l] << std::endl;
            // std::cout << " r[j].random_index[l]=" << r[j].random_index[l] << std::endl;
            hj.j = hj.j + 1;
            // std::cout << "--------hj.j-----------" << hj.j  <<  std::endl;
        }
    }
    if (hj.j <= M)
    {
        // std::cout << "--------hj.j-----------" << hj.j  <<  std::endl;
        int len = removeElement(r[hj.j].S_l, x);
        // std::cout << "hj.j" << hj.j << std::endl;

        // for (int u = 0; u < len; u++)
        // {
        //     std::cout << " u=" << u << " S_l[u]=" << r[hj.j].S_l[u] << std::endl;
        // }
        for (int u = 0; u < N / 2; u++)
        {
            r[hj.j].S_h.push_back((rand() % N) + l * N);
            // std::cout << " u=" << u << " S_h[u]=" << r[hj.j].S_h[u] << std::endl;
        }
    }
}

/* void Answer1(int x, int N, int M)
{
    resP.Pj = 0;
    resP.Pj_ = 0;
    int l = floor(x / N);
    for (int j = 0; j < M; j++)
    {
        if (r[j].res0[l] < t[j].median && r[j].random_index[l] == x % N)
        {
            for (int u = 0; u < N / 2; u++)
            {
                resP.Pj += data[r[j].S_l[u]].D;
                std::cout << " u=" << u << " S_l[u]=" << r[j].S_l[u] << " D[S_l[u]]=" << data[r[j].S_l[u]].D << std::endl;
            }
            for (int u = 0; u < N / 2; u++)
            {
                resP.Pj_ += data[r[j].S_h[u]].D;
                std::cout << " u=" << u << " S_h[u]=" << r[j].S_h[u] << " D[S_h[u]]=" << data[r[j].S_h[u]].D << std::endl;
            }
            std::cout << " Pj=" << resP.Pj << std::endl;
            std::cout << " Pj_=" << resP.Pj_ << std::endl;
            // return (resP.Pj, resP.Pj_);
        }
        else if (hj.j >= M)
        {
            break;
        }
    }
} */

uint128_t Answer(uint128_t Pj, uint128_t Pj_, int x, int M, int N, uint64_t *X)
{
    uint128_t B = 0;
    int l = floor(x / N);
    hj.G = 0;
    for (int j = 0; j < M; j++)
    {
        if (r[j].res0[l] < t[j].median && r[j].random_index[l] == x % N)
        {
            // B = t[j].P * hj.Window_Size - Pj;  //in order to work with Pj(size:windowsize), let t[j].P = t[j].P ✖ windowsize。
            B = t[j].P - Pj;
            // std::cout <<  " hj.Window_Size = " << hj.Window_Size << " hj.Window_Size " << hj.Window_Size << std::endl;
            // std::cout << std::endl;
            // std::cout <<  " x = " << x << " D[x] = " << B << std::endl;

            string strPB0 = int128Toustring(B);
            string strPB1 = std::to_string(x);
            string result3 = strPB1;

            for (int i = 0; i < result3.length(); i++)
            {
                result3[i] ^= strPB0[i];
            }

            hj.G = stringTouint128(result3);

            break;
        }
        else if (hj.j >= M)
        {
            break;
        }
    }
    return B;
}

int Verify(int x, int N, int M, uint64_t *X, uint128_t Pj)
{

    uint128_t Oj = 0;
    uint128_t Oj_ = 0;
    uint128_t Hash = 0;
    int l = floor(x / N);
    for (int j = 0; j < M; j++)
    {
        if (r[j].res0[l] < t[j].median && r[j].random_index[l] == x % N)
        {
            uint128_t x = 0;
            string xx = int128Toustring(x);
            for (int u = 0; u < N / 2; u++)
            {
                string strPJ1 = std::to_string(r[j].S_l[u]);
                for (int i = 0; i < strPJ1.length(); i++)
                {
                    strPJ1[i] ^= xx[i];
                }
                Oj_ = Oj_ + stringTouint128(strPJ1);
            }

            string strPJ00 = int128Toustring(Pj);
            string Ojj = int128Toustring(Oj_);

            for (int i = 0; i < strPJ00.length(); i++)
            {
                strPJ00[i] ^= Ojj[i];
            }

            Oj = X[j] + stringTouint128(strPJ00);
            Hash = hj.G + Oj;

            if (Hash == t[j].F)
            {
                // std::cout <<  std::endl;
                // std::cout <<  " true" << " F[j]=" << t[j].F << std::endl;
                // std::cout <<  " true" << " Hash=" << Hash << std::endl;
                return 1;
            }
            else
            {
                // std::cout <<  " false" << " F[j]=" << t[j].F << std::endl;
                // std::cout <<  " false" << " Hash=" << Hash << std::endl;
                return 0;
            }
        }
        else if (hj.j >= M)
        {
            break;
        }
    }
}

void Refresh(int x, int M, int N, uint128_t B) {}
/*     int l = floor(x / N);
    for (int j = 0; j < M; j++)
    {
        if (r[j].res0[l] < t[j].median && r[j].random_index[l] == x % N)
        { // Consume j and reuse the one where j is not located (res0[j][l] > median[j]). If we reuse the one where j is located, we can't look up other indexes of Pj
            t[j].P = t_[j].P_;
            t[j].F = t_[j].F_;
            std::cout << std::endl;
            std::cout << " j=" << j << " P[j]=" << t[j].P << std::endl;
            // j = J;
            t[j].e = x;
            t[j].P = t[j].P + B;
            t[j].F = t[j].F + hj.G;
            std::cout << " j=" << j << " e[j]=" << t[j].e << " P[j]=" << t[j].P << std::endl;
            std::cout << " j=" << j << " e[j]=" << t[j].e << " F[j]=" << t[j].F << std::endl;
            break;
        }
        else if (hj.j >= M)
        {
            break;
        }
    }
} */

uint64_t primaryNumParam(double Q, double ChunkSize, double target)
{
    uint64_t k = ceil(log(2) * (target) + log(Q));
    return uint64_t(k) * uint64_t(ChunkSize);
}

uint128_t QueryClient::AggQuery(string agg_id, QueryObj &query)
{
    CombinedFilter *filters[NUM_SERVERS];
    QueryAggRequest reqs[NUM_SERVERS];
    QueryAggResponse resps[NUM_SERVERS];
    ClientContext ctx[NUM_SERVERS];
    CompletionQueue cq[NUM_SERVERS];
    Status status[NUM_SERVERS];
    unique_ptr<ClientAsyncResponseReader<QueryAggResponse>> rpcs[NUM_SERVERS];

    int x = 1;
    uint64_t *X;
    uint64_t *X_;
    X = new uint64_t[M_SIZE];
    X_ = new uint64_t[M_SIZE];
    int l = floor(x / N_SIZE);
    for (int j = 0; j < M_SIZE; j++)
    {
        block seed = toBlock(rand(), rand());
        PRNG prng(seed);
        X[j] = prng.get<uint64_t>();
        X_[j] = prng.get<uint64_t>();
    }

    INIT_TIMER;
    // START_TIMER;
    struct timeval t11, t22;
    gettimeofday(&t11, NULL);
    gettimeofday(&t22, NULL);
    double Hint_time = ((t22.tv_sec - t11.tv_sec) * 1000000.0 + t22.tv_usec - t11.tv_usec) / 1000.0;
    // cout << "====================Hint time====================(ms): " << Hint_time << endl;
    // STOP_TIMER("====================Hint time====================");

    uint128_t one = 1;
    uint128_t group_mod = (one << 125);

    // INIT_TIMER;
    START_TIMER;
    struct timeval t1, t2;
    gettimeofday(&t1, NULL);
    for (int i = 0; i < NUM_SERVERS; i++)
    {
        filters[i] = reqs[i].mutable_combined_filter(); // Set x=1 corresponds to the token
    }
    // cout << "Going to generate combined filter" << endl;
    GenerateCombinedFilter(query.expr, filters);
    // cout << "Generated combined filter" << endl;

    // STOP_TIMER("====================Generated combined filter====================");
    gettimeofday(&t2, NULL);
    double GenComFilter_time = ((t2.tv_sec - t1.tv_sec) * 1000000.0 + t2.tv_usec - t1.tv_usec) / 1.000;
    // cout << "====================Generated combined filter====================(us): " << GenComFilter_time << endl;

    // The client sends a query request, the server calculates d0 e0, d1 e1 of the two predicates AND and sends them to the client, who gets and calculates d e
    // cout << "===================== send AggQuery, get d_ and e_ and compute d e(AND 1 2) =====================" << endl;
    for (int i = 0; i < NUM_SERVERS; i++)
    {
        reqs[i].set_agg_id(agg_id);
        // cout << "Query size: " << reqs[i].ByteSizeLong() << "B" << endl;
        // cout << "Doing queryStubs[" << i << "]->AsyncSendAggQuery..." << endl;
        rpcs[i] = queryStubs[i]->AsyncSendAggQuery(&ctx[i], reqs[i], &cq[i]);
        rpcs[i]->Finish(&resps[i], &status[i], (void *)1);
    }

    for (int q = 0; q < NUM_SERVERS; q++)
    {
        void *got_tag;
        bool ok = false;
        cq[q].Next(&got_tag, &ok); // send but can't receive, note that asynchronous sending is included in these three sentences
        if (ok && got_tag == (void *)1)
        {
            int length0 = resps[0].leng0(); // return Pj(size:windowsize)

            if (status[q].ok())
            {
                // cout << "hj.j = " << hj.j << ",  M = " << M_SIZE << endl;

                if (hj.j <= M_SIZE)
                {
                    uint128_t resPP1;
                    uint128_t resPP2;
                    uint128_t resPPQ1;
                    uint128_t resPPQ2;
                    int len = resps[q].d_i().size();
                    int l = sizeof(uint128_t);
                    length = len / l;
                    if (q == 0)
                    {
                        d0 = (uint128_t *)malloc(sizeof(uint128_t) * length);
                        e0 = (uint128_t *)malloc(sizeof(uint128_t) * length);
                        memcpy(d0, (const uint128_t *)resps[q].d_i().c_str(), sizeof(uint128_t) * length);
                        memcpy(e0, (const uint128_t *)resps[q].e_i().c_str(), sizeof(uint128_t) * length);

                        // cout << "d0[1]: " << d0[0] << endl;
                        // cout << "e0[1]: " << e0[1] << endl;

                        for (int v = 0; v < length; v++)
                        { // return all Pj
                            memcpy((uint8_t *)&resPP1, (const uint8_t *)resps[q].p1(v).c_str(), sizeof(uint128_t));
                            // resPP1 = stringTouint128(resps[q].p1(v));
                            // std::cout <<  " resPP1: " << resPP1 << std::endl;
                            resP[q].Pj[v] = resPP1;
                            // resP.Pj = resps[q].p1();
                            // std::cout <<  " resP[0].Pj---------=" << resP[q].Pj[v] << std::endl;
                            memcpy((uint8_t *)&resPP2, (const uint8_t *)resps[q].p2(v).c_str(), sizeof(uint128_t));
                            // resPP2 = stringTouint128(resps[q].p2());
                            // resP.Pj_ = resps[q].p2();
                            resP[q].Pj_[v] = resPP2;
                            // std::cout <<  " resP[0].Pj_-----------=" << resP[q].Pj_[v] << std::endl;

                            // std::cout <<  " list_a0[v]-----------=" << list_a0[v] << std::endl;
                            // std::cout <<  " list_b0[v]-----------=" << list_b0[v] << std::endl;
                        }
                    }
                    else
                    {
                        d1 = (uint128_t *)malloc(sizeof(uint128_t) * length);
                        e1 = (uint128_t *)malloc(sizeof(uint128_t) * length);
                        d = (uint128_t *)malloc(sizeof(uint128_t) * length);
                        e = (uint128_t *)malloc(sizeof(uint128_t) * length);
                        memcpy(d1, (const uint128_t *)resps[q].d_i().c_str(), sizeof(uint128_t) * length);
                        memcpy(e1, (const uint128_t *)resps[q].e_i().c_str(), sizeof(uint128_t) * length);

                        // cout << "d1[1]: " << d1[1] << endl;
                        // cout << "e1[1]: " << e1[1] << endl;

                        Vd = (uint128_t *)malloc(sizeof(uint128_t) * length);
                        Ve = (uint128_t *)malloc(sizeof(uint128_t) * length);

                        for (int v = 0; v < length; v++)
                        {
                            memcpy((uint8_t *)&resPPQ1, (const uint8_t *)resps[q].p1(v).c_str(), sizeof(uint128_t));
                            // resPPQ1 = stringTouint128(resps[q].p1());t[j].P
                            // std::cout <<  " resPP1: " << resPP1 << std::endl;
                            resP[q].Pj[v] = resPPQ1;
                            // resP.Pj = resps[q].p1();
                            // std::cout <<  " resP[1].Pj---------=" << resP[q].Pj[v] << std::endl;
                            memcpy((uint8_t *)&resPPQ2, (const uint8_t *)resps[q].p2(v).c_str(), sizeof(uint128_t));
                            // resPPQ2 = stringTouint128(resps[q].p2());
                            // resP.Pj_ = resps[q].p2();
                            resP[q].Pj_[v] = resPPQ2;
                            // std::cout <<  " resP[1].Pj_-----------=" << resP[q].Pj_[v] << std::endl;

                            // std::cout <<  " list_a1[v]-----------=" << list_a1[v] << std::endl;
                            // std::cout <<  " list_b1[v]-----------=" << list_b1[v] << std::endl;

                            d[v] = (d0[v] + d1[v]);
                            e[v] = (e0[v] + e1[v]);

                            d[v] += list_a[v];
                            e[v] += list_b[v];

                            Vd[v] = Answer(d[v], e[v], x, M_SIZE, N_SIZE, X);

                            // if (Verify(x, N_SIZE, M_SIZE, X, d[v]) == 1)
                            // {
                            //     std::cout <<  " ==========Verify Passed=========== " <<  std::endl;
                            //     Refresh(x, M, N, Vd[v]);
                            // }
                            // else
                            // {
                            //     std::cout <<  " ==========Verify Not Passed=========== " <<  std::endl;
                            // }

                            Ve[v] = Answer(e[v], d[v], x, M_SIZE, N_SIZE, X);

                            d[v] = Vd[v] - list_a[v];
                            e[v] = Ve[v] - list_b[v];
                        }
                    }
                }
                else
                {
                    for (int v = 0; v < length0; v++)
                    {
                        resP[q].Pj[v] = 0;
                        resP[q].Pj_[v] = 0;
                        std::cout << " resP.Pj=" << resP[q].Pj[v] << std::endl;
                        std::cout << " resP.Pj_=" << resP[q].Pj_[v] << std::endl;
                    }
                }
            }
            else
            {
                cout << "ERROR receiving message " << status[q].error_message().c_str() << endl;
            }
        }
    }

    // cout << "d0[1]: " << d0[1] << endl;
    // cout << "e0[1]: " << e0[1] << endl;
    // cout << "d1[1]: " << d1[1] << endl;
    // cout << "e1[1]: " << e1[1] << endl;
    // cout << "d[1]: " << d[1] << endl;
    // cout << "e[1]: " << e[1] << endl;
    // cout << "Already get d e (AND 1 2)" << endl;
    // STOP_TIMER("send AggQuery, get d_ and e_ and compute d e(AND 1 2)");

    // INIT_TIMER;
    // START_TIMER;
    // Intermediate AND loop, send de，get de shares
    // cout << "===================== send d e, get d_ and e_ and compute d e(AND 3~)=====================" << endl;
    int p = query.expr->conds.size();
    int n = p - 2;
    // cout << "n: " << n << endl;

    DEshareRequest reqs_de[n][NUM_SERVERS];
    DEshareResponse resps_de[n][NUM_SERVERS];
    ClientContext ctxs_de[n][NUM_SERVERS];
    Status status_de[n][NUM_SERVERS];
    int count_verify = 0;
    int count_n = 0;

    for (int i = 0; i < n; i++)
    {
        int m = 2 + i;
        // cout << "m = " << m << ": " << endl;

        for (int j = 0; j < NUM_SERVERS; j++)
        {
            reqs_de[i][j].set_dm((uint8_t *)d, sizeof(uint128_t) * length);
            reqs_de[i][j].set_em((uint8_t *)e, sizeof(uint128_t) * length);
            string num = to_string(m);

            // cout << "sizeof num: " << sizeof(num) << endl;
            reqs_de[i][j].set_num(num);
            // cout << "Doing SendDEshare[" << i << "]->SendDEshare " << "to server[" << j << "]..." << endl;
            status_de[i][j] = queryStubs[j]->SendDEshare(&ctxs_de[i][j], reqs_de[i][j], &resps_de[i][j]);
        }

        memset(d, 0, sizeof(uint128_t) * length);
        memset(e, 0, sizeof(uint128_t) * length);
        // cout << "d[1](0): " << d[1] << endl;
        // cout << "e[1](0): " << e[1] << endl;
        for (int j = 0; j < NUM_SERVERS; j++)
        {
            if (status_de[i][j].ok())
            {
                // cout << "                   [" << "server: " << j << "]                   " << endl;

                const uint128_t *d_j = (const uint128_t *)resps_de[i][j].d_j().c_str();
                const uint128_t *e_j = (const uint128_t *)resps_de[i][j].e_j().c_str();
                // cout << "d_" << j << "[1]: " << d_j[1] << endl;
                // cout << "e_" << j << "[1]: " << e_j[1] << endl;

                for (int j = 0; j < length; j++)
                {
                    d[j] = (d[j] + d_j[j]); // in for (int j = 0; j < NUM_SERVERS; j++), “the first share（0）+ the second share”（d_j） added twice
                    // d[j] += list_a[j];
                    // cout << "------------------d[j]:--------------------- " << d[j] << endl;
                    e[j] = (e[j] + e_j[j]);
                    // cout << "------------------e[1]:--------------------- " << e[j] << endl;
                }

                // cout << "d[1]: " << d[1] << endl;
                // cout << "e[1]: " << e[1] << endl;
            }
            else
            {
                cout << "ERROR receiving message " << status_de[i][j].error_message().c_str() << endl;
            }
        }

        count_n++;
        for (int j = 0; j < length; j++)
        { // only + one times（combined b，is not shares）

            e[j] += list_b[j];
            Ve[j] = Answer(e[j], d[j], x, M_SIZE, N_SIZE, X);

            if (Verify(x, N_SIZE, M_SIZE, X, e[j]) == 1)
            {
                count_verify++;
                // std::cout << " ==========Verify Passed=========== " << std::endl;
                // std::cout <<  "|";
                // Refresh(x, M, N, Vd[v]);
            }
            // else
            // {
            //     std::cout << " ==========Verify Not Passed=========== " << std::endl;
            // }
            // cout << "------------------Ve[j]:--------------------- " << Ve[j] << endl;
            e[j] = Ve[j] - list_b[j];
        }
    }
    if (count_verify == length * count_n)
    {
        std::cout << ">> All Verify Passed" << std::endl;
    }
    else
    {
        std::cout << ">> Some Verify Not Passed" << std::endl;
    }
    // STOP_TIMER("send d e, get d_ and e_ and compute d e(AND 3~)");

    // INIT_TIMER;
    // START_TIMER;
    // The client sends d, e to the server, the server calculates z0, z1 (cout shares)
    // and then takes z0, z1 and valist0, valist1 as the new x0 x1, y0 y1 calculates the new d0 e0, d1 e1 and sends them to the client,
    // the client gets the d0 e0, d1 e1 and calculates the dv ev
    // cout << "===================== send d e, get d_ and e_ and compute d e(SUM) =====================" << endl;
    ZshareRequest req[NUM_SERVERS];
    ZshareResponse resp[NUM_SERVERS];
    ClientContext Context[NUM_SERVERS];
    Status st[NUM_SERVERS];

    for (int i = 0; i < NUM_SERVERS; i++)
    {
        req[i].set_d((uint8_t *)d, sizeof(uint128_t) * length);
        req[i].set_e((uint8_t *)e, sizeof(uint128_t) * length);
        req[i].set_agg_id(agg_id);

        // cout << "sizeof agg_id: " << sizeof(agg_id) << endl;
        // cout << "Doing GetZshare[" << i << "]->SendGetZshare..." << endl;
        st[i] = queryStubs[i]->SendGetZshare(&Context[i], req[i], &resp[i]);
    }

    uint128_t *dv = (uint128_t *)malloc(sizeof(uint128_t) * length);
    uint128_t *ev = (uint128_t *)malloc(sizeof(uint128_t) * length);
    memset(dv, 0, sizeof(uint128_t) * length);
    memset(ev, 0, sizeof(uint128_t) * length);
    for (int i = 0; i < NUM_SERVERS; i++)
    {
        if (st[i].ok())
        {
            // cout << "                   [" << "server: " << i << "]                   " << endl;
            // int len = resp[i].dv_i().size()/sizeof(uint128_t);

            const uint128_t *dv_i = (const uint128_t *)resp[i].dv_i().c_str();
            const uint128_t *ev_i = (const uint128_t *)resp[i].ev_i().c_str();
            // cout << "dv_" << i << "[1]: " << dv_i[1] << endl;
            // cout << "ev_" << i << "[1]: " << ev_i[1] << endl;

            for (int j = 0; j < length; j++)
            {
                dv[j] = (dv[j] + dv_i[j]);
                ev[j] = (ev[j] + ev_i[j]);
            }
            // cout << "dv[1]: " << dv[1] << endl;
            // cout << "ev[1]: " << ev[1] << endl;
        }
        else
        {
            cout << "ERROR receiving message " << st[i].error_message().c_str() << endl;
        }
    }

    // The client sends dv, ev to the server, the two servers each calculate z0, z1 windowsize columns add up the results,
    // the client add up to get the final sum results
    // cout << "===================== send d e and get the result =====================" << endl;
    AggRequest req1[NUM_SERVERS];
    AggResponse resp1[NUM_SERVERS];
    ClientContext Context1[NUM_SERVERS];
    Status st1[NUM_SERVERS];
    uint128_t ret = 0;

    for (int i = 0; i < NUM_SERVERS; i++)
    {
        req1[i].set_dv((uint8_t *)dv, sizeof(uint128_t) * length);
        req1[i].set_ev((uint8_t *)ev, sizeof(uint128_t) * length);
        // cout << "Doing SendAgg[" << i << "]->SendAgg..." << endl;
        st1[i] = queryStubs[i]->SendAgg(&Context1[i], req1[i], &resp1[i]);
    }

    for (int i = 0; i < NUM_SERVERS; i++)
    {
        if (st1[i].ok())
        {
            cout << "[" << "server " << i << "]" << endl;
            uint128_t res;
            memcpy((uint8_t *)&res, (const uint8_t *)resp1[i].res().c_str(), sizeof(uint128_t));
            ret += res;
            cout << "res" << i << ": " << res << endl;
        }
        else
        {
            cout << "ERROR receiving message " << st1[i].error_message().c_str() << endl;
        }
    }

    // STOP_TIMER("Sum");
    return ret;
}

void QueryClient::GenerateCombinedFilter(Expression *expr, CombinedFilter *filters[])
{
    for (int i = 0; i < expr->conds.size(); i++)
    {
        // cout << "generating filter for cond " << i << endl;
        BaseFilter *tmp[2];
        for (int j = 0; j < NUM_SERVERS; j++)
        {
            tmp[j] = filters[j]->add_base_filters();
        }
        GenerateBaseFilter(&expr->conds[i], tmp); // Query times
    }
    // cout << "generated all base filters" << endl;
    filters[0]->set_op_is_and(expr->op_type == AND_OP);
    filters[1]->set_op_is_and(expr->op_type == AND_OP);
}

void QueryClient::GenerateBaseFilter(Condition *cond, BaseFilter *filters[])
{
    if (cond->cond_type == POINT_COND)
    {
        GenerateSPPFilter(cond->table_id, cond->x, filters); // number of predicates
    }
}

void QueryClient::GenerateSPPFilter(string id, uint32_t x, BaseFilter *filters[])
{
    // uint8_t *k[NUM_SERVERS];
    vector<int> S_l;
    vector<int> S_h;
    struct timeval t01, t02;
    gettimeofday(&t01, NULL);

    Query(x, M_SIZE, N_SIZE);

    gettimeofday(&t02, NULL);
    double Query_time = ((t01.tv_sec - t02.tv_sec) * 1000000.0 + t02.tv_usec - t01.tv_usec) / 1.000;
    // cout << "====================Query_time compute filter====================(us): " << Query_time << endl;

    for (int i = 0; i < NUM_SERVERS; i++)
    {
        filters[i]->set_id(id);
        // filters[i]->set_key0(k[i], key_len);
        for (int u = 0; u < N_SIZE / 2; u++)
        {
            filters[i]->add_s1(r[hj.j].S_l[u]);
            filters[i]->add_s2(r[hj.j].S_h[u]);
        }
        filters[i]->set_is_point(true);
    }
}

uint128_t QueryClient::GetMACAlpha()
{
    return alpha;
}
