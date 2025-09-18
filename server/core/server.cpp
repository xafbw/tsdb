#include <fstream>
#include <thread>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <cryptoTools/Crypto/AES.h>
#include "../../secure-indices/core/DCFTable.h"
#include "../../secure-indices/core/DPFTable.h"
#include "../../secure-indices/core/AggTree.h"
#include "../../network/core/query.grpc.pb.h"
#include "../../network/core/query.pb.h"
#include "../../secure-indices/core/common.h"
#include "../../utils/json.hpp"
#include "../../utils/config.h"
#include "../../utils/dorydbconfig.h"
#include "server.h"
#include "network-emp/core/io_channel.h"
#include "network-emp/core/net_io_channel.h"
#include "network-emp/core/highspeed_net_io_channel.h"
#include <cstdlib>

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
using dbquery::InitSystemRequest;
using dbquery::InitSystemResponse;
using dbquery::MultRequest;
using dbquery::MultResponse;
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
using grpc::ChannelArguments;
using grpc::ClientContext;
using grpc::Server;
using grpc::ServerAsyncResponseWriter;
using grpc::ServerBuilder;
using grpc::ServerCompletionQueue;
using grpc::ServerContext;
using grpc::Status;
using json = nlohmann::json;
using namespace std;
using namespace osuCrypto;
using namespace emp;

NetIO *emp_io_upstream;
NetIO *emp_io_downstream;

#define WS 16 // 2^log_windowsize

QueryServer::QueryServer(string addrs[], int serverID, int cores, bool malicious)
{
    this->serverID = serverID;
    this->malicious = malicious;
    this->cores = cores;
    block seed = toBlock(rand(), rand());
    PRNG prng(seed);
    prfKey0 = prng.get<uint64_t>();
    prfCounter = 0;
    multReceivedShares0 = NULL;
    multReceivedShares1 = NULL;
}

void QueryServer::StartSystemInit(string addrs[])
{
    new CallData(*this, service, cq, INIT);
    sleep(5);

    ChannelArguments args;
    args.SetMaxSendMessageSize(-1);
    args.SetMaxReceiveMessageSize(-1);
    nextServerStub = Query::NewStub(grpc::CreateCustomChannel(addrs[(serverID + 1) % NUM_SERVERS], grpc::InsecureChannelCredentials(), args));
    multStub = Aggregate::NewStub(grpc::CreateCustomChannel(addrs[(serverID + 1) % NUM_SERVERS], grpc::InsecureChannelCredentials(), args));
    cout << "connected to " << addrs[(serverID + 1) % NUM_SERVERS] << endl;

    int emp_port = 32000;

    string next_server_addr = addrs[(serverID + 1) % NUM_SERVERS];
    int psn = next_server_addr.find(":");
    next_server_addr = next_server_addr.substr(0, psn);

    if (serverID == 0)
    {
        cout << "setting up EMP connection as client on address, port " << next_server_addr << " " << (emp_port + serverID) << endl;
        emp_io_upstream = new NetIO(next_server_addr.c_str(), emp_port + serverID);
        cout << "setting up EMP connection as server on address, port " << "0.0.0.0" << " " << (emp_port + (1 % NUM_SERVERS)) << endl;
        emp_io_downstream = new NetIO(nullptr, emp_port + (1 % NUM_SERVERS));
    }
    else
    {
        cout << "setting up EMP connection as server on address, port " << "0.0.0.0" << " " << (emp_port + ((serverID - 1) % NUM_SERVERS)) << endl;
        emp_io_downstream = new NetIO(nullptr, emp_port + ((serverID - 1) % NUM_SERVERS));
        cout << "setting up EMP connection as client on address, port " << next_server_addr << " " << (emp_port + serverID) << endl;
        emp_io_upstream = new NetIO(next_server_addr.c_str(), emp_port + serverID);
    }

    cout << "connected EMP NetIO to " << next_server_addr << endl;

    InitSystemRequest req;
    InitSystemResponse resp;
    ClientContext ctx;
    req.set_key((char *)&prfKey0, sizeof(uint128_t));
    multStub->SendSystemInit(&ctx, req, &resp);
}

void QueryServer::FinishSystemInit(const uint8_t *key)
{
    memcpy((uint8_t *)&prfKey1, key, sizeof(uint128_t));
    cout << "----- DONE WITH SETUP ------" << endl;
}

void QueryServer::FinishMultiply(const uint128_t *shares0, const uint128_t *shares1, int len)
{
    unique_lock<mutex> lk(multLock);
    // multLock.lock();
    if (multReceivedShares0 != NULL || multReceivedShares1 != NULL)
    {
        new CallData(*this, service, cq, MULT);
    }
    while (multReceivedShares0 != NULL || multReceivedShares1 != NULL)
    {
        orderCV.wait(lk);
    }
    multReceivedShares0 = (uint128_t *)malloc(len);
    multReceivedShares1 = (uint128_t *)malloc(len);
    memcpy(multReceivedShares0, shares0, len);
    memcpy(multReceivedShares1, shares1, len);
    // cout << "multReceivedShares0: " << multReceivedShares0[0] << endl;
    multCV.notify_one();
}

void QueryServer::AddValList(string id, uint32_t windowSize)
{
    vector<uint128_t> list1(windowSize, 0);
    ValLists[id] = list1;
    ValListWindowPtrs[id] = 0;
}

void QueryServer::ValListUpdate(string id, uint32_t loc, uint128_t val0)
{
    if (loc == APPEND_LOC)
    {
        loc = ValListWindowPtrs[id];
        ValListWindowPtrs[id]++;
    }
    ValLists[id][loc] = val0;
}

void QueryServer::AddSPPTable(string id, uint32_t windowSize, uint32_t numBuckets, bool malicious)
{
    DPFTableServer *s1 = new DPFTableServer(id, getDepth(numBuckets), windowSize, cores, malicious);
    SPPTables[id] = s1;
    SPPTableWindowPtrs[id] = 0;
    vector<uint128_t> list_a(windowSize, 0);
    vector<uint128_t> list_b(windowSize, 0);
    vector<uint128_t> list_ab(windowSize, 0);
}

void QueryServer::SPPUpdate(string id, uint32_t loc, const uint128_t *data0, uint128_t a, uint128_t b, uint128_t ab)
{
    if (loc == APPEND_LOC)
    {
        loc = SPPTableWindowPtrs[id];
        SPPTableWindowPtrs[id]++;
    }
    setTableColumn(SPPTables[id]->table, loc, data0, SPPTables[id]->numBuckets);
    // cout << "ab_i: " << ab << endl;
    list_a.push_back(a);
    list_b.push_back(b);
    list_ab.push_back(ab);
    // cout << "ab_i: " << list_ab[loc] << endl;
}

void QueryServer::AggFilterQuery(string aggID, const CombinedFilter &filterSpec, uint128_t **d_i, uint128_t **e_i, int *len)
{
    // printf("Doing AggFilterQuery\n");
    uint128_t *filter0;
    uint128_t *filter1;
    *d_i = NULL;
    *e_i = NULL;
    int l = 0;
    string baseFilterID;
    BaseFilter baseFilterSpec = filterSpec.base_filters(0);
    baseFilterID = baseFilterSpec.id();
    l = SPPTables[baseFilterID]->windowSize;
    *len = l;
    // cout << "*len: " << *len << endl;

    printf("Doing EvalFilter\n");
    EvalFilter(&filter0, &filter1, filterSpec);
    // printf("Done EvalFilter\n");

    // cout << "filter0[1]: " << filter0[1] << endl;
    // cout << "filter1[1]: " << filter1[1] << endl;

    *d_i = filter0;
    *e_i = filter1;
}

RespPS* resPS = nullptr;

struct RespPSManager {
    RespPSManager() { init_resps_globals(); }
    ~RespPSManager() { free_resps_globals(); }
} _resps_manager;

void init_resps_globals() {
    resPS = new RespPS[WS];
}

void free_resps_globals() {
    delete[] resPS;
    resPS = nullptr;
}


void QueryServer::EvalFilter(uint128_t **filter0, uint128_t **filter1, const CombinedFilter &filterSpec)
{
    // INIT_TIMER;
    // START_TIMER;

    *filter0 = NULL;
    *filter1 = NULL;

    // assuming filters all of same type for now
    uint128_t **res0 = (uint128_t **)malloc(sizeof(uint128_t *) * filterSpec.base_filters_size());
    uint128_t **res1 = (uint128_t **)malloc(sizeof(uint128_t *) * filterSpec.base_filters_size());

    bool is_point = true;
    string baseFilterID;
    int len;
    // int cnttt = 0;
    for (int i = 0; i < filterSpec.base_filters_size(); i++)
    {
        BaseFilter baseFilterSpec = filterSpec.base_filters(i);
        baseFilterID = baseFilterSpec.id();
        int windowSize = SPPTables[baseFilterID]->windowSize;
        len = windowSize;

        res0[i] = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
        res1[i] = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
        memset(res0[i], 0, sizeof(uint128_t) * windowSize);
        memset(res1[i], 0, sizeof(uint128_t) * windowSize);

        vector<int> S_l;
        vector<int> S_h;
        for (int u1 = 0; u1 < baseFilterSpec.s1_size(); u1++)
        {
            S_l.push_back(baseFilterSpec.s1(u1));
            S_h.push_back(baseFilterSpec.s2(u1));
        }
        // for (int u2 = 0; u2 < baseFilterSpec.s1_size(); u2++)
        // {
        //     std::cout << " u=" << u2 << " S_l[u]=" << S_l[u2] << std::endl;
        //     std::cout << " u=" << u2 << " S_h[u]=" << S_h[u2] << std::endl;
        // }

        struct timeval t10, t20;
        gettimeofday(&t10, NULL);

        for (int v = 0; v < len; v++)
        {
            resPS[v].Pj = 0;
            resPS[v].Pj_ = 0;
        }

        tb = SPPTables[baseFilterID]->table;
        for (int u = 0; u < sqrt(SPPTables[baseFilterID]->numBuckets) / 2; u++)
        {
            // resPS.Pj += temp[S_l[u]].D;
            for (int v = 0; v < len; v++)
            {
                resPS[v].Pj += tb[S_l[u]][v];
                // std::cout << " u=" << u << " S_l[u]=" << S_l[u] <<" D[S_l[u]]=" << tb[S_l[u]][v] << std::endl;
            }
        }
        for (int u = 0; u < sqrt(SPPTables[baseFilterID]->numBuckets) / 2; u++)
        {
            for (int v = 0; v < len; v++)
            {
                resPS[v].Pj_ += tb[S_h[u]][v];
                // resPS.Pj_ += temp[S_h[u]].D;
                // std::cout << " u=" << u << " S_h[u]=" << S_h[u] <<" D[S_h[u]]=" << tb[S_l[u]][v] << std::endl;
            }
        }

        gettimeofday(&t20, NULL);
        double Answer_time = ((t20.tv_sec - t10.tv_sec) * 1000000.0 + t20.tv_usec - t10.tv_usec) / 1.000;
        // cout << "====================Answer_time=====================(us): " << Answer_time << endl;

        for (int v = 0; v < len; v++)
        {
            res0[i][v] = resPS[v].Pj;
        }
    }
    // STOP_TIMER("Eval_dpf_table");
    // cout << "Done parallel_eval_dpf_table" << endl;
    // cout << "----------------------cnttt-------------------------"<< cnttt << endl;

    // cout << "Doing copy res0 -> res_g" << endl;
    res_g = (uint128_t **)malloc(sizeof(uint128_t *) * filterSpec.base_filters_size());
    for (int i = 0; i < filterSpec.base_filters_size(); i++)
    {
        int windowSize = SPPTables[baseFilterID]->windowSize;
        res_g[i] = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
        memcpy(res_g[i], res0[i], sizeof(uint128_t) * windowSize);
    }
    // cout << "res_g[1][1]: " << res_g[1][1] << endl;
    // cout << "=-===================res0[1][1]: ======================" << res0[1][1] << endl;
    // cout << "Done copy res0 -> res_g" << endl;

    // cout << "Doing AndFilters" << endl;
    for (int i = 0; i < 2; i++)
    {
        BaseFilter baseFilterSpec = filterSpec.base_filters(i);
        int len = SPPTables[baseFilterSpec.id()]->windowSize;
        // cout << "i: " << i << endl;

        if (*filter0 != NULL)
        {
            uint128_t *tmp0 = (uint128_t *)malloc(sizeof(uint128_t) * len);
            memcpy(tmp0, *filter0, sizeof(uint128_t) * len);
            if (filterSpec.op_is_and())
            {
                // cout << "Before AndFilters"<< endl;
                AndFilters(*filter0, *filter1, tmp0, res0[i], len);
            } /* else {
                OrFilters(*filter0, *filter1, tmp0, res0[i], len);
            } */
            free(tmp0);
            free(res0[i]);
        }
        else
        {
            *filter0 = res0[i];
            *filter1 = res1[i];
        }
    }
    // cout << "Done AndFilters" << endl;
}

//*filter0,              *filter1,           tmp0  res0[i-1],           res0[i],      len
void QueryServer::AndFilters(uint128_t *shares_out0, uint128_t *shares_out1, uint128_t *shares_x0, uint128_t *shares_y0, int len)
{
    Multiply(shares_out0, shares_out1, shares_x0, shares_y0, len);
}

/* void QueryServer::OrFilters(uint128_t *shares_out0, uint128_t *shares_out1, uint128_t *shares_x0, uint128_t *shares_y0, int len) {
    Multiply(shares_out0, shares_out1, shares_x0, shares_y0, len, d_i, e_i);
    for (int i = 0; i < len; i++) {
        shares_out0[i] += shares_x0[i] + shares_y0[i];
    }
} */

void QueryServer::Multiply(uint128_t *shares_out0, uint128_t *shares_out1, uint128_t *shares_x0, uint128_t *shares_y0, int len)
{
    int val_len = malicious ? len / 2 : len;
    uint128_t *d = (uint128_t *)malloc(val_len * sizeof(uint128_t));
    uint128_t *e = (uint128_t *)malloc(val_len * sizeof(uint128_t));

    // cout << "shares_x0[1](res0[1][1])" << shares_x0[0] << endl;
    // cout << "shares_y0[1](res0[1][1])" << shares_y0[0] << endl;

    // cout << "Doing Multiply" << endl;
    for (int i = 0; i < val_len; i++)
    {
        // cout << "i:" << i << endl;
        d[i] = shares_x0[i] - list_a[i];
        e[i] = shares_y0[i] - list_b[i];
        shares_out0[i] = d[i];
        shares_out1[i] = e[i];
    }
    // cout << "share_d[1]: " << d[1] << endl;
    // cout << "share_e[1]: " << e[1] << endl;

    // cout << "shares_out d[1]: " << shares_out0[1] << endl;
    // cout << "shares_out e[1]: " << shares_out1[1] << endl;

    // cout << "Done Multiply" << endl;
}

void QueryServer::DEshare(const uint128_t *d1, const uint128_t *e1, int n, int len, uint128_t **d_j, uint128_t **e_j)
{
    uint128_t *d = (uint128_t *)malloc(len);
    uint128_t *e = (uint128_t *)malloc(len);
    uint128_t *z = (uint128_t *)malloc(len);
    memcpy(d, d1, len);
    memcpy(e, e1, len);
    memset(z, 0, len);
    int l = sizeof(uint128_t);
    int val_len = len / l;

    // cout << "d[1]: " << d[1] << endl;
    // cout << "e[1]: " << e[1] << endl;

    for (int i = 0; i < val_len; i++)
    {
        if (serverID == 0)
        {
            z[i] = (d[i] * e[i] + d[i] * list_b[i] + e[i] * list_a[i] + list_ab[i]);
        }
        else
        {
            z[i] = (d[i] * list_b[i] + e[i] * list_a[i] + list_ab[i]);
        }
        // cout << "z[" << i << "]: " << z[i] << endl;
    }
    // cout << "z[1]: " << z[1] << endl;

    uint128_t *dj = (uint128_t *)malloc(len);
    uint128_t *ej = (uint128_t *)malloc(len);
    memset(dj, 0, len);
    memset(ej, 0, len);

    // cout << "n: " << n << endl;
    for (int i = 0; i < val_len; i++)
    {
        // cout << "i:" << i << endl;
        dj[i] = (z[i] - list_a[i]);
        ej[i] = (res_g[n][i] - list_b[i]); // P = res0 = 000000
    }
    // cout << "dj[1]: " << dj[1] << endl;
    // cout << "ej[1]: " << ej[1] << endl;

    *d_j = dj;
    *e_j = ej;
}

void QueryServer::GetZshare(const uint128_t *d1, const uint128_t *e1, int len, uint128_t **dv_i, uint128_t **ev_i, string aggID)
{
    uint128_t *d = (uint128_t *)malloc(len);
    uint128_t *e = (uint128_t *)malloc(len);
    uint128_t *z0 = (uint128_t *)malloc(len);
    memcpy(d, d1, len);
    memcpy(e, e1, len);
    memset(z0, 0, len);
    int l = sizeof(uint128_t);
    int val_len = len / l;

    // cout << "d[1]: " << d[1] << endl;
    // cout << "e[1]: " << e[1] << endl;

    for (int i = 0; i < val_len; i++)
    {
        if (serverID == 0)
        {
            z0[i] = (d[i] * e[i] + d[i] * list_b[i] + e[i] * list_a[i] + list_ab[i]);
        }
        else
        {
            z0[i] = (d[i] * list_b[i] + e[i] * list_a[i] + list_ab[i]);
        }
        // cout << "z0[" << i << "]: " << z0[i] << endl;
    }
    // cout << "z0[1]: " << z0[1] << endl;

    uint128_t *dv = (uint128_t *)malloc(len);
    uint128_t *ev = (uint128_t *)malloc(len);
    memset(dv, 0, len);
    memset(ev, 0, len);

    for (int i = 0; i < val_len; i++)
    {
        dv[i] = (z0[i] - list_a[i]);
        ev[i] = (ValLists[aggID][i] - list_b[i]);
    }
    // cout << "dv[1]: " << dv[1] << endl;
    // cout << "ev[1]: " << ev[1] << endl;

    *dv_i = dv;
    *ev_i = ev;
}

void QueryServer::Aggregate(const uint128_t *d1, const uint128_t *e1, int len, uint128_t *res)
{
    *res = 0;
    uint128_t *dv = (uint128_t *)malloc(len);
    uint128_t *ev = (uint128_t *)malloc(len);
    uint128_t *zi = (uint128_t *)malloc(len);
    memcpy(dv, d1, len);
    memcpy(ev, e1, len);
    memset(zi, 0, len);
    int l = sizeof(uint128_t);
    int val_len = len / l;

    // cout << "dv[1]: " << dv[1] << endl;
    // cout << "ev[1]: " << ev[1] << endl;

    for (int i = 0; i < val_len; i++)
    {
        if (serverID == 0)
        {
            zi[i] = (dv[i] * ev[i] + dv[i] * list_b[i] + ev[i] * list_a[i] + list_ab[i]);
        }
        else
        {
            zi[i] = (dv[i] * list_b[i] + ev[i] * list_a[i] + list_ab[i]);
        }
        // cout << "zi[" << i << "]: " << zi[i] << endl;
    }
    // cout << "zi[1]: " << zi[1] << endl;

    for (int i = 0; i < val_len; i++)
    {
        *res += zi[i];
    }
}

CallData::CallData(QueryServer &server, Aggregate::AsyncService *service, ServerCompletionQueue *cq, RpcType type) : server(server), service(service), cq(cq), responderMult(&ctx), responderInit(&ctx), status(CREATE), type(type)
{
    Proceed();
}

void CallData::Proceed()
{
    if (status == CREATE)
    {
        status = PROCESS;
        if (type == MULT)
        {
            service->RequestSendMult(&ctx, &reqMult, &responderMult, cq, cq, this);
        }
        else if (type == INIT)
        {
            service->RequestSendSystemInit(&ctx, &reqInit, &responderInit, cq, cq, this);
        }
    }
    else if (status == PROCESS)
    {
        if (type == MULT)
        {
            new CallData(server, service, cq, MULT);
            server.FinishMultiply((const uint128_t *)reqMult.shares0().c_str(), (const uint128_t *)reqMult.shares1().c_str(), reqMult.shares0().size());
            responderMult.Finish(respMult, Status::OK, this);
        }
        else if (type == INIT)
        {
            new CallData(server, service, cq, INIT);
            server.FinishSystemInit((const uint8_t *)reqInit.key().c_str());
            responderInit.Finish(respInit, Status::OK, this);
        }
        status = FINISH;
    }
    else
    {
        assert(status == FINISH);
        delete this;
    }
}

class QueryServiceImpl final : public Query::Service
{
public:
    QueryServer &server;

    QueryServiceImpl(QueryServer &server) : server(server) {}

    Status SendListInit(ServerContext *context, const InitListRequest *req, InitListResponse *resp) override
    {
        printf("Doing ListInit\n");
        server.AddValList(req->id(), req->window_size());
        // printf("Done ListInit\n");
        return Status::OK;
    }

    Status SendListBatchedUpdate(ServerContext *context, const BatchedUpdateListRequest *req, BatchedUpdateListResponse *resp) override
    {
        printf("Doing ListBatchedUpdate\n");
        for (int i = 0; i < req->updates_size(); i++)
        {
            uint128_t val0;
            memcpy((uint8_t *)&val0, req->updates(i).share0().c_str(), sizeof(uint128_t));
            server.ValListUpdate(req->updates(i).id(), req->updates(i).val(), val0);
        }
        // printf("Done ListBatchedUpdate\n");
        return Status::OK;
    }

    Status SendListUpdate(ServerContext *context, const UpdateListRequest *req, UpdateListResponse *resp) override
    {
        uint128_t val0;
        memcpy((uint8_t *)&val0, req->share0().c_str(), sizeof(uint128_t));
        server.ValListUpdate(req->id(), req->val(), val0);
        return Status::OK;
    }

    Status SendSPPInit(ServerContext *context, const InitSPPRequest *req, InitSPPResponse *resp) override
    {
        printf("Doing SPPInit\n");
        server.AddSPPTable(req->id(), req->window_size(), req->num_buckets(), server.malicious);
        // printf("Done SPPInit\n");
        return Status::OK;
    }

    Status SendSPPBatchedUpdate(ServerContext *context, const BatchedUpdateSPPRequest *req, BatchedUpdateSPPResponse *resp) override
    {
        printf("Doing SPPBatchedUpdate\n");
        for (int i = 0; i < req->updates_size(); i++)
        {
            uint128_t a;
            uint128_t b;
            uint128_t ab;
            memcpy((uint8_t *)&a, req->updates(i).a().c_str(), sizeof(uint128_t));
            memcpy((uint8_t *)&b, req->updates(i).b().c_str(), sizeof(uint128_t));
            memcpy((uint8_t *)&ab, req->updates(i).ab().c_str(), sizeof(uint128_t));
            server.SPPUpdate(req->updates(i).id(), req->updates(i).val(), (const uint128_t *)req->updates(i).data0().c_str(), a, b, ab);
        }
        // printf("Done SPPBatchedUpdate\n");
        return Status::OK;
    }

    Status SendSPPUpdate(ServerContext *context, const UpdateSPPRequest *req, UpdateSPPResponse *resp) override
    {
        printf("Doing SPPUpdate\n");
        uint128_t a;
        uint128_t b;
        uint128_t ab;
        memcpy((uint8_t *)&a, req->a().c_str(), sizeof(uint128_t));
        memcpy((uint8_t *)&b, req->b().c_str(), sizeof(uint128_t));
        memcpy((uint8_t *)&ab, req->ab().c_str(), sizeof(uint128_t));
        server.SPPUpdate(req->id(), req->val(), (const uint128_t *)req->data0().c_str(), a, b, ab);
        // printf("Done SPPUpdate\n");
        return Status::OK;
    }

    Status SendAggQuery(ServerContext *context, const QueryAggRequest *req, QueryAggResponse *resp)
    {
        printf("Received aggregate query\n");
        uint128_t *d_i;
        uint128_t *e_i;
        int len = 0;

        server.AggFilterQuery(req->agg_id(), req->combined_filter(), &d_i, &e_i, &len);
        cout << "Done AggFilterQuery" << endl;
        // cout << "len: " << len << endl;
        // cout << "d_i[1]: " << d_i[1] << endl;
        // cout << "e_i[1]: " << e_i[1] << endl;

        resp->set_d_i((uint8_t *)d_i, sizeof(uint128_t) * len);
        resp->set_e_i((uint8_t *)e_i, sizeof(uint128_t) * len);
        // printf("Done d_i and e_i\n");

        for (int v = 0; v < len; v++)
        {
            // PjSum += resPS[v].Pj;
            resp->add_p1((uint8_t *)&(resPS[v].Pj), sizeof(uint128_t));
            // std::cout <<  " resP.Pj============" << resPS[v].Pj << std::endl;
            //  PjSum_ += resPS[v].Pj_;
            resp->add_p2((uint8_t *)&(resPS[v].Pj_), sizeof(uint128_t));
            // std::cout <<  " resP.Pj_===========" << resPS[v].Pj_ << std::endl;
        }
        resp->set_leng0(len); // return Pj(size:windowsize)

        return Status::OK;
    }

    Status SendDEshare(ServerContext *context, const DEshareRequest *req, DEshareResponse *resp) override
    {
        printf("Doing GetDEshare\n");
        uint128_t *d_j;
        uint128_t *e_j;
        int len = req->dm().size();

        string str = req->num();
        int num = stoi(str);

        server.DEshare((const uint128_t *)req->dm().c_str(), (const uint128_t *)req->em().c_str(), num, len, &d_j, &e_j);
        // cout << "d_j[1]: " << d_j[1] << endl;
        // cout << "e_j[1]: " << e_j[1] << endl;

        resp->set_d_j((uint8_t *)d_j, len);
        resp->set_e_j((uint8_t *)e_j, len);

        // cout << "sizeof d_j: " << len << " B" << endl;
        // cout << "sizeof e_j: " << len << " B" << endl;
        // printf("Done GetDEshare\n");
        return Status::OK;
    }

    Status SendGetZshare(ServerContext *context, const ZshareRequest *req, ZshareResponse *resp) override
    {
        printf("Doing GetZshare\n");
        uint128_t *dv_i;
        uint128_t *ev_i;
        int len = req->d().size();
        server.GetZshare((const uint128_t *)req->d().c_str(), (const uint128_t *)req->e().c_str(), len, &dv_i, &ev_i, req->agg_id());
        // cout << "dv_i[1]: " << dv_i[1] << endl;
        // cout << "ev_i[1]: " << ev_i[1] << endl;
        resp->set_dv_i((uint8_t *)dv_i, len);
        resp->set_ev_i((uint8_t *)ev_i, len);

        // cout << "sizeof dv_i: " << len << " B" << endl;
        // cout << "sizeof ev_i: " << len << " B" << endl;
        // printf("Done GetZshare\n");
        return Status::OK;
    }

    Status SendAgg(ServerContext *context, const AggRequest *req, AggResponse *resp) override
    {
        printf("Doing Aggregate\n");
        uint128_t res;
        int len = req->dv().size();
        server.Aggregate((const uint128_t *)req->dv().c_str(), (const uint128_t *)req->ev().c_str(), len, &res);
        cout << "res: " << res << endl;
        resp->set_res((uint8_t *)&res, sizeof(uint128_t));
        printf("Finished processing aggregate query\n");
        return Status::OK;
    }
};

void handleAsyncRpcs(QueryServer &server, Aggregate::AsyncService &service, unique_ptr<ServerCompletionQueue> &cq)
{
    new CallData(server, &service, cq.get(), INIT);
    new CallData(server, &service, cq.get(), MULT);
    void *tag;
    bool ok;
    while (true)
    {
        assert(cq->Next(&tag, &ok));
        assert(ok);
        static_cast<CallData *>(tag)->Proceed();
    }
}

void runServer(string publicAddrs[], string bindAddr, int serverID, int cores, bool malicious)
{
    QueryServer s(publicAddrs, serverID, cores, malicious);
    QueryServiceImpl queryService(s);
    Aggregate::AsyncService asyncService;

    grpc::EnableDefaultHealthCheckService(true);
    grpc::reflection::InitProtoReflectionServerBuilderPlugin();

    ServerBuilder queryBuilder;
    queryBuilder.SetMaxReceiveMessageSize(-1);
    queryBuilder.AddListeningPort(bindAddr, grpc::InsecureServerCredentials());
    queryBuilder.RegisterService(&queryService);
    queryBuilder.RegisterService(&asyncService);
    unique_ptr<ServerCompletionQueue> cq(queryBuilder.AddCompletionQueue());
    unique_ptr<Server> queryServer(queryBuilder.BuildAndStart());

    s.service = &asyncService;
    s.cq = cq.get();
    thread t(handleAsyncRpcs, ref(s), ref(asyncService), ref(cq));
    s.StartSystemInit(publicAddrs);
    t.join();
}

int main(int argc, char *argv[])
{
    ifstream config_stream(argv[1]);
    json config;
    config_stream >> config;

    string addrs[NUM_SERVERS];
    for (int i = 0; i < NUM_SERVERS; i++)
    {
        addrs[i] = config[ADDRS][i];
    }
    string bindAddr = "0.0.0.0:" + string(config[PORT]);
    assert(argc == 2);
    int server_num = config[SERVER_NUM];
    assert(server_num == 0 || server_num == 1);
    bool malicious = 0; // malicious
    runServer(addrs, bindAddr, server_num, config[CORES], malicious);
}
