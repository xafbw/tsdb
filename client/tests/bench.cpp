#include <string>
#include <vector>
#include <fstream>
#include "../core/client.h"
#include "../core/query.h"
#include "../../secure-indices/core/common.h"
#include "../../utils/json.hpp"
#include "../../utils/config.h"

using grpc::Channel;
using json = nlohmann::json;
using namespace dorydb;
using namespace std;

bool simPraPirTest(QueryClient *client, int numBuckets, int windowSize, int numConds, int reps, vector<uint32_t> &times, string dir)
{
    QueryObj q;
    q.agg_table_id = "test_vals";
    vector<Condition> conds;
    for (int i = 0; i < numConds; i++)
    {
        Condition cond;
        cond.table_id = "test_spp";
        cond.cond_type = POINT_COND;
        cond.x = 1;
        conds.push_back(cond);
    }
    Expression expr;
    expr.op_type = numConds == 1 ? NO_OP : AND_OP;
    vector<Expression> emptyExprs;
    expr.exprs = emptyExprs;
    expr.conds = conds;
    q.expr = &expr;

    
    float totalMI = 0.0;
    float avgMI = 0.0;
    float avgI = 0.0;
    for (int i = 0; i < reps; i++) {
        INIT_TIMER;
        START_TIMER;
            
        vector<uint128_t> dataVals(windowSize, (uint128_t)1);
        vector<uint32_t> simPraPirVals(windowSize, (uint32_t)1);
    
        cout << "Doing AddValList..." << endl;
        client->AddValList(string("test_vals"), windowSize, dataVals);
        cout << "Doing AddSPPTable..." << endl;
        client->AddSPPTable(string("test_spp"), windowSize, numBuckets, simPraPirVals);
        
        uint32_t time = STOP_TIMER_();
        times.push_back(time);
        cout << "********************************************" << endl;
        cout << "reps[" << i << "]: " << time << " milliseconds" << endl;
        totalMI += time;
        avgMI = totalMI/reps;
        avgI = avgMI/1000;
        //STOP_TIMER("AggQuery");
    }
    cout << "######################################################################################" << endl;
    cout << "totalMI: " << totalMI << " milliseconds" << endl;
    //cout << "avgMs: " << avgMs << " milliseconds" << endl;
    cout << "avgMI: " << fixed << setprecision(3) << avgMI << " milliseconds" << endl;
    cout << "avgI: " << fixed << setprecision(5) << avgI << " seconds" << endl;
    cout << "######################################################################################" << endl;

    // test for AddValList and AddSPPTable
    /*
    float totalMs = 0.0;
    float avgMs = 0.0;
    float avgS = 0.0;
    for (int i = 0; i < reps; i++) {
        cout << "Doing AddValList..." << endl;
        INIT_TIMER;
        START_TIMER;
        client->AddValList(string("test_vals"), windowSize, dataVals);
        cout << "Doing AddSPPTable..." << endl;
        client->AddSPPTable(string("test_dpf"), windowSize, numBuckets, simPraPirVals);
        uint32_t time = STOP_TIMER_();
        cout << "*********************************************************" << endl;
        cout << "reps[" << i << "]: " << time << " milliseconds" << endl;
        cout << "*********************************************************" << endl;
        totalMs += time;
    }
    avgMs = totalMs/reps;
    avgS = avgMs/1000;
    times.push_back(avgS);
    cout << "============================================================" << endl;
    cout << "totalMs: " << totalMs << " milliseconds" << endl;
    //cout << "avgMs: " << avgMs << " milliseconds" << endl;
    cout << "avgMs: " << fixed << setprecision(3) << avgMs << " milliseconds" << endl;
    cout << "avgS: " << fixed << setprecision(5) << avgS << " seconds" << endl;
    cout << "============================================================" << endl;
    */

    // test for AggQuery
    float totalMs = 0.0;
    float avgMs = 0.0;
    float avgS = 0.0;
    for (int i = 0; i < reps; i++)
    {
        INIT_TIMER;
        START_TIMER;
        cout << "Doing AggQuery..." << endl;
        uint128_t agg = client->AggQuery(q.agg_table_id, q);
        cout << ">> AggQuery = " << agg << endl;
        uint32_t time = STOP_TIMER_();
        times.push_back(time);
        cout << "************************************************************" << endl;
        cout << "reps[" << i << "]: " << time << " milliseconds" << endl;
        cout << "************************************************************" << endl;
        totalMs += time;
        // STOP_TIMER("AggQuery");
    }
    avgMs = totalMs / reps;
    avgS = avgMs / 1000;
    cout << "============================================================" << endl;
    cout << "totalMs: " << totalMs << " milliseconds" << endl;
    // cout << "avgMs: " << avgMs << " milliseconds" << endl;
    cout << "avgMs: " << fixed << setprecision(3) << avgMs << " milliseconds" << endl;
    cout << "avgS: " << fixed << setprecision(5) << avgS << " seconds" << endl;
    cout << "============================================================" << endl;

    int logWindowSize = log2(windowSize);
    ofstream file(dir, ios::app);
    if (file.is_open())
    {
        file << logWindowSize << " " << numConds << " " << avgS << endl;
    }

    cout << "######################### DONE #############################" << endl;
}

bool simPraPirThroughput(QueryClient *client, int numBuckets, int windowSize, int numConds, vector<uint32_t> &times, int numAppends, int numSearches, int seconds, string dir)
{
    QueryObj q;
    q.agg_table_id = "test_vals";
    vector<Condition> conds;
    for (int i = 0; i < numConds; i++)
    {
        Condition cond;
        cond.table_id = "test_spp";
        cond.cond_type = POINT_COND;
        cond.x = 1;
        conds.push_back(cond);
    }
    Expression expr;
    expr.op_type = numConds == 1 ? NO_OP : AND_OP;
    vector<Expression> emptyExprs;
    expr.exprs = emptyExprs;
    expr.conds = conds;
    q.expr = &expr;

    vector<uint128_t> dataVals(windowSize, (uint128_t)1);
    vector<uint32_t> simPraPirVals(windowSize, (uint32_t)1);

    client->AddValList(string("test_vals"), windowSize, dataVals);
    client->AddSPPTable(string("test_spp"), windowSize, numBuckets, simPraPirVals);

    uint32_t totalMs = 0.0;

    while (totalMs < seconds * 1000)
    {
        for (int j = 0; j < numSearches && totalMs < seconds * 1000; j++)
        {
            INIT_TIMER;
            START_TIMER;
            uint128_t agg = client->AggQuery(q.agg_table_id, q);
            uint32_t time = STOP_TIMER_();
            times.push_back(time);
            totalMs += time;
        }
        for (int j = 0; j < numAppends && totalMs < seconds * 1000; j++)
        {
            INIT_TIMER;
            START_TIMER;
            client->RunSPPUpdate("test_spp", 0, 1);
            uint32_t time = STOP_TIMER_();
            times.push_back(time);
            totalMs += time;
        }
    }

    ofstream file(dir);
    if (file.is_open())
    {
        for (int i = 0; i < times.size(); i++)
        {
            file << to_string(times[i]) << endl;
        }
    }
    cout << "====================================================" << endl;
}

int main(int argc, char *argv[])
{
    ifstream config_stream(argv[1]);
    json config;
    config_stream >> config;

    vector<shared_ptr<grpc::Channel>> channels;
    for (int i = 0; i < NUM_SERVERS; i++)
    {
        shared_ptr<grpc::Channel> channel = grpc::CreateChannel(config[ADDRS][i], grpc::InsecureChannelCredentials());
        channels.push_back(channel);
    }
    bool malicious = 0; // malicious
    QueryClient *client = new QueryClient(channels, malicious);

    int logNumBuckets = config[LOG_NUM_BUCKETS];
    int logWindowSize = config[LOG_WINDOW_SZ];
    int numBuckets = 1 << logNumBuckets;
    int windowSize = 1 << logWindowSize;
    // cout << "Type: " << config[TYPE] << endl;
    cout << "Predicates: " << config[NUM_ANDS] << endl;
    cout << "Window size: 2^" << logWindowSize << " = " << windowSize << endl;
    cout << "Num buckets: 2^" << logNumBuckets << " = " << numBuckets << endl;
    int numSearches = config[NUM_SEARCHES];
    int numAppends = config[NUM_APPENDS];
    int seconds = config[SECONDS];
    vector<uint32_t> times;
    string expDir = config[EXP_DIR];
    string dir = expDir + "/results.dat";

    if (config[TYPE] == "point")
    {
        cout << "Doing simPraPirTest: " << endl;
        simPraPirTest(client, numBuckets, windowSize, config[NUM_ANDS], config[REPS], times, dir);
        cout << "Done simPraPirTest" << endl;
    }
    else if (config[TYPE] == "point-throughput")
    {
        simPraPirThroughput(client, numBuckets, windowSize, config[NUM_ANDS], times, numAppends, numSearches, seconds, dir);
    }
}
