#include <string>
#include <math.h>
#include <assert.h>

#include "client.h"
#include "query.h"
#include "../../secure-indices/core/DCFTable.h"
#include "../../secure-indices/core/DPFTable.h"
#include "../../network/core/query.grpc.pb.h"
#include "../../network/core/query.pb.h"
#include "../../secure-indices/core/common.h"

using dbquery::Query;
using grpc::Channel;
using grpc::ClientAsyncResponseReader;
using grpc::ClientContext;
using grpc::CompletionQueue;
using grpc::Status;
using namespace dorydb;
using namespace osuCrypto;
using namespace std;

int main(int argc, char *argv[])
{
    string addrs[3] = {"127.0.0.1:12345", "127.0.0.1:12346", "127.0.0.1:12347"};
    uint32_t windowSize = 256;
    uint32_t numBuckets = 256;
    int depth = 1;

    vector<uint32_t> data(windowSize, 1);

    vector<shared_ptr<grpc::Channel>> channels;
    for (int i = 0; i < NUM_SERVERS; i++) {


        grpc::ChannelArguments args;
        args.SetMaxReceiveMessageSize(1024 * 1024 * 1024); // grpc max 1024MB
        args.SetMaxSendMessageSize(1024 * 1024 * 1024);    // grpc max 1024MB
        
        shared_ptr<grpc::Channel> channel = grpc::CreateCustomChannel(
            addrs[i],
            grpc::InsecureChannelCredentials(),
            args
        );

        //shared_ptr<grpc::Channel> channel = grpc::CreateChannel(addrs[i], grpc::InsecureChannelCredentials());  grpc max 4MB
        channels.push_back(channel);
    }
    printf("going to create client\n");
    QueryClient *client = new QueryClient(channels);
}
