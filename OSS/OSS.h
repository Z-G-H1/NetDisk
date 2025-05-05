#include <alibabacloud/oss/OssClient.h>


struct OSSInfo {
    std::string Bucket = "zhouguanghan";
    std::string Endpoint = "oss-cn-beijing.aliyuncs.com";

};

enum{
    FS,
    OSS
};

struct Config{
    int storeType = OSS;
    int isAsyncTransferEnable = true;
};