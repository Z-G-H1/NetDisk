#include <string>
struct RabbitMqInfo{
    std::string RabbitURL = "amqp://guest:guest@127.0.0.1:5672";
    std::string TransExchangeName = "uploadserver.trans";
    std::string TransQueueName = "uploadserver.trans.oss";
    std::string TransRoutingKey = "oss";
};