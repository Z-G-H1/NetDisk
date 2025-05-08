#include "CloudiskServer.h"

int main() {
    CloudiskServer server(1);
    server.loadModules();
    server.start(1234);
    return 0;
}