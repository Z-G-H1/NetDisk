#include <iostream>
#include <wfrest/HttpServer.h>
#include <workflow/WFFacilities.h>


class CloudiskServer{

public:
    CloudiskServer(int cnt) : _waitGroup(cnt)
    {}

    ~CloudiskServer(){}

    void start(unsigned short port);

    void loadModules();


private:
    void loadStaticResourceModule();
    void loadUserRegisterModule();
    void loadUserLoginModule();
    void loadFileQueryModule();

private:

    WFFacilities::WaitGroup _waitGroup;
    wfrest::HttpServer _httpServer;

};