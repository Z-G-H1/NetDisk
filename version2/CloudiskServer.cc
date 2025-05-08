#include "CloudiskServer.h"
#include <wfrest/HttpFile.h>

using namespace wfrest;

void CloudiskServer::start(unsigned short port){
    if(_httpServer.track().start(port) == 0){
        _httpServer.list_routes();
        _waitGroup.wait();
        _httpServer.stop();
    }

}

void CloudiskServer::loadModules(){
    loadStaticResourceModule();
}

void CloudiskServer::loadStaticResourceModule(){

    _httpServer.GET("/file/upload",[](const HttpReq *req, HttpResp *resq){
        //自动 MIME 类型	根据扩展名设置 Content-Type（如 .html → text/html）
        resq->File("static/view/upload.html");
    });

    _httpServer.GET("/file/upload/success",[](const HttpReq *req, HttpResp *resp){
        resp->String("Upload success");
        // 添加新逻辑，实现跳转到原界面
    });

    _httpServer.GET("/user/signup",[](const HttpReq *req, HttpResp *resp){
        resp->File("static/view/signup.html");
    });

    _httpServer.GET("/static/view/home.html",[](const HttpReq *req, HttpResp *resp){
        resp->File("static/view/home.html");
    });

    _httpServer.GET("/static/js/auth.js",[](const HttpReq *req, HttpResp *resp){
        resp->File("static/js/auth.js");
    });

    _httpServer.GET("/static/img/avatar.jpeg",[](const HttpReq *req, HttpResp *resp){
        resp->File("static/img/avatar.jpeg");
    });


    _httpServer.Static("file/upload_files", "static/view/upload_files");

}