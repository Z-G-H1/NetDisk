#include "CloudiskServer.h"
#include <cstdio>
#include <nlohmann/json.hpp>
#include <wfrest/Json.h>
#include <string>
#include <utility>
#include <wfrest/HttpFile.h>
#include <wfrest/HttpMsg.h>
#include <workflow/MySQLMessage.h>
#include <workflow/MySQLResult.h>
#include <workflow/WFTask.h>
#include <workflow/WFTaskFactory.h>
#include "Hash.h"
#include "Token.h"
using Json = nlohmann::json;

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
    loadUserRegisterModule();
    loadUserLoginModule();
    loadFileQueryModule();
}

void CloudiskServer::loadUserRegisterModule(){
    _httpServer.POST("/user/signup",[](const HttpReq* req, HttpResp *resp,SeriesWork *series){
        // 按照url 解析post报文体
        std::map<std::string, std::string> &form_kv = req->form_kv();
        std::string username = form_kv["username"];
        std::string password = form_kv["password"];
        
        // 对密码进行加密
        std::string salt = "12345678";
        char *encryptPassword = crypt(password.c_str(), salt.c_str());

        // 把用户信息插入到数据库
        std::string sql = "INSERT INTO test1.tbl_user (user_name,user_pwd) values ('" + username + "','" + encryptPassword + "');";
        // 创建mysql任务

        auto mysqlTask = WFTaskFactory::create_mysql_task("mysql://root:root@localhost",0,[](WFMySQLTask* mysqlTask){
            HttpResp *resp2client = static_cast<HttpResp*>(mysqlTask->user_data);
            if(mysqlTask->get_state() != WFT_STATE_SUCCESS){
                fprintf(stderr, "State: %d, Error: %d, Error Msg: %s\n",
                    mysqlTask->get_state(),
                    mysqlTask->get_error(),
                    WFGlobal::get_error_string(mysqlTask->get_state(), mysqlTask->get_error()));
                resp2client->append_output_body("FAIL", 4);
                return ;    
            }

            protocol::MySQLResponse *resp = mysqlTask->get_resp();
            protocol::MySQLResultCursor cursor(resp);

            if(resp->get_packet_type() == MYSQL_PACKET_ERROR){
                fprintf(stderr,"error_code = %d msg = %s\n",resp->get_error_code(), resp->get_error_msg().c_str());
                resp2client->append_output_body("FAIL",4);
                return;
            }

            if(cursor.get_cursor_status() == MYSQL_STATUS_OK){
                //写指令，执行成功
                fprintf(stderr,"OK. %llu rows affected. %d warnings. insert_id = %llu.\n",
                    cursor.get_affected_rows(), cursor.get_warnings(), cursor.get_insert_id());
                if (cursor.get_affected_rows() == 1)
                {
                    resp2client->append_output_body("SUCCESS",7);
                    return;
                }
            }

        });
        mysqlTask->get_req()->set_query(sql);
        mysqlTask->user_data = resp;

        series->push_back(mysqlTask);
        
    });

}

void CloudiskServer::loadUserLoginModule(){
    _httpServer.POST("/user/signin",[](const HttpReq* req, HttpResp* resp, SeriesWork * series){
                // 1 解析用户请求
        std::map<std::string,std::string> &form_kv = req->form_kv();
            std::string username = form_kv["username"];
            std::string password = form_kv["password"];
            // 2 查询数据库
            std::string url = "mysql://root:root@localhost";
            std::string sql = "SELECT user_pwd FROM test1.tbl_user WHERE user_name = '" + username + "'LIMIT 1;";
            string salt("12345678");//这里应该是随机生成
            string encodedPassword(crypt(password.c_str(), salt.c_str()));
            auto readTask = WFTaskFactory::create_mysql_task(url,0,[=](WFMySQLTask* readTask){
                //提取readtask的结果
            auto *mysqlResp = readTask->get_resp();
            protocol::MySQLResultCursor cursor(mysqlResp);
            std::vector<std::vector<protocol::MySQLCell>> rows;
            cursor.fetch_all(rows);

            std::string nowPassword = rows[0][0].as_string();
            // fprintf(stderr, "nowPassword: %s\n", nowPassword.c_str());

            // 3 解密
            std::string salt = "12345678";
            char *encryptPassword = crypt(password.c_str(), salt.c_str());
            // fprintf(stderr, "encryptPassword: %s\n", encryptPassword);
            if(strcmp(nowPassword.c_str(),encryptPassword) != 0){
                // userInfo
                resp->append_output_body("Fail",4);
                return;
            }
            // 3 没有问题就生成一个token 存入数据库
            //根据登录时间和用户名（容易伪造，使用加密避免伪造）
            //根据用户信息
            Token usertoken(username,"12345678");
            //fprintf(stderr,"token = %s\n",usertoken.token.c_str());
            std::string tokenStr = usertoken.genToken();
            

            // 存入数据库当中
            std::string url = "mysql://root:root@localhost";
            std::string sql = "REPLACE INTO test1.tbl_user_token (user_name,user_token) VALUES ('" 
                + username
                + "', '" + tokenStr + "');";
            auto writeTask = WFTaskFactory::create_mysql_task(url,0,[=](WFMySQLTask *writeTask){
                ::Json msg;
                ::Json data;
                data["Token"] = tokenStr;
                data["Username"] = username;
                data["Location"] = "/static/view/home.html";//跳转到用户中心页面
                msg["data"] = data;
                resp->String(msg.dump());//序列化之后，发送给客户端
            });
            writeTask->get_req()->set_query(sql);
            series_of(readTask)->push_back(writeTask);
            // 4 将信息包装成json 返回客户端
            });
            readTask->get_req()->set_query(sql);
            series->push_back(readTask);    
        
    });



}


void CloudiskServer::loadStaticResourceModule(){

    _httpServer.GET("/file/upload",[](const HttpReq *req, HttpResp *resq){
        //自动 MIME 类型	根据扩展名设置 Content-Type（如 .html → text/html）
        resq->File("static/view/upload.html");
    });

    _httpServer.GET("/static/view/signin.html", [](const HttpReq *, HttpResp * resp){
        resp->File("static/view/signin.html");
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



void CloudiskServer::loadFileQueryModule(){
    _httpServer.POST("/file/upload",[](const HttpReq *req, HttpResp* resp){
        //从url中 获取用户名信息
        auto userInfo = req->query_list();
        std::string username = userInfo["username"];
        // 读取文件内容， 解析form-data类型的请求报文
        // 键是file 值是文件名和文件内容
        using Form = std::map<std::string, std::pair<std::string, std::string>>;
        Form &form = req->form();

        std::pair<std::string,std::string> fileInfo = form["file"];

        // first为文件名，second为文件内容
        std::string filepath = "tmp/" + fileInfo.first;
        int fd = open(filepath.c_str(), O_RDWR | O_CREAT , 0666);
        if( fd < 0 ){
            resp->set_status_code("500");
            return;
        }
        // 将上传的文件写入
        int ret = write(fd, fileInfo.second.c_str(), fileInfo.second.size());
        close(fd);

        Hash hash(filepath);
        // 将文件信息写入tbl_file表，将用户与文件对应关系写入tbl_user_file表
//         std::string sql = "INSERT INTO test1.tbl_file (file_sha1,file_name,file_size,file_addr,status) VALUES('" 
//         + hash.sha1() + "','"
//         + fileInfo.first + "'," 
//         + std::to_string(fileInfo.second.size()) + ",'"
//         + filepath + "', 0);";
// sql += "INSERT INTO test1.tbl_user_file (user_name, file_sha1, file_name, file_size) VALUES ('"
//         + username + "','"
//         + hash.sha1() + "','"
//         + fileInfo.first + "',"
//         + std::to_string(fileInfo.second.size()) + ");";

    });
}