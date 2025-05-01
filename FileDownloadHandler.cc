#include <wfrest/HttpMsg.h>
#include <wfrest/HttpServer.h>
#include <string>
#include <fcntl.h>
#include <unistd.h>

class FileDownloadHandler{
public:
    void handleUpload(wfrest::HttpReq *req, wfrest::HttpResp *resp){
        // // /file/download?filehash=aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d&filename=1.txt&filesize=5
        auto fileInfo = req->query_list();
        std::string filesha1 = fileInfo["filehash"];
        std::string filename = fileInfo["filename"];
        // int filesize = std::stoi(fileInfo["filesize"]);
        std::string filepath = "tmp/"+filename;

        // 下面这种方式也能实现下载功能，但当用户量较大的时候就抗不住了
        // int fd = open(filepath.c_str(),O_RDONLY);
        // int size = lseek(fd,0,SEEK_END);
        // lseek(fd,0,SEEK_SET);
        // std::unique_ptr<char []> buf(new char[size]);
        // read(fd,buf.get(),size);

        // resp->append_output_body(buf.get(),size);
        // resp->headers["Content-Type"] = "application/octect-stream";
        // resp->headers["content-disposition"] = "attachment;filename="+filename;
   
        // 转发到静态资源服务器来处理下载任务
        resp->set_status_code("302");
        resp->headers["Location"] = "http://192.168.137.138:1235/"+filename;
    }
};