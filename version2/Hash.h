#ifndef __Hash__HPP__
#define __Hash__HPP__
#include <string>

class Hash{
public:
    Hash(const std::string& filename): _filename(filename){}

    std::string sha1() const;

private: 
    std::string _filename;
};



#endif