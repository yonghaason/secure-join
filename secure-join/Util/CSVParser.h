#pragma once
#include <cmath>
#include "cryptoTools/Crypto/PRNG.h"
#include "secure-join/Join/Table.h"
#include <fstream>
#include "secure-join/Defines.h"

namespace secJoin
{

    // std::string getMetaInfo(std::string& line, const std::string& type);
    // ColumnInfo getColumnInfo(std::string& line);
    void getFileInfo(std::string& fileName, std::vector<ColumnInfo>& columnInfo, 
                    u64& rowCount, u64 &colCount, bool& isBin);
    void getFileInfo(std::string& fileName, std::istream& in, std::vector<ColumnInfo>& columnInfo, 
                    u64& rowCount, u64& colCount, bool& isBin);
    void writeFileInfo(std::string &filePath, Table& tb, bool isBin=false);
    void writeColumnInfo(std::ofstream &file, Table &tb);
    void writeFileData(std::string &filePath, Table& tb, bool isBin=false);
    void writeFileHeader(std::ofstream &file, Table &tb);

}
