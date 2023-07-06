#pragma once
#include <cmath>
#include "cryptoTools/Crypto/PRNG.h"
#include "secure-join/Table.h"
#include <fstream>
#include "secure-join/Defines.h"

namespace secJoin
{

    u64 getRows(std::string line);
    ColumnInfo getColumnInfo(std::string line);
    void getFileInfo(std::string& fileName, std::vector<ColumnInfo>& columnInfo, u64& rowCount);
    void getFileInfo(std::string& fileName, std::istream& in, std::vector<ColumnInfo>& columnInfo, 
                    u64& rowCount);
    void writeFileInfo(std::string &filePath, Table& tb);
    void writeColumnInfo(std::ofstream &file, Table &tb);
    void writeFileData(std::string &filePath, Table& tb);
    void writeFileHeader(std::ofstream &file, Table &tb);

}
