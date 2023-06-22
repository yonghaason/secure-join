#include <cmath>
#pragma once
#include "cryptoTools/Crypto/PRNG.h"
#include "secure-join/Table.h"
#include <fstream>
#include "secure-join/Defines.h"

oc::u64 getRows(std::string line);
oc::ColumnInfo getColumnInfo(std::string line);
void getFileInfo(std::string& fileName, std::vector<oc::ColumnInfo>& columnInfo, oc::u64& rowCount);
void getFileInfo(std::string& fileName, std::istream& in, std::vector<oc::ColumnInfo>& columnInfo, 
                oc::u64& rowCount);
