#include "CSVParser_Test.h"

using namespace secJoin;


void secret_share_table_test()
{
    std::string csvMetaFileNm = "/Users/harshah/Documents/Core/testing/secret_sharing/visa_meta.txt";
    std::string csvFileNm = "/Users/harshah/Documents/Core/testing/secret_sharing/visa.csv";
    // std::string csvFileNm = "/Users/harshah/Documents/Core/testing/secret_sharing/bank.csv";

    std::vector<oc::ColumnInfo> columnInfo;
    oc::u64 rowCount = 0;
    
    getFileInfo(csvMetaFileNm, columnInfo, rowCount);

    // std::cout << "The row size is " << rowCount << std::endl;

    oc::Table table(rowCount, columnInfo);
    std::array<oc::Table,2> shareTables;
    shareTables[0].init(rowCount, columnInfo);
    shareTables[1].init(rowCount, columnInfo);

    oc::PRNG prng(oc::block(0,0));
    populateTable(table, csvFileNm, rowCount);

    secret_share_table(table, shareTables, prng);
    
    for(oc::u64 i =0; i<table.mColumns.size(); i++)
    {
        oc::Matrix<oc::u8> temp = reveal(shareTables[0].mColumns[i].mData.mData, 
                                        shareTables[1].mColumns[i].mData.mData);
                                        
        if(!eq(temp, table.mColumns[i].mData.mData))
            throw RTE_LOC;
    }
    

}

