#include "CSVParser_Test.h"

using namespace secJoin;


void secret_share_table_test()
{
    using oc::block;
    std::vector<ColumnInfo> columnInfo;
    u64 rowCount = 0;
    
    std::string filename = "Visa Meta File";
    std::istream in(visa_meta_text.rdbuf());
    getFileInfo(filename, in, columnInfo, rowCount);

    Table table(rowCount, columnInfo);
    std::array<Table,2> shareTables;
    shareTables[0].init(rowCount, columnInfo);
    shareTables[1].init(rowCount, columnInfo);

    PRNG prng(block(0,0));

    std::istream in1(visa_csv.rdbuf());
    populateTable(table, in1, rowCount);

    secretShareTable(table, shareTables, prng);
    
    for(u64 i =0; i<table.mColumns.size(); i++)
    {
        Matrix<u8> temp = reveal(shareTables[0].mColumns[i].mData.mData, 
                                        shareTables[1].mColumns[i].mData.mData);
                                        
        if(!eq(temp, table.mColumns[i].mData.mData))
            throw RTE_LOC;
    }
    

}

void secret_share_csv_test()
{
    std::string csvMetaFileNm = "INSERT PATH TO META DATA FILE";
    std::string csvFileNm = "INSERT PATH TO THE CSV DATA";

    std::vector<ColumnInfo> columnInfo;
    u64 rowCount = 0;
    
    getFileInfo(csvMetaFileNm, columnInfo, rowCount);

    // std::cout << "The row size is " << rowCount << std::endl;

    Table table(rowCount, columnInfo);
    std::array<Table,2> shareTables;
    shareTables[0].init(rowCount, columnInfo);
    shareTables[1].init(rowCount, columnInfo);

    PRNG prng(block(0,0));
    populateTable(table, csvFileNm, rowCount);

    secretShareTable(table, shareTables, prng);
    
    for(u64 i =0; i<table.mColumns.size(); i++)
    {
        Matrix<u8> temp = reveal(shareTables[0].mColumns[i].mData.mData, 
                                        shareTables[1].mColumns[i].mData.mData);
                                        
        if(!eq(temp, table.mColumns[i].mData.mData))
            throw RTE_LOC;
    }

}

