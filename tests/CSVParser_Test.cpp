#include "CSVParser_Test.h"
#include"cryptoTools/Common/TestCollection.h"
using namespace secJoin;

void secret_share_table_test()
{
    std::vector<ColumnInfo> columnInfo;
    u64 rowCount = 0;
    u64 colCount = 0;
    bool isBin;

    std::string filename = "Visa Meta File";
    std::istream in(visa_meta_text.rdbuf());
    getFileInfo(filename, in, columnInfo, rowCount, colCount, isBin);

    Table table(rowCount, columnInfo);
    std::array<Table, 2> shareTables;
    shareTables[0].init(rowCount, columnInfo);
    shareTables[1].init(rowCount, columnInfo);

    PRNG prng(block(0, 0));

    std::istream in1(visa_csv.rdbuf());
    populateTable(table, in1, rowCount, isBin);

    share(table, shareTables, prng);

    for (u64 i = 0; i < table.mColumns.size(); i++)
    {
        Matrix<u8> temp = reveal(shareTables[0].mColumns[i].mData.mData,
            shareTables[1].mColumns[i].mData.mData);

        if (!eq(temp, table.mColumns[i].mData.mData))
            throw RTE_LOC;
    }


}

void secret_share_csv_test()
{
    throw oc::UnitTestSkipped("known issue");
    std::string csvMetaFileNm = "INSERT PATH TO META DATA FILE";
    std::string csvFileNm = "INSERT PATH TO THE CSV DATA";

    std::vector<ColumnInfo> columnInfo;
    u64 rowCount = 0, colCount = 0;
    bool isBin;

    getFileInfo(csvMetaFileNm, columnInfo, rowCount, colCount, isBin);

    Table table(rowCount, columnInfo);
    std::array<Table, 2> shareTables;
    shareTables[0].init(rowCount, columnInfo);
    shareTables[1].init(rowCount, columnInfo);

    PRNG prng(block(0, 0));
    populateTable(table, csvFileNm, rowCount, isBin);

    share(table, shareTables, prng);

    for (u64 i = 0; i < table.mColumns.size(); i++)
    {
        Matrix<u8> temp = reveal(shareTables[0].mColumns[i].mData.mData,
            shareTables[1].mColumns[i].mData.mData);

        if (!eq(temp, table.mColumns[i].mData.mData))
            throw RTE_LOC;
    }

}

void table_write_csv_test()
{
    std::vector<ColumnInfo> columnInfo;
    u64 rowCount = 0, colCount = 0;
    bool isBin;
    
    std::string filename = "Visa Meta File";
    std::istream in(visa_meta_text.rdbuf());
    getFileInfo(filename, in, columnInfo, rowCount, colCount, isBin);

    Table table(rowCount, columnInfo);
    std::istream in1(visa_csv.rdbuf());
    populateTable(table, in1, rowCount, isBin);

    // std::string csvMetaFileNm = "/Users/harshah/Documents/Core/testing/secret_sharing/output/joindata_meta.txt";
    // std::string csvFileNm = "/Users/harshah/Documents/Core/testing/secret_sharing/output/joindata.csv";
    std::string csvMetaFileNm = "INSERT PATH TO META DATA FILE";
    std::string csvFileNm = "INSERT PATH TO THE CSV DATA";

    writeFileInfo(csvMetaFileNm, table);
    writeFileData(csvFileNm, table);
}


void table_write_bin_csv_test()
{
    std::string rootPath(SEC_JOIN_ROOT_DIRECTORY);
    std::string visaCsvPath = rootPath + "/tests/tables/visa.csv";
    std::string visaMetaDataPath = rootPath + "/tests/tables/visa_meta.txt";

    oc::u64 lRowCount = 0, lColCount = 0;
    bool isBin;

    std::vector<ColumnInfo> lColInfo, rColInfo;
    getFileInfo(visaMetaDataPath, lColInfo, lRowCount, lColCount, isBin);

    Table table(lRowCount, lColInfo);
    populateTable(table, visaCsvPath, lRowCount, isBin);

    std::string csvMetaFileNm1 = rootPath + "/tests/tables/joindata_meta.txt";
    std::string csvFileNm1 = rootPath + "/tests/tables/joindata.csv";
    
    std::array<Table, 2> shareTables;
    shareTables[0].init(lRowCount, lColInfo);
    shareTables[1].init(lRowCount, lColInfo);

    PRNG prng(block(0, 0));

    share(table, shareTables, prng);

    writeFileInfo(csvMetaFileNm1, shareTables[0], true);
    writeFileData(csvFileNm1, shareTables[0], true);
    

    // Testing whether the write was successful or not
    std::vector<ColumnInfo> columnInfo1;
    u64 rowCount1 = 0, colCount1 = 0;
    bool isBin1;
    getFileInfo(csvMetaFileNm1, columnInfo1, rowCount1, colCount1, isBin1);

    Table shtb(rowCount1, columnInfo1);
    populateTable(shtb, csvFileNm1, rowCount1, isBin1);

    if(shareTables[0] != shtb)
        throw RTE_LOC;
}