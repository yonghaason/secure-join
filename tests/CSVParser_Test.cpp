#include "CSVParser_Test.h"
#include"cryptoTools/Common/TestCollection.h"
#include "secure-join/config.h"
using namespace secJoin;

void table_csvIo_test()
{
	Table table;
    u64 rows = 100;
	std::vector<ColumnInfo> colsInfo = { 
        ColumnInfo("a", ColumnType::Int, 16), 
        ColumnInfo("b", ColumnType::String, 64) 
    };
    table.init(rows, colsInfo);

    PRNG prng(block(324234, 1234213));
    prng.get<u8>(table.mColumns[0].mData);
	prng.get<u8>(table.mColumns[1].mData);
	for (auto i = 0ull; i < table.mColumns[1].mData.size(); ++i)
    {
		if (table.mColumns[1].mData(i) == 0 || table.mColumns[1].mData(i) == ';')
			table.mColumns[1].mData(i) = 'a';
	}

	std::stringstream stream;
    table.writeCSV(stream);

    Table table2;
    table2.readCSV(stream);

	if (table != table2)
		throw RTE_LOC;

}


void table_binIo_test()
{

    Table table;
    u64 rows = 100;
    std::vector<ColumnInfo> colsInfo = {
        ColumnInfo("a", ColumnType::Int, 16),
        ColumnInfo("b", ColumnType::String, 64)
    };
    table.init(rows, colsInfo);

    PRNG prng(block(324234, 1234213));
    prng.get<u8>(table.mColumns[0].mData);
    prng.get<u8>(table.mColumns[1].mData);

    std::stringstream stream;
    table.writeBin(stream);

    Table table2;
    table2.writeBin(stream);

    if (table != table2)
        throw RTE_LOC;
}