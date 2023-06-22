#include "CSVParser.h"

oc::u64 getRows(std::string line)
{
    std::stringstream str(line);
    std::string word;

    oc::u64 rowCount = 0;
    oc::u8 colInfoCount = 0;
    while(getline(str, word, CSV_COL_DELIM))
    {
        if(colInfoCount == 0)
        {
            if(word.compare(ROWS_META_TYPE) != 0)
                throw RTE_LOC;
        }
        else if(colInfoCount == 1)
        {
            rowCount = std::stol(word);
        }
        
        colInfoCount++;
    }

    if(colInfoCount!=2)
    {
        std::string temp = line 
                  + " -> Not enough Information in the Meta File\n"
                  + LOCATION;
        throw std::runtime_error(temp);
    }
    return rowCount;
}


oc::ColumnInfo getColumnInfo(std::string line)
{
    std::stringstream str(line);
    std::string word;

    oc::u64 colInfoCount = 0;
    std::string name;
    oc::TypeID type;
    oc::u64 size;
    while(getline(str, word, CSV_COL_DELIM))
    {
        if(colInfoCount == 0)
            name = word;
        else if(colInfoCount == 1)
        {
            if(word.compare(STRING_META_TYPE) == 0)
                type = oc::TypeID::StringID;
            else
                type = oc::TypeID::IntID;

        }
        else if(colInfoCount == 2)
        {
            size = std::stol(word) * 8;
        }

        colInfoCount++;
    }

    if(colInfoCount!=3)
    {
        std::cout << line 
                  << " -> Not enough Information in the Meta File" 
                  << std::endl;
        throw RTE_LOC;
    }
    return {name, type, size};
}

void getFileInfo(std::string& fileName, 
                std::istream& in, 
                std::vector<oc::ColumnInfo>& columnInfo, 
                oc::u64& rowCount)
{
    std::string line, word;
    bool readRowCount = false;

    while(getline(in, line))
    {
        if(!readRowCount)
            rowCount = getRows(line);
        else
            columnInfo.push_back(getColumnInfo(line));

        readRowCount = true;
    }

    if(SECJOIN_ENABLE_LOGGING)
    {
        std::cout << "Printing " << fileName << " Meta Data" << std::endl;
        for(oc::u64 i =0; i<columnInfo.size(); i++)
        {
            if(std::get<1>(columnInfo[i]) == oc::TypeID::IntID)
            {
                std::cout 
                << std::get<0>(columnInfo[i]) << " "
                << "Integer "
                << std::get<2>(columnInfo[i]) << " "
                << std::endl;
            }
            else
            {
                std::cout 
                << std::get<0>(columnInfo[i]) << " "
                << "String "
                << std::get<2>(columnInfo[i]) << " "
                << std::endl;
            }

        }
    }

}



void getFileInfo(std::string& fileName, std::vector<oc::ColumnInfo>& columnInfo, oc::u64& rowCount)
{

    std::fstream file (fileName, std::ios::in);
    std::istream in(file.rdbuf());

    if(!file.is_open())
	{
        std::cout<<"Could not open the file" << std::endl;
        throw RTE_LOC;
	}

    getFileInfo(fileName, in, columnInfo, rowCount);
    file.close();
}