#include "CSVParser.h"

namespace secJoin
{

    std::string getMetaInfo(std::string& line, const std::string& type)
    {
        std::stringstream str(line);
        std::string word;

        std::string info;
        u8 colInfoCount = 0;
        while (getline(str, word, CSV_COL_DELIM))
        {
            if (colInfoCount == 0)
            {
                if (word.compare(type) != 0)
                    throw RTE_LOC;
            }
            else if (colInfoCount == 1)
            {
                info = word;
            }

            colInfoCount++;
        }

        if (colInfoCount != 2)
        {
            std::string temp = line + " -> Not enough Information in the Meta File\n" + LOCATION;
            throw std::runtime_error(temp);
        }
        return info;
    }

    ColumnInfo getColumnInfo(std::string& line)
    {
        std::stringstream str(line);
        std::string word;

        u64 colInfoCount = 0;
        std::string name;
        TypeID type;
        u64 size;
        while (getline(str, word, CSV_COL_DELIM))
        {
            if (colInfoCount == 0)
                name = word;
            else if (colInfoCount == 1)
            {
                if (word.compare(STRING_META_TYPE) == 0)
                    type = TypeID::StringID;
                else
                    type = TypeID::IntID;
            }
            else if (colInfoCount == 2)
            {
                size = std::stol(word) * 8;
            }

            colInfoCount++;
        }

        if (colInfoCount != 3)
        {
            std::cout << line
                << " -> Not enough Information in the Meta File"
                << std::endl;
            throw RTE_LOC;
        }
        return { name, type, size };
    }

    void getFileInfo(std::string& fileName,
        std::istream& in,
        std::vector<ColumnInfo>& columnInfo,
        u64& rowCount,
        u64& colCount,
        bool& isBin)
    {
        std::string line, word;
        bool readFileType = false;
        bool readRowCount = false;
        bool readColCount = false;

        while (getline(in, line))
        {
            if (!readFileType)
            {
                std::string type = getMetaInfo(line, TYPE_OF_FILE);

                if (type.compare(BINARY_FILE_TYPE) == 0)
                    isBin = true;
                else
                    isBin = false;

                readFileType = true;
            }
            else if (!readRowCount)
            {
                rowCount = std::stol(getMetaInfo(line, ROWS_META_TYPE));
                readRowCount = true;
            }
            else if (!readColCount)
            {
                colCount = std::stol(getMetaInfo(line, COLS_META_TYPE));
                readColCount = true;
            }
            else
                columnInfo.push_back(getColumnInfo(line));

        }

        if (columnInfo.size() != colCount)
        {
            throw std::runtime_error(std::string("Col Count doesn't match the total \
                number of column info ") + std::string(fileName) + "\n" LOCATION);
        }

        if (false)
        {
            std::cout << "Printing " << fileName << " Meta Data" << std::endl;
            for (u64 i = 0; i < columnInfo.size(); i++)
            {
                if (columnInfo[i].mType == TypeID::IntID)
                {
                    std::cout
                        << columnInfo[i].mName << " "
                        << "Integer "
                        << columnInfo[i].mBitCount << " "
                        << std::endl;
                }
                else
                {
                    std::cout
                        << columnInfo[i].mName << " "
                        << "String "
                        << columnInfo[i].mBitCount << " "
                        << std::endl;
                }
            }
        }
    }

    void getFileInfo(std::string& fileName,
        std::vector<ColumnInfo>& columnInfo,
        u64& rowCount,
        u64& colCount,
        bool& isBin)
    {
        std::fstream file(fileName, std::ios::in);

        if (!file.good())
            throw std::runtime_error("Could not open the file " + std::string(fileName) + "\n" LOCATION);

        getFileInfo(fileName, file, columnInfo, rowCount, colCount, isBin);
        file.close();
    }


    void writeFileInfo(std::string& filePath, Table& tb, bool isBin)
    {
        std::ofstream file;
        file.open(filePath);

        if (!file.is_open())
            throw std::runtime_error("Could not open the file " + std::string(filePath) + "\n" LOCATION);

        // Adding the Type to the file
        if (isBin)
            file << TYPE_OF_FILE << CSV_COL_DELIM << BINARY_FILE_TYPE << "\n";
        else
            file << TYPE_OF_FILE << CSV_COL_DELIM << BINARY_FILE_TYPE << "\n";

        // Adding the Row Count to the file
        file << ROWS_META_TYPE << CSV_COL_DELIM << tb.rows() << "\n";

        // Adding the Col Count to the file
        file << COLS_META_TYPE << CSV_COL_DELIM << tb.mColumns.size() << "\n";

        // Adding the Column info to the file
        writeColumnInfo(file, tb);

        file.close();
    }

    void writeColumnInfo(std::ofstream& file, Table& tb)
    {
        for (u64 i = 0; i < tb.mColumns.size(); i++)
        {
            if (tb.mColumns[i].getTypeID() == TypeID::IntID)
            {
                file << tb.mColumns[i].mName << CSV_COL_DELIM
                    << "INT" << CSV_COL_DELIM
                    << tb.mColumns[i].getByteCount()
                    << "\n";
            }
            else
            {
                file << tb.mColumns[i].mName << CSV_COL_DELIM
                    << "STRING" << CSV_COL_DELIM
                    << tb.mColumns[i].getByteCount()
                    << "\n";
            }
        }
    }

    void writeFileHeader(std::ofstream& file, Table& tb)
    {
        for (u64 i = 0; i < tb.cols(); i++)
        {
            file << tb.mColumns[i].mName;

            if (i == tb.cols() - 1)
                file << "\n";
            else
                file << CSV_COL_DELIM;
        }
    }

    void writeFileData(std::string& filePath, Table& tb, bool isBin)
    {
        std::ofstream file;
        file.open(filePath);

        if (!file.is_open())
            throw std::runtime_error("Could not open the file " + std::string(filePath) + "\n" LOCATION);

        // Adding the Columns names to the file
        if (!isBin)
            writeFileHeader(file, tb);

        for (u64 rowNum = 0; rowNum < tb.rows(); rowNum++)
        {
            for (u64 colNum = 0; colNum < tb.cols(); colNum++)
            {
                if (isBin)
                {
                    u64 bytes = tb.mColumns[colNum].getByteCount();
                    u8* ptr = tb.mColumns[colNum].mData[rowNum].data();

                    for (u64 i = 0; i < bytes; i++)
                    {
                        file << *ptr;
                        ptr++;
                    }
                }
                else
                {
                    if (tb.mColumns[colNum].getTypeID() == TypeID::IntID)
                    {
                        if (tb.mColumns[colNum].getByteCount() <= 4)
                        {
                            u8* ptr = tb.mColumns[colNum].mData[rowNum].data();
                            i32 number = *(i32*)ptr;

                            file << number;
                        }
                        else if (tb.mColumns[colNum].getByteCount() <= 8)
                        {
                            u8* ptr = tb.mColumns[colNum].mData[rowNum].data();
                            i64 number = *(i64*)ptr;

                            file << number;
                        }
                        else
                        {
                            std::string temp = tb.mColumns[colNum].mName
                                + " can't be stored as int type\n"
                                + LOCATION;
                            throw std::runtime_error(temp);
                        }
                    }
                    else
                    {
                        std::string temp(tb.mColumns[colNum].getByteCount(), '\0');

                        copyBytes(temp, tb.mColumns[colNum].mData[rowNum]);
                        // m emcpy(temp.data(), tb.mColumns[colNum].mData[rowNum].data(),
                        //     tb.mColumns[colNum].getByteCount());

                        temp.erase(temp.find('\0'));
                        file << temp;
                    }

                    if (colNum == tb.cols() - 1)
                        file << "\n";
                    else
                        file << CSV_COL_DELIM;

                }

            }
        }

        file.close();
    }

}