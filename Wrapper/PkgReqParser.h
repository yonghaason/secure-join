#pragma once
#include "secure-join/Util/ArrGate.h"
#include "Wrapper/state.h"

namespace secJoin{

    // This function is repetiting in Where.cpp, Can we remove from here?
    inline oc::u64 getMapVal(std::unordered_map<oc::u64, oc::u64>& map, oc::u64 tag)
    {
        auto t = map.find(tag);
        if (t == map.end()){
            std::string temp = "Column Index not present in the uMap "
                + std::to_string(tag) + LOCATION;
            throw std::runtime_error(temp);
        }
        return t->second;
    }

    inline oc::u64 getRColIndex(oc::u64 relativeIndex, oc::u64 lColCount, oc::u64 rColCount)
    {
        oc::u64 index = relativeIndex - lColCount;

        if( index < 0 || index >= rColCount)
        {
            std::string temp = "Right Column relative index = "+ std::to_string(relativeIndex) 
                + " is not present in the right table" + "\n" + LOCATION;
            throw std::runtime_error(temp);
        }

        return index;
    }

    inline std::vector<secJoin::ColRef> getColRefFromMapping(std::unordered_map<oc::u64, oc::u64>& map, 
        std::vector<oc::u64>& colList, Table& joinTable)
    {
        std::vector<secJoin::ColRef> colRefs;

        for(oc::u64 i =0; i< colList.size(); i++)
        {
            oc::u64 mappedIndex = getMapVal(map, colList[i]);
            colRefs.emplace_back(joinTable[mappedIndex]);
        }

        return colRefs;
    }

    inline std::vector<secJoin::ColRef> getSelectColRef( std::vector<oc::u64>& selectCols, 
        Table& L, Table &R, u64 lColCount, u64 rColCount)
    {
        std::vector<secJoin::ColRef> selectColRef;
        selectColRef.reserve(selectCols.size());

        for(u64 i=0; i < selectCols.size(); i++)
        {
            u64 colNum = selectCols[i];
            if(colNum < lColCount)            
                selectColRef.emplace_back(L[colNum]);
            else if(colNum < (lColCount + rColCount) ) 
            {
                oc::u64 index = getRColIndex(colNum, lColCount, rColCount);
                selectColRef.emplace_back(R[index]);
            }       
            else
            {
                std::string temp = "Select Col Num = "+ std::to_string(colNum) 
                    + " is not present in any table" + "\n" + LOCATION;
                throw std::runtime_error(temp);
            }

        }
        return selectColRef;
    }

    // checking end of the array
    inline oc::u64 checkEOA(oc::i64 val)
    {
        if(val == -1)
            throw RTE_LOC;
        
        return val;
    }

    inline void printCols(std::vector<oc::u64>& vec, std::string colType)
    {
        std::cout << "Printing " << colType << " Cols" << std::endl;
        for(oc::u64 i = 0; i < vec.size(); i++)
            std::cout << vec[i] << " ";
        
        std::cout << std::endl;
    }

    inline void printGates(std::vector<ArrGate>& gates)
    {
        std::cout << "Printing Gates" << std::endl;

        for(oc::u64 i = 0; i < gates.size(); i++)
            std::cout << gates[i];
        
        std::cout << std::endl;
    }

    inline void initCols(std::vector<oc::u64>& vec, oc::u64& startIndex, std::vector<oc::i64>& opInfo)
    {
        oc::u64 size = checkEOA(opInfo[startIndex++]);
        
        vec.reserve(size);
        
        for(u64 i=0; i<size; i++)
            vec.emplace_back(checkEOA(opInfo[startIndex++]));
    }

    inline void initGates(std::vector<ArrGate>& gates, oc::u64& startIndex, std::vector<oc::i64>& opInfo)
    {
        oc::u64 size = checkEOA(opInfo[startIndex++]);
        gates.reserve(size);

        for(u64 i=0; i<size; i++)
        {
            gates.emplace_back(
                checkEOA(opInfo[startIndex]),
                checkEOA(opInfo[startIndex+1]),
                checkEOA(opInfo[startIndex+2]),
                checkEOA(opInfo[startIndex+3])
            );
            startIndex=startIndex+4;
        }
    }

    /*
    opInfo array contains object in the following way (without gates info)
    1) Total number of the Join Columns
    2) Series of the Join Columns
    3) Total number of the Select Columns
    4) Series of the Select Columns
    5) Total number of the Groupby Columns
    6) Series of the Groupby Columns
    7) Total number of the Average Columns
    8) Series of the Average Columns
    9) -1
    */
    inline void parseColsArray(std::vector<oc::u64>& joinCols, 
        std::vector<oc::u64>& selectCols,
        std::vector<oc::u64>& groupByCols, 
        std::vector<oc::u64>& avgCols, 
        std::vector<oc::i64>& opInfo, 
        u64& startIndex,
        bool print = false)
    {   
        // Getting Join Cols
        initCols(joinCols, startIndex, opInfo);

        // Getting Select Cols
        initCols(selectCols, startIndex, opInfo); 
        
        // Getting Groupby Cols
        initCols(groupByCols, startIndex, opInfo);

        // Getting Average Cols
        initCols(avgCols, startIndex, opInfo);

        if(print)
        {
            printCols(joinCols, "Join");
            printCols(selectCols, "Select");
            printCols(groupByCols, "GroupBy");
            printCols(avgCols, "Average");
        }
    }


    /*
    opInfo array contains object in the following way
    1) Total number of the Join Columns
    2) Series of the Join Columns
    3) Total number of the Select Columns
    4) Series of the Select Columns
    5) Total number of the Groupby Columns
    6) Series of the Groupby Columns
    7) Total number of the Average Columns
    8) Series of the Average Columns
    9) Total number of Gates
    10) Four Entries for Gate 1
    11) Four Entries for Gate 2
    12) .
    13) .
    14) .
    15) -1
    */
    inline void parseColsArray(std::vector<oc::u64>& joinCols, 
        std::vector<oc::u64>& selectCols,
        std::vector<oc::u64>& groupByCols, 
        std::vector<oc::u64>& avgCols, 
        std::vector<secJoin::ArrGate>& gates,
        std::vector<oc::i64>& opInfo, 
        bool print = false)
    {
        oc::u64 startIndex = 0;
        
        parseColsArray(joinCols, selectCols, groupByCols, avgCols, opInfo, startIndex, print);

        // Getting the where Gates
        initGates(gates, startIndex, opInfo);

        if(print)
            printGates(gates);
        
    }

    inline void appendVecIfNec(std::vector<oc::u64>& select, oc::u64 element)
    {
        std::vector<oc::u64>::iterator it = std::find(select.begin(), select.end(), element) ;
        if( it == select.end())
            select.emplace_back(element);

    }

    inline void updateSelectCols(std::vector<oc::u64>& select, std::vector<ArrGate>& gates, 
        oc::u64 totalColCount)
    {
        for(u64 i=0; i < gates.size(); i++)
        {

            for( u64 j=0; j< gates[i].mInput.size(); j++)
            {
                u64 element = gates[i].mInput[j];
                // Check whether input to the gate is a table column or not
                if(element < totalColCount)
                    appendVecIfNec(select, element);
            }
        }        
    }


    inline void updateSelectCols(std::vector<oc::u64>& select, std::vector<oc::u64>& colList)
    {
        for(u64 i=0; i < colList.size(); i++)
        {
            u64 element = colList[i];
            // If the col is not present then add it to the select
            appendVecIfNec(select, element);

        }        
    }

    /*
    This method method updates the Select Cols if any of the where, 
    groupby & Average Columns don't exists in the Select Cols.
    */
    inline void updateSelectCols(WrapperState* cState, bool print)
    {  

        // Checking GroupBy Cols
        updateSelectCols(cState->mSelectCols, cState->mGroupByCols);

        // Checking Average Cols
        updateSelectCols(cState->mSelectCols, cState->mAvgCols);

        // Checking where Cols
        updateSelectCols(cState->mSelectCols, cState->mGates, 
            cState->mLTable.cols() + cState->mRTable.cols());

        if(print)
            printCols(cState->mSelectCols, "Select");
    }

    inline void createNewMapping(std::unordered_map<oc::u64, oc::u64> &mMap,
        std::vector<oc::u64>& mSelectCols)
    {
        for(oc::u64 i = 0; i < mSelectCols.size(); i++)
        {
            oc::u64 colIndex = mSelectCols[i];
            mMap[colIndex] = i;
        }
    }

}