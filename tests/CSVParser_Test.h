#pragma once
#include "secure-join/Join/Table.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "secure-join/Util/Util.h"
#include "secure-join/Util/CSVParser.h"
#include "FileContent.h"

void secret_share_table_test();
void secret_share_csv_test();
void table_write_csv_test();
void table_write_bin_csv_test();