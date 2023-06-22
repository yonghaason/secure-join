#pragma once

const std::istringstream visa_meta_text("\
Rows;7\n\
PAN;INT;8\n\
Risk_Score;STRING;10\n\
");

const std::istringstream visa_csv("\
PAN;Risk_Score\n\
9970891536;0.99\n\
1632619219;0.97\n\
3273429032;0.92\n\
2490717994;1.0\n\
4567664634;1.0\n\
3136665904;0.9\n\
4953106736;1.0\n\
");