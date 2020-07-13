/*

 The MIT License (MIT)

 Copyright (c) 2017 Jonas Schnelli

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

 */

#include <btc/chainparams.h>

const btc_chainparams btc_chainparams_main = {
    "Bitcoin",
    0x00,
    0x05,
    "bc",
    0x80,
    0x0488ADE4,
    0x0488B21E,
    {0xf9, 0xbe, 0xb4, 0xd9},
    {0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00},
    8333,
    {{"seed.bitcoin.jonasschnelli.ch"}, {}},
};
const btc_chainparams btc_chainparams_test = {
    "Bitcoin testnet",
    0x6f,
    0xc4,
    "tb",
    0xEF,
    0x04358394,
    0x043587CF,
    {0x0b, 0x11, 0x09, 0x07},
    {0x43, 0x49, 0x7f, 0xd7, 0xf8, 0x26, 0x95, 0x71, 0x08, 0xf4, 0xa3, 0x0f, 0xd9, 0xce, 0xc3, 0xae, 0xba, 0x79, 0x97, 0x20, 0x84, 0xe9, 0x0e, 0xad, 0x01, 0xea, 0x33, 0x09, 0x00, 0x00, 0x00, 0x00},
    18333,
    {{"testnet-seed.bitcoin.jonasschnelli.ch"}, {}},
};
const btc_chainparams btc_chainparams_regtest = {
    "regtest",
    0x6f,
    0xc4,
    "bcrt",
    0xEF,
    0x04358394,
    0x043587CF,
    {0xfa, 0xbf, 0xb5, 0xda},
    {0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59, 0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf, 0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f, 0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f},
    18444,
    {},
};


const btc_chainparams ltc_chainparams_main = {
    "Litecoin",
    0x30,
    0x32,
    "ltc",
    0xb0,
    0x019d9cfe,
    0x019da462,
    {0xdb, 0xb6, 0xc0, 0xfb},
    {0x12,0xa7, 0x65, 0xe3, 0x1f, 0xfd, 0x40, 0x59, 0xba, 0xda, 0x1e, 0x25, 0x19, 0x0f, 0x6e, 0x98, 0xc9, 0x9d, 0x97, 0x14, 0xd3, 0x34, 0xef, 0xa4, 0x1a, 0x19, 0x5a, 0x7e, 0x7e, 0x04, 0xbf, 0xe2},
    8333,
    {{"dnsseed.litecointools.com"}, {}},
};
const btc_chainparams ltc_chainparams_test = {
    "Litecoin testnet",
    0x6f,
    0x3a,
    "tltc",
    0xEF,
    0x0436ef7d,
    0x0436f6e1,
    {0xdb, 0xb6, 0xc0, 0xfb},
    {0xf5, 0xae, 0x71, 0xe2, 0x6c, 0x74, 0xbe, 0xac, 0xc8, 0x83, 0x82, 0x71, 0x6a, 0xce, 0xd6, 0x9c, 0xdd, 0xf3, 0xdf, 0xff, 0xf2, 0x4f, 0x38, 0x4e, 0x18, 0x08, 0x90, 0x5e, 0x01, 0x88, 0xf6, 0x8f},
    18333,
    {{"dnsseed.litecointools.com"}, {}},
};

const btc_chainparams dash_chainparams_main = {
    "Dash",
    0x4c,
    0x10,
    "dash",
    0xcc,
    0x0488ade4,
    0x0488b21e,
    {0xbf, 0x0c, 0x6b, 0xdb},
    {0x00, 0x00, 0x0f, 0xfd, 0x59, 0x0b, 0x14, 0x85, 0xb3, 0xca, 0xad, 0xc1, 0x9b, 0x22, 0xe6, 0x37, 0x9c, 0x73, 0x33, 0x55, 0x10, 0x8f, 0x10, 0x7a, 0x43, 0x04, 0x58, 0xcd, 0xf3, 0x40, 0x7a, 0xb6},    8333,
    {{"dash.org"}, {}},
};
const btc_chainparams dash_chainparams_test = {
    "Dash testnet",
    0x8c,
    0x13,
    "tdash",
    0xEF,
    0x04358394,
    0x043587cf,
    {0xdb, 0xb6, 0xc0, 0xfb},
    {0x00, 0x00, 0x0b, 0xaf, 0xbc, 0x94, 0xad, 0xd7, 0x6c, 0xb7, 0x5e, 0x2e, 0xc9, 0x28, 0x94, 0x83, 0x72, 0x88, 0xa4, 0x81, 0xe5, 0xc0, 0x05, 0xf6, 0x56, 0x3d, 0x91, 0x62, 0x3b, 0xf8, 0xbc, 0x2c},
    18333,
    {{"dash.org"}, {}},
};



const btc_checkpoint btc_mainnet_checkpoint_array[] = {
    {0, "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f", 1231006505, 0x1d00ffff},
    {20160, "000000000f1aef56190aee63d33a373e6487132d522ff4cd98ccfc96566d461e", 1248481816, 0x1d00ffff},
    {40320, "0000000045861e169b5a961b7034f8de9e98022e7a39100dde3ae3ea240d7245", 1266191579, 0x1c654657},
    {60480, "000000000632e22ce73ed38f46d5b408ff1cff2cc9e10daaf437dfd655153837", 1276298786, 0x1c0eba64},
    {80640, "0000000000307c80b87edf9f6a0697e2f01db67e518c8a4d6065d1d859a3a659", 1284861847, 0x1b4766ed},
    {100800, "000000000000e383d43cc471c64a9a4a46794026989ef4ff9611d5acb704e47a", 1294031411, 0x1b0404cb},
    {120960, "0000000000002c920cf7e4406b969ae9c807b5c4f271f490ca3de1b0770836fc", 1304131980, 0x1b0098fa},
    {141120, "00000000000002d214e1af085eda0a780a8446698ab5c0128b6392e189886114", 1313451894, 0x1a094a86},
    {161280, "00000000000005911fe26209de7ff510a8306475b75ceffd434b68dc31943b99", 1326047176, 0x1a0d69d7},
    {181440, "00000000000000e527fc19df0992d58c12b98ef5a17544696bbba67812ef0e64", 1337883029, 0x1a0a8b5f},
    {201600, "00000000000003a5e28bef30ad31f1f9be706e91ae9dda54179a95c9f9cd9ad0", 1349226660, 0x1a057e08},
    {221760, "00000000000000fc85dd77ea5ed6020f9e333589392560b40908d3264bd1f401", 1361148470, 0x1a04985c},
    {241920, "00000000000000b79f259ad14635739aaf0cc48875874b6aeecc7308267b50fa", 1371418654, 0x1a00de15},
    {262080, "000000000000000aa77be1c33deac6b8d3b7b0757d02ce72fffddc768235d0e2", 1381070552, 0x1916b0ca},
    {282240, "0000000000000000ef9ee7529607286669763763e0c46acfdefd8a2306de5ca8", 1390570126, 0x1901f52c},
    {302400, "0000000000000000472132c4daaf358acaf461ff1c3e96577a74e5ebf91bb170", 1400928750, 0x18692842},
    {322560, "000000000000000002df2dd9d4fe0578392e519610e341dd09025469f101cfa1", 1411680080, 0x181fb893},
    {342720, "00000000000000000f9cfece8494800d3dcbf9583232825da640c8703bcd27e7", 1423496415, 0x1818bb87},
    {362880, "000000000000000014898b8e6538392702ffb9450f904c80ebf9d82b519a77d5", 1435475246, 0x1816418e},
    {383040, "00000000000000000a974fa1a3f84055ad5ef0b2f96328bc96310ce83da801c9", 1447236692, 0x1810b289},
    {403200, "000000000000000000c4272a5c68b4f55e5af734e88ceab09abf73e9ac3b6d01", 1458292068, 0x1806a4c3}};
