#include "AltPsu.h"
#include "secure-join/Prf/AltModPrfProto.h"
#include "secure-join/Sort/RadixSort.h"
#include "secure-join/Join/OmJoin.h"
#include "secure-join/Perm/PprfPermGen.h"
#include "secure-join/GMW/Gmw.h"
#include "cryptoTools/Crypto/AES.h"

namespace secJoin
{

    Proto AltModPsuSender::run_gmw_test(span<block> Y, PRNG &prng, Socket &chl)
    {
        MC_BEGIN(Proto, this, Y, &prng, &chl,
                ole_gmw = CorGenerator{},                
                ole_gmw_vector = std::vector<CorGenerator>{},    
                tgmw = macoro::task<void>{},
                tgmw_ole = macoro::task<void>{},
                in = oc::Matrix<u8>{},
                cmp = std::make_unique<Gmw>(),
                cir = BetaCircuit{},
                outView = oc::MatrixView<u8>{},
                flags = oc::BitVector{},
                temp = block{},
                i = int{},
                j = int{},
                row = int{},
                byteIndex = int{},
                bitMask = u8{},
                bitShift = int{},
                count = int{},

                key = block{},
                aes = oc::AES{},
                bit_block = std::vector<block>{},
                send_ciphertext = std::vector<block>{}
                
        );
        // std::cout << "sender 0\n";
        cir = isZeroCircuit(1);
        flags.resize(Y.size() * 80);
        in.resize(Y.size(), 1);
        ole_gmw_vector.resize(80);

        for(i = 0; i < 80; i++){
            std::memset(in.data(), 0, in.size());

            byteIndex = i / 8;
            bitShift = i & 7;
            bitMask = 1u << (bitShift);
            
            // std::cout << "sender 1\n";
            
            for (j = 0; j < Y.size(); j++){

                if(j % 2 == 0)
                    temp = oc::OneBlock;
                else
                    temp = oc::ZeroBlock;
                
                // temp = output_2party_wprf[i]^output_1party_wprf[i];
                // std::memcpy(&in(j, 0), ((u8*)&temp) + byteIndex, 1);
                u8    byteVal = ((u8*)&temp)[byteIndex];
                u8    bit     = (byteVal & bitMask) >> bitShift;   // 0 or 1

                in(j,0) = bit;
            }
            // std::cout << "sender 2\n";

            ole_gmw_vector[i].init(chl.fork(), prng, 0, 1, 1 << 18, 0);
            
            cmp->init(in.rows(), cir, ole_gmw_vector[i]);
            cmp->setInput(0, in);

            // std::cout << "sender 3\n";
            tgmw = cmp->run(chl);
            tgmw_ole = ole_gmw_vector[i].start();
            MC_AWAIT(when_all_ready(tgmw, tgmw_ole));
            // std::cout << "sender 4\n";
            outView = cmp->getOutputView(0);

            oc::BitVector bits(outView.data(), Y.size(), /*copy=*/false);
            for (row = 0; row < Y.size(); row++){
                // std::cout << "i is " << i << " row is " << row<< '\n';
                // bool outBit = outView[row][0] & static_cast<u8>(1);
                if(bits[row])
                    flags[row*80 + i] = true;
            }
            
        }
        // std::cout << "sender 5\n";
        MC_AWAIT(chl.send(flags));
        
        bit_block.resize(Y.size());
        std::memset(bit_block.data(), 0, Y.size() * sizeof(block));
        for(i = 0; i < Y.size(); i ++){
            std::memcpy(reinterpret_cast<u8*>(bit_block.data()) + i * sizeof(block), flags.data() + (i*10), 10);   
        }
        
        key = oc::ZeroBlock;

        aes.setKey(key);

        aes.ecbEncBlocks(bit_block.data(), bit_block.size(), bit_block.data());

        send_ciphertext.resize(Y.size());
        for(i = 0; i < Y.size(); i++){
            send_ciphertext[i] = (bit_block[i] ^ oc::OneBlock);
        }

        MC_AWAIT(chl.send(send_ciphertext));

        // std::cout << "sender 6\n";
        //use AES then, make pseudo-OTP


        MC_END();
    }
    
    Proto AltModPsuReceiver::run_gmw_test(span<block> X, PRNG &prng, Socket &chl)
    {
        MC_BEGIN(Proto, this, X, &prng, &chl,
                ole_gmw = CorGenerator{},
                ole_gmw_vector = std::vector<CorGenerator>{},    
                tgmw = macoro::task<void>{},
                tgmw_ole = macoro::task<void>{},
                cmp = std::make_unique<Gmw>(),
                cir = BetaCircuit{},
                in = oc::Matrix<u8>{},
                outView = oc::MatrixView<u8>{},
                flags = oc::BitVector{},
                receive_bitvec = oc::BitVector{},
                result_bitvec = oc::BitVector{},
                temp = block{},
                i = int{},
                j = int{},
                row = int{},
                byteIndex = int{},
                bitMask = u8{},
                bitShift = int{},
                count = int{},
                count2 = int{},
                count3 = int{},

                key = block{},
                aes = oc::AES{},
                bit_block = std::vector<block>{},
                received_ciphertext = std::vector<block>{},

                finalOtReceiver = std::make_unique<oc::SilentOtExtReceiver>(),
                finalOtMsgs = std::vector<block>{}
        );
        // std::cout << "0\n";

        cir = isZeroCircuit(1);
        flags.resize(X.size() * 80);
        in.resize(X.size(), 1);
        ole_gmw_vector.resize(80);

        for(i = 0; i < 80; i++){
            // std::cout << "1\n";
            std::memset(in.data(), 0, in.size());

            byteIndex = i / 8;
            bitShift = i & 7;
            bitMask = 1u << (bitShift);
            // std::cout << "2\n";
            for (j = 0; j < X.size(); j++){
                temp = oc::ZeroBlock;
                // temp = output_2party_wprf[i]^output_1party_wprf[i];
                // std::memcpy(&in(j, 0), ((u8*)&temp) + byteIndex, 1);
                u8    byteVal = ((u8*)&temp)[byteIndex];
                u8    bit     = (byteVal & bitMask) >> bitShift;   // 0 or 1

                in(j,0) = bit;
            }
            // std::cout << "3\n";

            ole_gmw_vector[i].init(chl.fork(), prng, 1, 1, 1 << 18, 0);
            
            cmp->init(in.rows(), cir, ole_gmw_vector[i]);
            cmp->setInput(0, in);

            tgmw = cmp->run(chl);
            tgmw_ole = ole_gmw_vector[i].start();
            MC_AWAIT(when_all_ready(tgmw, tgmw_ole));
            
            outView = cmp->getOutputView(0);
            // std::cout << "4\n";
            oc::BitVector bits(outView.data(), X.size(), /*copy=*/false);
            for (row = 0; row < X.size(); row++){
                
                // bool outBit = outView[row][0] & static_cast<u8>(1);
                // if(outBit)
                if(bits[row])
                    flags[row*80 + i] = true;
            }
            
        }
        // std::cout << "5\n";
        receive_bitvec.resize(X.size()*80);
        MC_AWAIT(chl.recv(receive_bitvec));
        // std::cout << "6\n";
        
        result_bitvec.resize(X.size()*80);
        for(i = 0; i < X.size() * 80; i++){
            result_bitvec[i] = flags[i] ^ receive_bitvec[i];
        }

        count = 0;
        count2 = 0;
        for(i = 0; i < X.size() * 80; i++){
            if(result_bitvec[i] == 1){
                count++;
                // std::cout << "i is " << i << '\n';
            }
            else
                count2++;
        }

        bit_block.resize(X.size());
        std::memset(bit_block.data(), 0, X.size() * sizeof(block));
        for(i = 0; i < X.size(); i ++){
            std::memcpy(reinterpret_cast<u8*>(bit_block.data()) + i * sizeof(block), flags.data() + (i*10), 10);
        }
        
        key = oc::ZeroBlock;

        aes.setKey(key);

        aes.ecbEncBlocks(bit_block.data(), bit_block.size(), bit_block.data());

        received_ciphertext.resize(X.size());

        MC_AWAIT(chl.recv(received_ciphertext));

        count3 = 0;
        for(i = 0; i < X.size(); i++){
            if ((received_ciphertext[i] ^ bit_block[i]) == oc::OneBlock)
                count3++;
        }

        // std::cout << "sc::OneBlock is " << oc::OneBlock << '\n';

        std::cout  << "X.size() is " << X.size() << " X.size() * 80 is " << X.size() * 80 << '\n';
        std::cout << "count is " << count << '\n';
        std::cout << "count2 is " << count2 << '\n';
        std::cout << "count3 is " << count3 << '\n';

        
        timer.setTimePoint("ot");

        std::cout << timer << '\n';

        MC_END();

    }
}