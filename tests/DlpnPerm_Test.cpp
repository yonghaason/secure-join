#include "DlpnPerm_Test.h"


/*
This is the case where input has not
arrived yet but we can start the pre
processing phase 

Advantage: setup can run in background
before the input comes
*/
void Dlpn_perm_test1(const oc::CLP& cmd)
{
    u64 n = cmd.getOr("n", 1000);
    u64 rowSize = cmd.getOr("m",63);
    // bool invPerm = false;

    oc::PRNG prng0(oc::ZeroBlock);
    oc::PRNG prng1(oc::OneBlock);

    secJoin::DLpnPerm dlpnPerm1, dlpnPerm2;

    oc::Matrix<u8> x(n, rowSize), 
        yExp(n,rowSize),
        aExp(n,rowSize),
        sout1(n,rowSize),
        sout2(n,rowSize);

    prng0.get(x.data(), x.size());
    Perm pi(n,prng0);
    // std::cout << "The Current Permutation is " << pi.mPerm << std::endl;

    // Fake Setup
    OleGenerator ole0, ole1;
    ole0.fakeInit(OleGenerator::Role::Sender);
    ole1.fakeInit(OleGenerator::Role::Receiver);


    // DLpnPrf dm;
    oc::block kk;
    kk = prng0.get();

    // Setuping up the OT Keys
    std::vector<oc::block> rk(dlpnPerm2.mSender.mPrf.KeySize);
    std::vector<std::array<oc::block, 2>> sk(dlpnPerm2.mSender.mPrf.KeySize);
    for (u64 i = 0; i < dlpnPerm2.mSender.mPrf.KeySize; ++i)
    {
        sk[i][0] = oc::block(i, 0);
        sk[i][1] = oc::block(i, 1);
        rk[i] = oc::block(i, *oc::BitIterator((u8*)&kk, i));
    }
    dlpnPerm2.setupDlpnSender(kk,rk);
    dlpnPerm1.setupDlpnReceiver(sk);

    auto sock = coproto::LocalAsyncSocket::makePair();

    for(auto invPerm : {false,true})
    {

        // the preprocessing phase
        auto res = coproto::sync_wait(coproto::when_all_ready(
            dlpnPerm1.setup(pi, rowSize, prng0, sock[0], ole1, invPerm),
            dlpnPerm2.setup(prng1, sock[1], ole0, n, rowSize)
        ));

        oc::Matrix<oc::u8>  permPiA = reveal(dlpnPerm1.mDelta, dlpnPerm2.mB);

        pi.apply<u8>(dlpnPerm2.mA, aExp, invPerm);

        if(eq(aExp, permPiA) == false)
        {
            std::cout << "A & permuted A are not the same" << std::endl;
            throw RTE_LOC;
        }

        // std::get<0>(res).result();
        // std::get<1>(res).result();

        coproto::sync_wait(coproto::when_all_ready(
            ole0.stop(),
            ole1.stop()
        ));

        // the online phase (where input are already arrived)
        auto res1 = coproto::sync_wait(coproto::when_all_ready(
            dlpnPerm1.apply(pi , sout1, rowSize, sock[0], invPerm),
            dlpnPerm2.apply(x, sout2, sock[1]))
        );

        std::get<0>(res1).result();
        std::get<1>(res1).result();


        oc::Matrix<oc::u8>  yAct = reveal(sout2,sout1);
                
        pi.apply<u8>(x, yExp, invPerm);

        if(eq(yExp, yAct) == false)
            throw RTE_LOC;

    }
   
}

/*
This is the case where input has already
arrived and you want the protocol to 
take care of the preprocessing phase
*/
void Dlpn_perm_test2(const oc::CLP& cmd)
{
    u64 n = cmd.getOr("n", 1000);
    u64 rowSize = cmd.getOr("m",63);
    
    // bool invPerm = false;
    
    oc::PRNG prng0(oc::ZeroBlock);
    oc::PRNG prng1(oc::OneBlock);

    secJoin::DLpnPerm dlpnPerm1, dlpnPerm2;

    oc::Matrix<u8> x(n, rowSize), 
        yExp(n,rowSize),
        sout1(n,rowSize),
        sout2(n,rowSize);

    prng0.get(x.data(), x.size());
    Perm pi(n,prng0);
    // // std::cout << "The Current Permutation is " << pi.mPerm << std::endl;

    // Fake Setup
    OleGenerator ole0, ole1;
    ole0.fakeInit(OleGenerator::Role::Sender);
    ole1.fakeInit(OleGenerator::Role::Receiver);

    auto res = coproto::sync_wait(coproto::when_all_ready(
        dlpnPerm1.setupDlpnReceiver(ole0),
        dlpnPerm2.setupDlpnSender(ole1)
    ));

    std::get<0>(res).result();
    std::get<1>(res).result();

    auto sock = coproto::LocalAsyncSocket::makePair();

    for(auto invPerm : {false,true})
    {
        auto res1 = coproto::sync_wait(coproto::when_all_ready(
            dlpnPerm1.apply<u8>(pi, rowSize, prng0, sock[0], ole1, sout1, invPerm),
            dlpnPerm2.apply<u8>(prng1, sock[1], ole0, x, sout2)
        ));


        std::get<0>(res1).result();
        std::get<1>(res1).result();

        coproto::sync_wait(coproto::when_all_ready(
            ole0.stop(),
            ole1.stop()
        ));

        oc::Matrix<oc::u8>  yAct = reveal(sout2,sout1);
                
        pi.apply<u8>(x, yExp, invPerm);

        if(eq(yExp, yAct) == false)
            throw RTE_LOC;

    }

}


void Dlpn_perm_secret_shared_input_test(const oc::CLP& cmd)
{
    u64 n = cmd.getOr("n", 1000);
    u64 rowSize = cmd.getOr("m",63);
    
    // bool invPerm = false;
    
    oc::PRNG prng0(oc::ZeroBlock);
    oc::PRNG prng1(oc::OneBlock);

    secJoin::DLpnPerm dlpnPerm1, dlpnPerm2;

    oc::Matrix<u8> x(n, rowSize), 
        yExp(n,rowSize),
        sout1(n,rowSize),
        sout2(n,rowSize);

    prng0.get(x.data(), x.size());
    Perm pi(n,prng0);
    // // std::cout << "The Current Permutation is " << pi.mPerm << std::endl;

    // Fake Setup
    OleGenerator ole0, ole1;
    ole0.fakeInit(OleGenerator::Role::Sender);
    ole1.fakeInit(OleGenerator::Role::Receiver);

    auto res = coproto::sync_wait(coproto::when_all_ready(
        dlpnPerm1.setupDlpnReceiver(ole0),
        dlpnPerm2.setupDlpnSender(ole1)
    ));

    std::get<0>(res).result();
    std::get<1>(res).result();

    std::array<oc::Matrix<u8>, 2> xShares = share(x,prng0);

    auto sock = coproto::LocalAsyncSocket::makePair();

    for(auto invPerm : {false,true})
    {
        auto res1 = coproto::sync_wait(coproto::when_all_ready(
            dlpnPerm1.apply<u8>(pi, prng0, sock[0], ole1,  xShares[0], sout1, invPerm),
            dlpnPerm2.apply<u8>(prng1, sock[1], ole0, xShares[1], sout2)
        ));


        std::get<0>(res1).result();
        std::get<1>(res1).result();

        coproto::sync_wait(coproto::when_all_ready(
            ole0.stop(),
            ole1.stop()
        ));

        oc::Matrix<oc::u8>  yAct = reveal(sout2,sout1);
                
        pi.apply<u8>(x, yExp, invPerm);

        if(eq(yExp, yAct) == false)
            throw RTE_LOC;

    }
   
}